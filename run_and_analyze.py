"""
run_and_analyze.py

Script unique : build + lancement + surveillance temps réel.

CHANGEMENTS demandés par l'encadreur (compte rendu du 31/07) :
  1. Prompt réduit à 6 points : retrait des commandes Linux (destinées
     à un expert Linux, pas nécessaires ici) et du point "volontaire
     vs réelle" (jugé superflu). Le point 4 inclut maintenant le
     numéro de ligne exact dans le fichier de log.
  2. Log4j2 n'archive plus automatiquement (.gz) : un seul fichier
     plat, sans rotation ni compression.
  3. Le rapport d'analyses est maintenant un fichier PAR JOUR
     (logs/rapport_analyses_AAAA-MM-JJ.log), avec horodatage précis
     heure/minute/seconde à chaque entrée.
  4. Le rappel périodique "Toujours actif" a été retiré.
"""

import re
import subprocess
import sys
import time
import signal
import requests
import json
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


DOSSIER_PROJET = Path(__file__).resolve().parent
CHEMIN_LOG = DOSSIER_PROJET / "logs" / "petclinic.log"
NOM_MODELE = "llama3.2:3b"
FUSEAU_LOCAL = ZoneInfo("Indian/Antananarivo")
URL_OLLAMA = "http://localhost:11434/api/generate"
TIMEOUT_OLLAMA = 300
NIVEAUX_A_ANALYSER = {"WARN", "ERROR", "FATAL"}

MOTIF_LIGNE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})"
    r"\s\[(?P<thread>.*?)\]\s"
    r"(?P<niveau>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"(?P<logger>\S+)\s-\s"
    r"(?P<message>.*)$"
)


def construire_projet() -> bool:
    print("Build Maven en cours (peut prendre 1-2 minutes)...")
    resultat = subprocess.run(
        ["./mvnw", "clean", "package", "-DskipTests"],
        cwd=DOSSIER_PROJET,
        capture_output=True,
        text=True,
    )
    if resultat.returncode != 0:
        print("Le build a échoué :\n")
        print(resultat.stdout[-3000:])
        print(resultat.stderr[-1500:])
        return False
    print("Build réussi.\n")
    return True


def obtenir_position_et_nombre_lignes() -> tuple[int, int]:
    """
    Retourne (position en octets, nombre de lignes déjà présentes),
    en comptant les lignes une par une (comme le fait un éditeur de
    texte), plutôt qu'en comptant les '\n' sur un bloc lu d'un coup —
    ce qui évite tout décalage en cas de ligne finale non terminée.
    """
    if not CHEMIN_LOG.exists():
        return 0, 0
    nombre_lignes = 0
    with open(CHEMIN_LOG, encoding="utf-8") as f:
        for _ in f:
            nombre_lignes += 1
    taille = CHEMIN_LOG.stat().st_size
    return taille, nombre_lignes


def lancer_application() -> subprocess.Popen:
    jars = list((DOSSIER_PROJET / "target").glob("*.jar"))
    jars = [j for j in jars if "original" not in j.name]
    if not jars:
        raise FileNotFoundError("Aucun .jar trouvé dans target/ après le build.")

    print(f"Lancement de {jars[0].name}...")
    processus = subprocess.Popen(
        ["java", "-jar", str(jars[0])],
        cwd=DOSSIER_PROJET,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return processus


def formater_timestamp(ts_texte: str) -> str:
    try:
        dt_naif = datetime.strptime(ts_texte, "%Y-%m-%d %H:%M:%S.%f")
        dt_local = dt_naif.replace(tzinfo=FUSEAU_LOCAL)
        return dt_local.strftime("%Y-%m-%d %H:%M:%S") + " heure Madagascar"
    except ValueError:
        return ts_texte


# ----------------------------------------------------------------------
# NOUVEAU PROMPT — 6 points au lieu de 8, point 4 avec numéro de ligne
# ----------------------------------------------------------------------
def construire_prompt(niveau: str, logger: str, message: str, details_suivants: str, numero_ligne: int) -> str:
    return f"""Tu es un ingénieur SRE senior spécialisé Spring Boot.
Tu aides un développeur débutant.

RÈGLE ABSOLUE : appuie chaque affirmation sur une citation exacte du
log fourni ci-dessous. Si une information n'est pas déductible du log,
dis "je ne peux pas le confirmer avec ce log seul" plutôt que de deviner.

Réponds EXACTEMENT dans cet ordre :

1. Résumé du problème (explique en français simple ce qui s'est passé)
2. Est-ce que l'application continue à fonctionner ? (distingue "cette
   requête précise a échoué" de "toute l'application est indisponible")
3. Cause la plus probable
4. Indices précis dans le log : cite les mots/phrases exacts trouvés,
   ET indique la ligne {numero_ligne} du fichier comme référence
5. Niveau de gravité : Critique / Élevé / Moyen / Faible
   (justifie ta réponse en une phrase)
6. Action immédiate proposée

Réponds uniquement en français, en texte brut (pas de Markdown).

Niveau du log : {niveau}
Classe (logger) : {logger}
Message : {message}
Détails complémentaires (stack trace éventuelle, tronquée) :
{details_suivants[:1500] if details_suivants else "aucun"}
"""


def nettoyer_markdown(texte: str) -> str:
    texte = re.sub(r"\*\*(.+?)\*\*", r"\1", texte)
    texte = re.sub(r"^#+\s*", "", texte, flags=re.MULTILINE)
    return texte.strip()


def analyser_avec_ollama(niveau: str, logger: str, message: str, details: str, numero_ligne: int) -> str:
    prompt = construire_prompt(niveau, logger, message, details, numero_ligne)
    try:
        reponse = requests.post(
            URL_OLLAMA,
            json={"model": NOM_MODELE, "prompt": prompt, "stream": False},
            timeout=TIMEOUT_OLLAMA,
        )
        reponse.raise_for_status()
        return nettoyer_markdown(reponse.json().get("response", ""))
    except requests.exceptions.ConnectionError:
        return "[Impossible de joindre Ollama — vérifie qu'il tourne : ollama serve]"
    except requests.exceptions.Timeout:
        return f"[Timeout après {TIMEOUT_OLLAMA}s]"
    except requests.exceptions.RequestException as e:
        return f"[Erreur Ollama : {e}]"


# ----------------------------------------------------------------------
# NOUVEAU : rapport organisé PAR JOUR (un fichier par date)
# ----------------------------------------------------------------------
def chemin_rapport_du_jour() -> Path:
    aujourdhui = datetime.now(FUSEAU_LOCAL).strftime("%Y-%m-%d")
    return DOSSIER_PROJET / "logs" / f"rapport_analyses_{aujourdhui}.log"


def enregistrer_rapport(entree: dict):
    Path("logs").mkdir(exist_ok=True)
    maintenant_local = datetime.now(FUSEAU_LOCAL)
    entree_complete = {
        "date": maintenant_local.strftime("%Y-%m-%d"),
        "heure": maintenant_local.strftime("%H:%M:%S"),
        **entree,
    }
    with open(chemin_rapport_du_jour(), "a", encoding="utf-8") as f:
        f.write(json.dumps(entree_complete, ensure_ascii=False) + "\n")


def surveiller_en_temps_reel(position_depart: int, numero_ligne_initial: int):
    print(f"Surveillance en temps réel de {CHEMIN_LOG} (Ctrl+C pour arrêter)")
    print("Aucune erreur détectée pour l'instant — tout va bien.\n")

    while not CHEMIN_LOG.exists():
        time.sleep(0.5)

    with open(CHEMIN_LOG, encoding="utf-8") as f:
        f.seek(position_depart)

        # On compte les lignes déjà lues avant ce lancement, pour que
        # le numéro affiché corresponde à la vraie position dans le
        # fichier complet (utile pour le point 4 du prompt).
        numero_ligne = numero_ligne_initial

        entree_courante = None

        while True:
            ligne = f.readline()

            if not ligne:
                if entree_courante:
                    traiter_entree(entree_courante)
                    entree_courante = None
                time.sleep(1)
                continue

            numero_ligne += 1
            ligne = ligne.rstrip("\n")
            correspondance = MOTIF_LIGNE.match(ligne)

            if correspondance:
                if entree_courante:
                    traiter_entree(entree_courante)
                entree_courante = {
                    "timestamp": correspondance.group("timestamp"),
                    "niveau": correspondance.group("niveau"),
                    "logger": correspondance.group("logger"),
                    "message": correspondance.group("message"),
                    "details": "",
                    "numero_ligne": numero_ligne,
                }
            elif entree_courante:
                entree_courante["details"] += ligne + "\n"


def traiter_entree(entree: dict):
    niveau = entree["niveau"]
    if niveau not in NIVEAUX_A_ANALYSER:
        return

    timestamp_affiche = formater_timestamp(entree["timestamp"])
    print(f"[{timestamp_affiche}] {niveau} — {entree['logger']} (ligne {entree['numero_ligne']})")
    print(f"   {entree['message']}\n")
    print("   Analyse Ollama en cours...")

    debut = datetime.now(timezone.utc)
    analyse = analyser_avec_ollama(
        niveau, entree["logger"], entree["message"], entree["details"], entree["numero_ligne"]
    )
    duree = (datetime.now(timezone.utc) - debut).total_seconds()

    print(f"---- Analyse Ollama (durée : {duree:.1f}s) ----")
    print(analyse)
    print("-------------------------\n")

    enregistrer_rapport({
        "timestamp_evenement": entree["timestamp"],
        "timestamp_evenement_lisible": timestamp_affiche,
        "numero_ligne": entree["numero_ligne"],
        "timestamp_analyse_utc": datetime.now(timezone.utc).isoformat(),
        "niveau": niveau,
        "logger": entree["logger"],
        "message": entree["message"],
        "analyse_llm": analyse,
    })


if __name__ == "__main__":
    if not construire_projet():
        sys.exit(1)

    position_avant_lancement, lignes_avant_lancement = obtenir_position_et_nombre_lignes()

    processus_app = lancer_application()

    def arret_propre(signum, frame):
        print("\nArrêt demandé — fermeture de l'application...")
        processus_app.terminate()
        processus_app.wait(timeout=10)
        print("Application arrêtée. Fin du script.")
        sys.exit(0)

    signal.signal(signal.SIGINT, arret_propre)

    print("Attente du démarrage de l'application (10s)...\n")
    time.sleep(10)

    try:
        surveiller_en_temps_reel(position_avant_lancement, lignes_avant_lancement)
    except KeyboardInterrupt:
        arret_propre(None, None)