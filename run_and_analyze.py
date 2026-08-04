"""
run_and_analyze.py

CORRECTIONS de cette version :
  1. Prompt clarifié : le numéro de ligne est présenté comme une
     DONNÉE FOURNIE (pas à vérifier par citation), pour éviter la
     confusion "ligne X n'est pas spécifiée" observée en test.
  2. stdout/stderr de l'application NE SONT PLUS jetés (DEVNULL) :
     ils sont capturés dans logs/demarrage_stderr.log. Si l'app
     plante AVANT que Log4j2 soit complètement initialisé (ex: port
     déjà utilisé), l'erreur écrite sur stderr est maintenant captée
     et analysée par Ollama, alors qu'avant elle était perdue.
  3. Détection explicite d'un crash au démarrage (le processus se
     termine tout seul pendant les 10s d'attente) : dans ce cas, le
     script analyse immédiatement le contenu de stderr, sans attendre
     une ligne dans petclinic.log qui ne viendra peut-être jamais.
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
CHEMIN_STDERR = DOSSIER_PROJET / "logs" / "demarrage_stderr.log"
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

    Path("logs").mkdir(exist_ok=True)
    # On capture stderr dans un fichier dédié, au lieu de le jeter.
    # C'est ce qui permet de voir les erreurs de démarrage précoces
    # (avant que Log4j2 lui-même soit prêt à écrire dans petclinic.log).
    fichier_stderr = open(CHEMIN_STDERR, "w", encoding="utf-8")

    processus = subprocess.Popen(
        ["java", "-jar", str(jars[0])],
        cwd=DOSSIER_PROJET,
        stdout=subprocess.DEVNULL,
        stderr=fichier_stderr,
    )
    return processus, fichier_stderr


def formater_timestamp(ts_texte: str) -> str:
    try:
        dt_naif = datetime.strptime(ts_texte, "%Y-%m-%d %H:%M:%S.%f")
        dt_local = dt_naif.replace(tzinfo=FUSEAU_LOCAL)
        return dt_local.strftime("%Y-%m-%d %H:%M:%S") + " heure Madagascar"
    except ValueError:
        return ts_texte


def construire_prompt(niveau: str, logger: str, message: str, details_suivants: str, numero_ligne) -> str:
    reference_ligne = (
        f"Numéro de ligne dans le fichier de log : {numero_ligne}\n"
        if numero_ligne is not None
        else "Numéro de ligne : non disponible (erreur survenue avant l'écriture du fichier de log)\n"
    )
    return f"""Tu es un ingénieur SRE senior spécialisé Spring Boot.
Tu aides un développeur débutant.

RÈGLE ABSOLUE : pour le RÉSUMÉ et la CAUSE, appuie chaque affirmation
sur une citation exacte du log fourni ci-dessous. Si une information
n'est pas déductible du log, dis "je ne peux pas le confirmer avec ce
log seul" plutôt que de deviner.

IMPORTANT : le numéro de ligne fourni ci-dessous est une donnée déjà
calculée et fiable par le système de surveillance — ce n'est PAS un
élément à retrouver ou vérifier dans le texte du message. Utilise-le
tel quel au point 4, sans le remettre en question.

Réponds EXACTEMENT dans cet ordre :

1. Résumé du problème (explique en français simple ce qui s'est passé)
2. Est-ce que l'application continue à fonctionner ?
3. Cause la plus probable
4. Indices précis dans le log : cite les mots/phrases exacts trouvés
   dans le message, ET précise la référence de ligne donnée ci-dessous
5. Niveau de gravité : Critique / Élevé / Moyen / Faible
   (justifie ta réponse en une phrase)
6. Action immédiate proposée

Réponds uniquement en français, en texte brut (pas de Markdown).

{reference_ligne}Niveau du log : {niveau}
Classe (logger) : {logger}
Message : {message}
Détails complémentaires (stack trace éventuelle, tronquée) :
{details_suivants[:1500] if details_suivants else "aucun"}
"""


def nettoyer_markdown(texte: str) -> str:
    texte = re.sub(r"\*\*(.+?)\*\*", r"\1", texte)
    texte = re.sub(r"^#+\s*", "", texte, flags=re.MULTILINE)
    return texte.strip()


def analyser_avec_ollama(niveau: str, logger: str, message: str, details: str, numero_ligne) -> str:
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


# ----------------------------------------------------------------------
# NOUVEAU : analyse d'un crash survenu AVANT que petclinic.log existe
# ou contienne quoi que ce soit d'exploitable (ex: port déjà utilisé,
# détecté par Spring Boot avant même que Log4j2 soit opérationnel)
# ----------------------------------------------------------------------
def analyser_crash_demarrage():
    contenu_stderr = CHEMIN_STDERR.read_text(encoding="utf-8", errors="replace").strip()

    if not contenu_stderr:
        print("Le processus s'est arrêté tôt, mais stderr est vide — cause indéterminée.\n")
        return

    print("L'application s'est arrêtée pendant le démarrage — analyse de stderr...")
    print(f"   Extrait : {contenu_stderr[:300]}\n")
    print("   Analyse Ollama en cours...")

    debut = datetime.now(timezone.utc)
    analyse = analyser_avec_ollama(
        "ERROR", "démarrage (stderr)", contenu_stderr[:1500], "", None
    )
    duree = (datetime.now(timezone.utc) - debut).total_seconds()

    print(f"---- Analyse Ollama (durée : {duree:.1f}s) ----")
    print(analyse)
    print("-------------------------\n")

    enregistrer_rapport({
        "timestamp_evenement": datetime.now(FUSEAU_LOCAL).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "timestamp_evenement_lisible": datetime.now(FUSEAU_LOCAL).strftime("%Y-%m-%d %H:%M:%S") + " heure Madagascar",
        "numero_ligne": None,
        "timestamp_analyse_utc": datetime.now(timezone.utc).isoformat(),
        "niveau": "ERROR",
        "logger": "démarrage (stderr, avant Log4j2)",
        "message": contenu_stderr[:500],
        "analyse_llm": analyse,
    })


def surveiller_en_temps_reel(position_depart: int, numero_ligne_initial: int):
    print(f"Surveillance en temps réel de {CHEMIN_LOG} (Ctrl+C pour arrêter)")
    print("Aucune erreur détectée pour l'instant — tout va bien.\n")

    while not CHEMIN_LOG.exists():
        time.sleep(0.5)

    with open(CHEMIN_LOG, encoding="utf-8") as f:
        f.seek(position_depart)
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

    processus_app, fichier_stderr = lancer_application()

    def arret_propre(signum, frame):
        print("\nArrêt demandé — fermeture de l'application...")
        processus_app.terminate()
        processus_app.wait(timeout=10)
        fichier_stderr.close()
        print("Application arrêtée. Fin du script.")
        sys.exit(0)

    signal.signal(signal.SIGINT, arret_propre)

    print("Attente du démarrage de l'application (10s)...\n")
    time.sleep(10)

    # NOUVEAU : si le processus s'est déjà arrêté tout seul pendant
    # cette attente, c'est un crash au démarrage (ex: port occupé) —
    # on l'analyse tout de suite via stderr, plutôt que d'attendre en
    # vain une ligne dans petclinic.log qui ne viendra jamais.
    if processus_app.poll() is not None:
        fichier_stderr.close()
        analyser_crash_demarrage()
        print("L'application n'a pas pu démarrer. Fin du script.")
        sys.exit(1)

    try:
        surveiller_en_temps_reel(position_avant_lancement, lignes_avant_lancement)
    except KeyboardInterrupt:
        arret_propre(None, None)