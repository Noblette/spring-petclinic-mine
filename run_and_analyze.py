"""
run_and_analyze.py

NOUVEAU dans cette version :
  - Le prompt impose des TITRES EXPLICITES pour chaque section de la
    réponse (DESCRIPTION, FONCTIONNEMENT, CAUSE, INDICES, GRAVITE, ACTION),
    dans le même esprit que le "Description:" / "Action:" que Spring
    Boot affiche lui-même pour ses propres erreurs connues.
  - La réponse d'Ollama est maintenant DÉCOUPÉE automatiquement en un
    dictionnaire structuré (une clé par section), stocké tel quel
    dans le rapport JSON — plus lisible, et directement réutilisable
    plus tard pour créer un ticket GLPI (titre = résumé, priorité =
    gravité, etc.) sans avoir à re-parser du texte libre.
  - L'affichage dans le terminal reprend aussi ces titres, au lieu de
    simples numéros.
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

# Les 6 sections attendues dans la réponse d'Ollama, dans cet ordre.
# Volontairement SANS accent (RESUME, pas RÉSUMÉ) pour que la
# reconnaissance par expression régulière soit fiable même si le
# modèle varie légèrement sa façon d'écrire les accents.
#SECTIONS = ["RESUME", "FONCTIONNEMENT", "CAUSE", "INDICES", "GRAVITE", "ACTION"]
SECTIONS = ["DESCRIPTION", "FONCTIONNEMENT", "CAUSE", "INDICES", "GRAVITE", "ACTION"]

# Titres affichés à l'humain (avec accents, pour la lisibilité),
# utilisés à l'affichage terminal ET conservés dans le rapport.
TITRES_AFFICHAGE = {
    "DESCRIPTION": "Description",
    "FONCTIONNEMENT": "Fonctionnement de l'application",
    "CAUSE": "Cause probable",
    "INDICES": "Indices dans le log",
    "GRAVITE": "Gravité",
    "ACTION": "Action recommandée",
}


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

RÈGLE ABSOLUE : pour DESCRIPTION et CAUSE, appuie chaque affirmation sur une
citation exacte du log fourni ci-dessous. Si une information n'est pas
déductible du log, dis "je ne peux pas le confirmer avec ce log seul"
plutôt que de deviner.

IMPORTANT : le numéro de ligne fourni ci-dessous est une donnée déjà
calculée et fiable — ce n'est PAS un élément à vérifier dans le texte.
Utilise-le tel quel dans INDICES, sans le remettre en question.

FORMAT DE RÉPONSE OBLIGATOIRE : réponds en français, en texte brut
(pas de Markdown), en respectant EXACTEMENT cette structure — chaque
titre ci-dessous seul sur sa ligne, suivi de ":", puis le contenu :

DESCRIPTION:
(résume en 1-2 phrases ce qui s'est passé)

FONCTIONNEMENT:
(l'application continue-t-elle à fonctionner ? distingue "cette
requête précise a échoué" de "toute l'application est indisponible")

CAUSE:
(la cause la plus probable)

INDICES:
(cite les mots/phrases exacts trouvés dans le message, et précise la
référence de ligne donnée ci-dessous)
Obligatoirement :

- Ligne : <numéro fourni ci-dessous>

- Citation exacte n°1

- Citation exacte n°2

- Citation exacte n°3

N'invente aucune citation.

GRAVITE:
(un seul mot parmi : Critique / Eleve / Moyen / Faible, puis une
phrase de justification)

ACTION:
(action immédiate proposée)

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


# ----------------------------------------------------------------------
# NOUVEAU : découpe la réponse brute d'Ollama en sections nommées
# ----------------------------------------------------------------------
def extraire_sections(texte: str) -> dict:
    motif = re.compile(
        r"(?:^|\n)\s*(" + "|".join(SECTIONS) + r")\s*:\s*\n?",
        re.IGNORECASE,
    )
    morceaux = motif.split(texte)

    resultat = {cle: "" for cle in SECTIONS}
    # morceaux ressemble à : [avant_premier_titre, TITRE1, contenu1, TITRE2, contenu2, ...]
    for i in range(1, len(morceaux) - 1, 2):
        cle = morceaux[i].strip().upper()
        contenu = morceaux[i + 1].strip()
        if cle in resultat:
            resultat[cle] = contenu

    # Si le modèle n'a pas du tout respecté le format (aucune section
    # reconnue), on garde le texte brut entier dans RESUME plutôt que
    # de perdre l'information.
    if all(v == "" for v in resultat.values()):
        resultat["DESCRIPTION"] = texte.strip()

    return resultat


def analyser_avec_ollama(niveau: str, logger: str, message: str, details: str, numero_ligne) -> dict:
    prompt = construire_prompt(niveau, logger, message, details, numero_ligne)
    try:
        reponse = requests.post(
            URL_OLLAMA,
            json={"model": NOM_MODELE, "prompt": prompt, "stream": False},
            timeout=TIMEOUT_OLLAMA,
        )
        reponse.raise_for_status()
        texte_brut = nettoyer_markdown(reponse.json().get("response", ""))
        return extraire_sections(texte_brut)

    except requests.exceptions.ConnectionError:
        return {"DESCRIPTION": "[Impossible de joindre Ollama — vérifie qu'il tourne : ollama serve]"}
    except requests.exceptions.Timeout:
        return {"DESCRIPTION": f"[Timeout après {TIMEOUT_OLLAMA}s]"}
    except requests.exceptions.RequestException as e:
        return {"DESCRIPTION": f"[Erreur Ollama : {e}]"}


def afficher_analyse(sections: dict):
    for cle in SECTIONS:
        contenu = sections.get(cle, "").strip()
        if contenu:
            print(f"{TITRES_AFFICHAGE[cle]} :")
            print(f"   {contenu}\n")


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


def analyser_crash_demarrage():
    contenu_stderr = CHEMIN_STDERR.read_text(encoding="utf-8", errors="replace").strip()

    if not contenu_stderr:
        print("Le processus s'est arrêté tôt, mais stderr est vide — cause indéterminée.\n")
        return

    print("L'application s'est arrêtée pendant le démarrage — analyse de stderr...")
    print(f"   Extrait : {contenu_stderr[:300]}\n")
    print("   Analyse Ollama en cours...")

    debut = datetime.now(timezone.utc)
    sections = analyser_avec_ollama("ERROR", "démarrage (stderr)", contenu_stderr[:1500], "", None)
    duree = (datetime.now(timezone.utc) - debut).total_seconds()

    print(f"---- Analyse Ollama (durée : {duree:.1f}s) ----")
    afficher_analyse(sections)
    print("-------------------------\n")

    enregistrer_rapport({
        "timestamp_evenement": datetime.now(FUSEAU_LOCAL).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "timestamp_evenement_lisible": datetime.now(FUSEAU_LOCAL).strftime("%Y-%m-%d %H:%M:%S") + " heure Madagascar",
        "numero_ligne": None,
        "timestamp_analyse_utc": datetime.now(timezone.utc).isoformat(),
        "niveau": "ERROR",
        "logger": "démarrage (stderr, avant Log4j2)",
        "message": contenu_stderr[:500],
        "analyse": sections,
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
    sections = analyser_avec_ollama(
        niveau, entree["logger"], entree["message"], entree["details"], entree["numero_ligne"]
    )
    duree = (datetime.now(timezone.utc) - debut).total_seconds()

    print(f"---- Analyse Ollama (durée : {duree:.1f}s) ----")
    afficher_analyse(sections)
    print("-------------------------\n")

    enregistrer_rapport({
        "timestamp_evenement": entree["timestamp"],
        "timestamp_evenement_lisible": timestamp_affiche,
        "numero_ligne": entree["numero_ligne"],
        "timestamp_analyse_utc": datetime.now(timezone.utc).isoformat(),
        "niveau": niveau,
        "logger": entree["logger"],
        "message": entree["message"],
        "analyse": sections,
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

    if processus_app.poll() is not None:
        fichier_stderr.close()
        analyser_crash_demarrage()
        print("L'application n'a pas pu démarrer. Fin du script.")
        sys.exit(1)

    try:
        surveiller_en_temps_reel(position_avant_lancement, lignes_avant_lancement)
    except KeyboardInterrupt:
        arret_propre(None, None)