"""
run_and_analyze.py

Script unique : build + lancement + surveillance temps réel.

CORRECTIONS de cette version :
  1. La position de lecture est maintenant capturée AVANT le lancement
     de l'application, pas après le délai d'attente. Sans ça, une
     erreur de démarrage rapide (ex: port déjà utilisé, qui échoue en
     1-3 secondes) pouvait être écrite dans le fichier AVANT que le
     script commence à surveiller, et donc être invisible pour lui.
  2. Message explicite "tout va bien" affiché dès le début de la
     surveillance, plus un rappel périodique si rien ne se passe.
  3. Le prompt Ollama réintègre les garde-fous anti-hallucination
     (citation obligatoire, vérification du mot "Expected"/"test"/
     "demo" avant de conclure "réelle" vs "volontaire", cohérence
     entre les points) tout en gardant la structure en 8 points
     demandée par l'encadreur.
"""

import re
import subprocess
import sys
import time
import signal
import requests
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
INTERVALLE_RAPPEL_SECONDES = 120  # rappelle "tout va bien" toutes les 2 min d'inactivité

MOTIF_LIGNE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})"
    r"\s\[(?P<thread>.*?)\]\s"
    r"(?P<niveau>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"(?P<logger>\S+)\s-\s"
    r"(?P<message>.*)$"
)


def construire_projet() -> bool:
    print(" Build Maven en cours (peut prendre 1-2 minutes)...")
    resultat = subprocess.run(
        ["./mvnw", "clean", "package", "-DskipTests"],
        cwd=DOSSIER_PROJET,
        capture_output=True,
        text=True,
    )
    if resultat.returncode != 0:
        print("❌ Le build a échoué :\n")
        print(resultat.stdout[-3000:])
        print(resultat.stderr[-1500:])
        return False
    print(" Build réussi.\n")
    return True


def obtenir_position_actuelle() -> int:
    """
    Mesure la taille actuelle du fichier de log, à appeler JUSTE AVANT
    de lancer l'application. Tout ce qui sera écrit après cet instant
    (y compris pendant le délai de démarrage) sera capturé — rien ne
    peut plus être "sauté" comme avec l'ancienne version.
    """
    if CHEMIN_LOG.exists():
        return CHEMIN_LOG.stat().st_size
    return 0


def lancer_application() -> subprocess.Popen:
    jars = list((DOSSIER_PROJET / "target").glob("*.jar"))
    jars = [j for j in jars if "original" not in j.name]
    if not jars:
        raise FileNotFoundError("Aucun .jar trouvé dans target/ après le build.")

    print(f" Lancement de {jars[0].name}...")
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


def construire_prompt(niveau: str, logger: str, message: str, details_suivants: str) -> str:
    return f"""Tu es un ingénieur SRE senior spécialisé Spring Boot.
Tu aides un développeur débutant.

RÈGLE ABSOLUE : appuie chaque affirmation sur une citation exacte du
log fourni ci-dessous. Si une information n'est pas déductible du log,
dis "je ne peux pas le confirmer avec ce log seul" plutôt que de deviner.

AVANT de répondre aux points 6 et 7, cherche explicitement dans le
message et les détails ci-dessous des mots comme "Expected", "test",
"demo", "showcase" : leur présence indique un comportement VOLONTAIRE
et non un vrai dysfonctionnement. Si tu en trouves, tes réponses aux
points 2 (l'application continue-t-elle ?), 6 (gravité) et 7
(volontaire ou réelle) doivent rester cohérentes entre elles : une
erreur volontaire isolée à une seule requête de test n'empêche PAS le
reste de l'application de fonctionner, et sa gravité réelle est
généralement Faible, pas Critique.

À partir du log fourni, réponds EXACTEMENT dans cet ordre :

1. Résumé du problème (explique en français simple ce qui s'est passé)
2. Est-ce que l'application continue à fonctionner ? (distingue "cette
   requête précise a échoué" de "toute l'application est indisponible")
3. Cause la plus probable
4. Indices précis dans le log (cite les mots/phrases exacts trouvés)  #+ligne danslo log
5. Commandes Linux si nécessaire (sinon écris "Aucune nécessaire")
6. Niveau de gravité : Critique / Élevé / Moyen / Faible
   (justifie en une phrase, cohérente avec ta réponse au point 7)
7. Cette erreur semble-t-elle volontaire (test) ou réelle ?
   (base-toi explicitement sur la présence ou l'absence des mots
   "Expected"/"test"/"demo"/"showcase" cités au point 4)
8. Action immédiate proposée

Réponds uniquement en français, en texte brut (pas de Markdown).


5 et 7 pas utile satria efa hainle olona hoe

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


def analyser_avec_ollama(niveau: str, logger: str, message: str, details: str) -> str:
    prompt = construire_prompt(niveau, logger, message, details)
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


def enregistrer_rapport(entree: dict):
    Path("logs").mkdir(exist_ok=True)
    with open(DOSSIER_PROJET / "logs" / "rapport_analyses.log", "a", encoding="utf-8") as f:
        import json
        f.write(json.dumps(entree, ensure_ascii=False) + "\n")


def surveiller_en_temps_reel(position_depart: int):
    print(f" Surveillance en temps réel de {CHEMIN_LOG} (Ctrl+C pour arrêter)")
    print(" Aucune erreur détectée pour l'instant — tout va bien.\n")

    while not CHEMIN_LOG.exists():
        time.sleep(0.5)

    with open(CHEMIN_LOG, encoding="utf-8") as f:
        f.seek(position_depart)  # reprend EXACTEMENT là où on s'est arrêté
        # avant le lancement de l'app, plus rien n'est manqué

        entree_courante = None
        dernier_rappel = time.monotonic()

        while True:
            ligne = f.readline()

            if not ligne:
                if entree_courante:
                    traiter_entree(entree_courante)
                    entree_courante = None
                if time.monotonic() - dernier_rappel > INTERVALLE_RAPPEL_SECONDES:
                    heure = datetime.now(FUSEAU_LOCAL).strftime("%H:%M:%S")
                    print(f" [{heure}] Toujours actif, aucune nouvelle erreur.")
                    dernier_rappel = time.monotonic()
                time.sleep(1)
                continue

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
                }
            elif entree_courante:
                entree_courante["details"] += ligne + "\n"


def traiter_entree(entree: dict):
    niveau = entree["niveau"]
    if niveau not in NIVEAUX_A_ANALYSER:
        return

    timestamp_affiche = formater_timestamp(entree["timestamp"])
    print(f"🔴 [{timestamp_affiche}] {niveau} — {entree['logger']}")
    print(f"   {entree['message']}\n")
    print("   Analyse Ollama en cours...")

    debut = datetime.now(timezone.utc)
    analyse = analyser_avec_ollama(niveau, entree["logger"], entree["message"], entree["details"])
    duree = (datetime.now(timezone.utc) - debut).total_seconds()

    print(f"---- Analyse Ollama (durée : {duree:.1f}s) ----")
    print(analyse)
    print("-------------------------\n")

    enregistrer_rapport({
        "timestamp_evenement": entree["timestamp"],
        "timestamp_evenement_lisible": timestamp_affiche,
        "timestamp_analyse_utc": datetime.now(timezone.utc).isoformat(),
        "niveau": niveau,
        "logger": entree["logger"],
        "message": entree["message"],
        "analyse_llm": analyse,
    })


if __name__ == "__main__":
    if not construire_projet():
        sys.exit(1)

    # On mesure la position AVANT de lancer l'app : c'est la correction
    # clé de cette version, voir explication en en-tête du fichier.
    position_avant_lancement = obtenir_position_actuelle()

    processus_app = lancer_application()

    def arret_propre(signum, frame):
        print("\n🛑 Arrêt demandé — fermeture de l'application...")
        processus_app.terminate()
        processus_app.wait(timeout=10)
        print(" Application arrêtée. Fin du script.")
        sys.exit(0)

    signal.signal(signal.SIGINT, arret_propre)

    print("⏳ Attente du démarrage de l'application (10s)...\n")
    time.sleep(10)

    try:
        surveiller_en_temps_reel(position_avant_lancement)
    except KeyboardInterrupt:
        arret_propre(None, None)