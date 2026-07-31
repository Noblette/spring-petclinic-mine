"""
run_and_analyze.py

Script UNIQUE qui remplace les 3 commandes manuelles :
    ./mvnw clean package -DskipTests
    java -jar target/*.jar
    python3 analyseur_logs.py

Une seule commande désormais :
    python3 run_and_analyze.py

Ce que fait le script, dans l'ordre :
  1. Build Maven (silencieux si succès, affiche l'erreur sinon)
  2. Lance l'application Spring Boot en arrière-plan
  3. Surveille le fichier de log EN TEMPS RÉEL (comme "tail -f") :
     dès qu'une nouvelle ligne WARN/ERROR/FATAL apparaît, elle est
     immédiatement envoyée à Ollama pour analyse — pas besoin de
     relancer quoi que ce soit.
  4. Ctrl+C arrête proprement l'application ET le script.

IMPORTANT — changement de format : les logs sont maintenant en TEXTE
BRUT (Log4j2, voir log4j2-spring.xml), plus en JSON/ECS. Ce script lit
donc chaque ligne avec une expression régulière au lieu de json.loads().
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


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
DOSSIER_PROJET = Path(__file__).resolve().parent
CHEMIN_LOG = DOSSIER_PROJET / "logs" / "petclinic.log"
NOM_MODELE = "llama3.2:3b"
FUSEAU_LOCAL = ZoneInfo("Indian/Antananarivo")
URL_OLLAMA = "http://localhost:11434/api/generate"
TIMEOUT_OLLAMA = 300
NIVEAUX_A_ANALYSER = {"WARN", "ERROR", "FATAL"}

# Reconnaît une ligne log4j2 qui DÉMARRE une nouvelle entrée, ex :
# "2026-07-30 10:22:00.123 [main] ERROR o.s.s.CrashController - message"
MOTIF_LIGNE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})"
    r"\s\[(?P<thread>.*?)\]\s"
    r"(?P<niveau>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"(?P<logger>\S+)\s-\s"
    r"(?P<message>.*)$"
)


# ------------------------------------------------------------------
# Étape 1 — build Maven
# ------------------------------------------------------------------
def construire_projet() -> bool:
    print("🔨 Build Maven en cours (peut prendre 1-2 minutes)...")
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
    print("✅ Build réussi.\n")
    return True


# ------------------------------------------------------------------
# Étape 2 — lancer l'application en arrière-plan
# ------------------------------------------------------------------
def lancer_application() -> subprocess.Popen:
    jars = list((DOSSIER_PROJET / "target").glob("*.jar"))
    jars = [j for j in jars if "original" not in j.name]
    if not jars:
        raise FileNotFoundError("Aucun .jar trouvé dans target/ après le build.")

    print(f"🚀 Lancement de {jars[0].name}...")
    processus = subprocess.Popen(
        ["java", "-jar", str(jars[0])],
        cwd=DOSSIER_PROJET,
        stdout=subprocess.DEVNULL,  # les logs vont déjà dans le fichier
        stderr=subprocess.DEVNULL,  # via log4j2, pas besoin de dupliquer ici
    )
    return processus


# ------------------------------------------------------------------
# Formatage des timestamps (identique aux versions précédentes)
# ------------------------------------------------------------------
def formater_timestamp(ts_texte: str) -> str:
    try:
        dt_naif = datetime.strptime(ts_texte, "%Y-%m-%d %H:%M:%S.%f")
        dt_local = dt_naif.replace(tzinfo=FUSEAU_LOCAL)
        return dt_local.strftime("%Y-%m-%d %H:%M:%S") + " heure Madagascar"
    except ValueError:
        return ts_texte


# ------------------------------------------------------------------
# Le nouveau prompt SRE — remplace l'ancien prompt ECS/JSON
# ------------------------------------------------------------------
def construire_prompt(niveau: str, logger: str, message: str, details_suivants: str) -> str:
    return f"""Tu es un ingénieur SRE senior spécialisé Spring Boot.
Tu aides un développeur débutant.
À partir du log fourni :

1. explique en français simple ce qui s'est passé.
2. indique si l'application continue à fonctionner ou non.
3. indique la cause la plus probable.
4. indique les indices précis dans le log.
5. propose des commandes Linux si nécessaire.
6. indique le niveau de gravité :
Critique
Élevé
Moyen
Faible
7. indique si cette erreur semble volontaire (test) ou réelle.
8. propose une action immédiate.

Réponds uniquement en français.

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


# ------------------------------------------------------------------
# Étape 3 — surveillance en temps réel (équivalent de "tail -f")
# ------------------------------------------------------------------
def surveiller_en_temps_reel():
    print(f"👀 Surveillance en temps réel de {CHEMIN_LOG} (Ctrl+C pour arrêter)\n")

    # Attend que le fichier existe (le temps que Log4j2 le crée)
    while not CHEMIN_LOG.exists():
        time.sleep(0.5)

    with open(CHEMIN_LOG, encoding="utf-8") as f:
        f.seek(0, 2)  # se place à la fin : on ne traite QUE le futur

        entree_courante = None  # accumulateur pour les lignes multi-lignes (stack trace)

        while True:
            ligne = f.readline()

            if not ligne:
                # Rien de nouveau : on traite l'entrée en attente s'il y
                # en a une, puis on patiente un peu avant de re-vérifier
                if entree_courante:
                    traiter_entree(entree_courante)
                    entree_courante = None
                time.sleep(1)
                continue

            ligne = ligne.rstrip("\n")
            correspondance = MOTIF_LIGNE.match(ligne)

            if correspondance:
                # Nouvelle entrée de log détectée : on traite l'ancienne
                # (si elle existait) et on en démarre une nouvelle
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
                # Ligne de continuation (ex: ligne de stack trace "at ...")
                entree_courante["details"] += ligne + "\n"


def traiter_entree(entree: dict):
    niveau = entree["niveau"]
    if niveau not in NIVEAUX_A_ANALYSER:
        return  # INFO/DEBUG/TRACE ignorés, comme avant

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


# ------------------------------------------------------------------
# Point d'entrée
# ------------------------------------------------------------------
if __name__ == "__main__":
    if not construire_projet():
        sys.exit(1)

    processus_app = lancer_application()

    def arret_propre(signum, frame):
        print("\n🛑 Arrêt demandé — fermeture de l'application...")
        processus_app.terminate()
        processus_app.wait(timeout=10)
        print("✅ Application arrêtée. Fin du script.")
        sys.exit(0)

    signal.signal(signal.SIGINT, arret_propre)

    print("⏳ Attente du démarrage de l'application (10s)...\n")
    time.sleep(10)

    try:
        surveiller_en_temps_reel()
    except KeyboardInterrupt:
        arret_propre(None, None)