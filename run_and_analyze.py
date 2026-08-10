"""
run_and_analyze.py

CORRECTIONS de cette version :
  1. BUG DE TRONCATURE CORRIGÉ : le script finalisait une entrée dès
     le premier cycle sans nouvelle donnée détectée, ce qui pouvait
     couper un bloc multi-lignes en plein milieu si Java l'écrivait
     en plusieurs petites écritures avec de micro-pauses entre elles
     (observé concrètement : "Web server failed to " coupé avant
     "start"). Corrigé avec un "debounce" : on attend plusieurs
     cycles consécutifs sans nouvelle ligne avant de considérer
     qu'une entrée est vraiment terminée.
  2. CONTEXTE AJOUTÉ : un tampon glissant garde les 20 dernières
     lignes brutes du log (tous niveaux confondus), pour que le
     fichier de preuve/l'email montrent aussi ce qui précédait
     l'erreur (comme dans VSCode), pas seulement le bloc isolé.
"""

import re
import subprocess
import sys
import time
import signal
import requests
import json
import smtplib
from collections import deque
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from email.message import EmailMessage


DOSSIER_PROJET = Path(__file__).resolve().parent
CHEMIN_LOG = DOSSIER_PROJET / "logs" / "petclinic.log"
CHEMIN_STDERR = DOSSIER_PROJET / "logs" / "demarrage_stderr.log"
CHEMIN_INCIDENTS = DOSSIER_PROJET / "logs" / "incidents"
NOM_MODELE = "llama3.2:3b"
FUSEAU_LOCAL = ZoneInfo("Indian/Antananarivo")
URL_OLLAMA = "http://localhost:11434/api/generate"
TIMEOUT_OLLAMA = 300
NIVEAUX_A_ANALYSER = {"WARN", "ERROR", "FATAL"}
LIGNES_DE_CONTEXTE = 20  # nombre de lignes brutes gardées avant l'incident

MOTIF_LIGNE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})"
    r"\s\[(?P<thread>.*?)\]\s"
    r"(?P<niveau>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"(?P<logger>\S+)\s-\s"
    r"(?P<message>.*)$"
)

SECTIONS = ["DESCRIPTION", "FONCTIONNEMENT", "CAUSE", "INDICES", "GRAVITE", "ACTION"]

TITRES_AFFICHAGE = {
    "DESCRIPTION": "Description",
    "FONCTIONNEMENT": "Fonctionnement de l'application",
    "CAUSE": "Cause probable",
    "INDICES": "Indices dans le log",
    "GRAVITE": "Gravité",
    "ACTION": "Action recommandée",
}

# Configuration email (à adapter / idéalement à sortir dans des
# variables d'environnement plutôt que codées en dur, voir remarque
# de sécurité en fin de fichier)
EMAIL_EXPEDITEUR = "noblette.tsimihanta@gmail.com"
EMAIL_MOT_DE_PASSE = "knex wyzt tlor zmwk"
EMAIL_DESTINATAIRE = "noblette.tsimihanta@gmail.com"


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

RÈGLE ABSOLUE : pour DESCRIPTION et CAUSE, appuie chaque affirmation
sur une citation exacte du log fourni ci-dessous. Si une information
n'est pas déductible du log, dis "je ne peux pas le confirmer avec ce
log seul" plutôt que de deviner.

IMPORTANT : le numéro de ligne fourni ci-dessous est une donnée déjà
calculée et fiable — ce n'est PAS un élément à vérifier dans le texte.

FORMAT DE RÉPONSE OBLIGATOIRE : réponds en français, en texte brut
(pas de Markdown), en respectant EXACTEMENT cette structure — chaque
titre ci-dessous seul sur sa ligne, suivi de ":", puis le contenu :

DESCRIPTION:
(résume en 1-2 phrases ce qui s'est passé)

FONCTIONNEMENT:
(l'application continue-t-elle à fonctionner ?)

CAUSE:
(la cause la plus probable)

INDICES:
(cite les mots/phrases exacts trouvés dans le message)

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


def extraire_sections(texte: str) -> dict:
    motif = re.compile(
        r"(?:^|\n)\s*(" + "|".join(SECTIONS) + r")\s*:\s*\n?",
        re.IGNORECASE,
    )
    morceaux = motif.split(texte)

    resultat = {cle: "" for cle in SECTIONS}
    for i in range(1, len(morceaux) - 1, 2):
        cle = morceaux[i].strip().upper()
        contenu = morceaux[i + 1].strip()
        if cle in resultat:
            resultat[cle] = contenu

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
        sections = extraire_sections(texte_brut)

        reference = (
            f"ligne {numero_ligne} du fichier de log"
            if numero_ligne is not None
            else "avant écriture dans le fichier de log (voir stderr)"
        )
        if sections["INDICES"]:
            sections["INDICES"] += f"\n(Référence : {reference})"
        else:
            sections["INDICES"] = f"(Référence : {reference})"

        return sections

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


# ----------------------------------------------------------------------
# NOUVEAU : fichier de preuve = contexte (lignes précédentes) + le
# bloc complet de l'incident, comme ce qu'on voit en scrollant VSCode.
# ----------------------------------------------------------------------
def creer_fichier_incident(entree: dict, contexte: list[str]) -> Path:
    CHEMIN_INCIDENTS.mkdir(parents=True, exist_ok=True)

    nom = datetime.now(FUSEAU_LOCAL).strftime("incident_%Y-%m-%d_%H-%M-%S.log")
    chemin = CHEMIN_INCIDENTS / nom

    with open(chemin, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("INCIDENT DETECTE\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"Date : {formater_timestamp(entree['timestamp'])}\n")
        f.write(f"Niveau : {entree['niveau']}\n")
        f.write(f"Logger : {entree['logger']}\n")
        f.write(f"Ligne : {entree['numero_ligne']}\n\n")

        f.write("-" * 70 + "\n")
        f.write(f"CONTEXTE — {len(contexte)} dernières lignes avant/pendant l'incident\n")
        f.write("-" * 70 + "\n\n")
        f.write("".join(contexte) + "\n")

        f.write("-" * 70 + "\n")
        f.write("MESSAGE PRINCIPAL\n")
        f.write("-" * 70 + "\n\n")
        f.write(entree["message"] + "\n\n")

        if entree["details"].strip():
            f.write("-" * 70 + "\n")
            f.write("STACKTRACE / DÉTAILS COMPLETS\n")
            f.write("-" * 70 + "\n\n")
            f.write(entree["details"])

    return chemin


def envoyer_email(sections: dict, fichier_incident: Path):
    message = EmailMessage()
    message["Subject"] = f"[AIOps] Incident détecté — {sections.get('GRAVITE', 'gravité inconnue')}"
    message["From"] = EMAIL_EXPEDITEUR
    message["To"] = EMAIL_DESTINATAIRE

    corps = f"""Un incident vient d'être détecté.

Description :
{sections.get('DESCRIPTION', '(non disponible)')}

Cause :
{sections.get('CAUSE', '(non disponible)')}

Gravité :
{sections.get('GRAVITE', '(non disponible)')}

Action :
{sections.get('ACTION', '(non disponible)')}

Le contexte complet du log (preuve brute) est joint à cet email.
"""
    message.set_content(corps)

    with open(fichier_incident, "rb") as f:
        message.add_attachment(
            f.read(), maintype="text", subtype="plain", filename=fichier_incident.name
        )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_EXPEDITEUR, EMAIL_MOT_DE_PASSE)
        smtp.send_message(message)


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

    # Tampon glissant des dernières lignes BRUTES lues (contexte)
    contexte = deque(maxlen=LIGNES_DE_CONTEXTE)

    with open(CHEMIN_LOG, encoding="utf-8") as f:
        f.seek(position_depart)
        numero_ligne = numero_ligne_initial
        entree_courante = None

        # CORRECTIF DEBOUNCE : on ne finalise une entrée qu'après
        # plusieurs cycles CONSÉCUTIFS sans nouvelle ligne (silence
        # confirmé), pas dès le premier cycle vide — ce qui évite de
        # couper un bloc multi-lignes en cours d'écriture par Java.
        cycles_vides_consecutifs = 0
        SEUIL_SILENCE = 3  # ~1.5s de silence confirmé (3 x 0.5s)

        while True:
            ligne = f.readline()

            if not ligne:
                cycles_vides_consecutifs += 1
                if entree_courante and cycles_vides_consecutifs >= SEUIL_SILENCE:
                    traiter_entree(entree_courante, list(contexte))
                    entree_courante = None
                    cycles_vides_consecutifs = 0
                time.sleep(0.5)
                continue

            cycles_vides_consecutifs = 0
            numero_ligne += 1
            contexte.append(ligne if ligne.endswith("\n") else ligne + "\n")

            ligne_nettoyee = ligne.rstrip("\n")
            correspondance = MOTIF_LIGNE.match(ligne_nettoyee)

            if correspondance:
                if entree_courante:
                    traiter_entree(entree_courante, list(contexte))
                entree_courante = {
                    "timestamp": correspondance.group("timestamp"),
                    "niveau": correspondance.group("niveau"),
                    "logger": correspondance.group("logger"),
                    "message": correspondance.group("message"),
                    "details": "",
                    "numero_ligne": numero_ligne,
                }
            elif entree_courante:
                entree_courante["details"] += ligne_nettoyee + "\n"


def traiter_entree(entree: dict, contexte: list[str]):
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

    chemin_incident = creer_fichier_incident(entree, contexte)
    print(f"Preuve sauvegardée : {chemin_incident}")

    try:
        envoyer_email(sections, chemin_incident)
        print("Email envoyé.")
    except Exception as e:
        print(f"Échec de l'envoi d'email : {e}")

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
        "preuve": str(chemin_incident),
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