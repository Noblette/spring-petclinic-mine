"""
run_and_analyze.py

Pipeline AIOps :

1. Build Spring Petclinic
2. Démarrage de l'application
3. Surveillance de petclinic.log
4. Détection des WARN / ERROR / FATAL
5. Analyse avec Ollama
6. Création du fichier incident
7. Envoi de l'analyse par email + fichier incident
8. Création du ticket GLPI
9. Ajout du fichier incident comme pièce jointe GLPI
10. Envoi d'un email de notification confirmant la création du ticket
    + même fichier incident en pièce jointe
"""

import os
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


# ============================================================
# CONFIGURATION
# ============================================================

DOSSIER_PROJET = Path(__file__).resolve().parent

CHEMIN_LOG = DOSSIER_PROJET / "logs" / "petclinic.log"
CHEMIN_STDERR = DOSSIER_PROJET / "logs" / "demarrage_stderr.log"
CHEMIN_INCIDENTS = DOSSIER_PROJET / "logs" / "incidents"

NOM_MODELE = "llama3.2:3b"

FUSEAU_LOCAL = ZoneInfo("Indian/Antananarivo")

URL_OLLAMA = "http://localhost:11434/api/generate"

TIMEOUT_OLLAMA = 300

NIVEAUX_A_ANALYSER = {
    "WARN",
    "ERROR",
    "FATAL",
}

LIGNES_DE_CONTEXTE = 20


# ============================================================
# GLPI
# ============================================================

GLPI_URL = "http://localhost"

GLPI_APP_TOKEN = os.getenv(
    "GLPI_APP_TOKEN",
    "Oh8MZhNDNF5bNhgRnv8VpKkHVTbbNdVNvQlXt6xl"
)

GLPI_USER_TOKEN = os.getenv(
    "GLPI_USER_TOKEN",
    "JB84o3AtMEUpxvUGxw8tLLEVTaGqYUD7QTNrDjfo"
)


# ============================================================
# EMAIL
# ============================================================

EMAIL_EXPEDITEUR = os.getenv(
    "EMAIL_EXPEDITEUR",
    "noblette.tsimihanta@gmail.com"
)

EMAIL_MOT_DE_PASSE = os.getenv(
    "EMAIL_MOT_DE_PASSE",
    "knex wyzt tlor zmwk"
)

EMAIL_DESTINATAIRE = os.getenv(
    "EMAIL_DESTINATAIRE",
    "noblette.tsimihanta@gmail.com"
)


# ============================================================
# REGEX LOG4J2
# ============================================================

MOTIF_LIGNE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})"
    r"\s+\[(?P<thread>.*?)\]\s+"
    r"(?P<niveau>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+"
    r"(?P<logger>\S+)\s+-\s+"
    r"(?P<message>.*)$"
)


# ============================================================
# ANALYSE
# ============================================================

SECTIONS = [
    "DESCRIPTION",
    "FONCTIONNEMENT",
    "CAUSE",
    "INDICES",
    "GRAVITE",
    "ACTION",
]

NIVEAUX_GRAVITE = [
    "Critique",
    "Élevé",
    "Moyen",
    "Faible",
]

TITRES_AFFICHAGE = {
    "DESCRIPTION": "Description",
    "FONCTIONNEMENT": "Fonctionnement de l'application",
    "CAUSE": "Cause probable",
    "INDICES": "Indices dans le log",
    "GRAVITE": "Gravité",
    "ACTION": "Action recommandée",
}


# ============================================================
# BUILD
# ============================================================

def construire_projet() -> bool:

    print("Build Maven en cours (peut prendre 1-2 minutes)...")

    resultat = subprocess.run(
        [
            "./mvnw",
            "clean",
            "package",
            "-DskipTests",
        ],
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


# ============================================================
# POSITION DU LOG
# ============================================================

def obtenir_position_et_nombre_lignes() -> tuple[int, int]:

    if not CHEMIN_LOG.exists():
        return 0, 0

    nombre_lignes = 0

    with open(
        CHEMIN_LOG,
        encoding="utf-8"
    ) as f:

        for _ in f:
            nombre_lignes += 1

    taille = CHEMIN_LOG.stat().st_size

    return taille, nombre_lignes


# ============================================================
# LANCEMENT APPLICATION
# ============================================================

def lancer_application():

    jars = list(
        (DOSSIER_PROJET / "target").glob("*.jar")
    )

    jars = [
        j
        for j in jars
        if "original" not in j.name
    ]

    if not jars:

        raise FileNotFoundError(
            "Aucun .jar trouvé dans target/ après le build."
        )

    print(
        f"Lancement de {jars[0].name}..."
    )

    CHEMIN_STDERR.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fichier_stderr = open(
        CHEMIN_STDERR,
        "w",
        encoding="utf-8"
    )

    processus = subprocess.Popen(
        [
            "java",
            "-jar",
            str(jars[0]),
        ],
        cwd=DOSSIER_PROJET,
        stdout=subprocess.DEVNULL,
        stderr=fichier_stderr,
    )

    return processus, fichier_stderr


# ============================================================
# TIMESTAMP
# ============================================================

def formater_timestamp(ts_texte: str) -> str:

    try:

        dt_naif = datetime.strptime(
            ts_texte,
            "%Y-%m-%d %H:%M:%S.%f"
        )

        dt_local = dt_naif.replace(
            tzinfo=FUSEAU_LOCAL
        )

        return (
            dt_local.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            + " heure Madagascar"
        )

    except ValueError:

        return ts_texte


# ============================================================
# PROMPT OLLAMA
# ============================================================

def construire_prompt(
    niveau: str,
    logger: str,
    message: str,
    details_suivants: str,
    numero_ligne,
) -> str:

    reference_ligne = (
        f"Numéro de ligne dans le fichier de log : "
        f"{numero_ligne}\n"
        if numero_ligne is not None
        else
        "Numéro de ligne : non disponible "
        "(erreur survenue avant l'écriture du fichier de log)\n"
    )

    return f"""
Tu es un ingénieur SRE senior spécialisé Spring Boot.
Tu aides un développeur débutant.

RÈGLE ABSOLUE :

Pour DESCRIPTION et CAUSE, appuie chaque affirmation
sur une citation exacte du log fourni ci-dessous.

Si une information n'est pas déductible du log,
dis :

"je ne peux pas le confirmer avec ce log seul"

plutôt que de deviner.

IMPORTANT :

Le numéro de ligne fourni ci-dessous est une donnée
déjà calculée et fiable.

FORMAT DE RÉPONSE OBLIGATOIRE :

Réponds en français, en texte brut.

Chaque titre doit être écrit exactement comme ceci :

DESCRIPTION:

FONCTIONNEMENT:

CAUSE:

INDICES:

GRAVITE:

ACTION:

DESCRIPTION:
(résume en 1-2 phrases ce qui s'est passé)

FONCTIONNEMENT:
(l'application continue-t-elle à fonctionner ?)

CAUSE:
(la cause la plus probable)

INDICES:
(cite les mots/phrases exacts trouvés dans le message)

GRAVITE:
(un seul mot parmi : Critique / Eleve / Moyen / Faible,
puis une phrase de justification)

ACTION:
(action immédiate proposée)

{reference_ligne}

Niveau du log : {niveau}

Classe (logger) : {logger}

Message :
{message}

Détails complémentaires :
{details_suivants[:1500] if details_suivants else "aucun"}
"""


# ============================================================
# NETTOYAGE MARKDOWN
# ============================================================

def nettoyer_markdown(texte: str) -> str:

    texte = re.sub(
        r"\*\*(.+?)\*\*",
        r"\1",
        texte
    )

    texte = re.sub(
        r"^#+\s*",
        "",
        texte,
        flags=re.MULTILINE
    )

    return texte.strip()


# ============================================================
# EXTRACTION SECTIONS
# ============================================================

def extraire_sections(texte: str) -> dict:

    motif = re.compile(
        r"(?:^|\n)\s*:?\s*("
        + "|".join(SECTIONS)
        + r")\s*:\s*\n?",
        re.IGNORECASE
    )

    morceaux = motif.split(texte)

    resultat = {
        cle: ""
        for cle in SECTIONS
    }

    for i in range(
        1,
        len(morceaux) - 1,
        2
    ):

        cle = morceaux[i].strip().upper()

        contenu = morceaux[i + 1].strip()

        if cle in resultat:

            resultat[cle] = contenu

    if all(
        valeur == ""
        for valeur in resultat.values()
    ):

        resultat["DESCRIPTION"] = texte.strip()

    return resultat


# ============================================================
# EXTRACTION GRAVITE
# ============================================================

def extraire_niveau_court(
    texte_gravite: str
) -> str:

    for niveau in NIVEAUX_GRAVITE:

        if niveau.lower() in texte_gravite.lower():

            if niveau == "Eleve":
                return "Élevé"

            return niveau

    return "gravité non précisée"


# ============================================================
# OLLAMA
# ============================================================

def analyser_avec_ollama(
    niveau: str,
    logger: str,
    message: str,
    details: str,
    numero_ligne,
) -> dict:

    prompt = construire_prompt(
        niveau,
        logger,
        message,
        details,
        numero_ligne
    )

    try:

        reponse = requests.post(
            URL_OLLAMA,
            json={
                "model": NOM_MODELE,
                "prompt": prompt,
                "stream": False,
            },
            timeout=TIMEOUT_OLLAMA,
        )

        reponse.raise_for_status()

        texte_brut = nettoyer_markdown(
            reponse.json().get(
                "response",
                ""
            )
        )

        sections = extraire_sections(
            texte_brut
        )

        reference = (
            f"ligne {numero_ligne} du fichier de log"
            if numero_ligne is not None
            else
            "avant écriture dans le fichier de log "
            "(voir stderr)"
        )

        if sections["INDICES"]:

            sections["INDICES"] += (
                f"\n(Référence : {reference})"
            )

        else:

            sections["INDICES"] = (
                f"(Référence : {reference})"
            )

        return sections

    except requests.exceptions.ConnectionError:

        return {
            "DESCRIPTION":
                "[Impossible de joindre Ollama — "
                "vérifie qu'il tourne : ollama serve]"
        }

    except requests.exceptions.Timeout:

        return {
            "DESCRIPTION":
                f"[Timeout après {TIMEOUT_OLLAMA}s]"
        }

    except requests.exceptions.RequestException as e:

        return {
            "DESCRIPTION":
                f"[Erreur Ollama : {e}]"
        }


# ============================================================
# AFFICHAGE ANALYSE
# ============================================================

def afficher_analyse(sections: dict):

    for cle in SECTIONS:

        contenu = sections.get(
            cle,
            ""
        ).strip()

        if contenu:

            print(
                f"{TITRES_AFFICHAGE[cle]} :"
            )

            print(
                f"   {contenu}\n"
            )


# ============================================================
# RAPPORT
# ============================================================

def chemin_rapport_du_jour() -> Path:

    aujourd_hui = datetime.now(
        FUSEAU_LOCAL
    ).strftime("%Y-%m-%d")

    return (
        DOSSIER_PROJET
        / "logs"
        / f"rapport_analyses_{aujourd_hui}.log"
    )


def enregistrer_rapport(entree: dict):

    maintenant_local = datetime.now(
        FUSEAU_LOCAL
    )

    entree_complete = {

        "date":
            maintenant_local.strftime(
                "%Y-%m-%d"
            ),

        "heure":
            maintenant_local.strftime(
                "%H:%M:%S"
            ),

        **entree,
    }

    with open(
        chemin_rapport_du_jour(),
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            json.dumps(
                entree_complete,
                ensure_ascii=False
            )
            + "\n"
        )


# ============================================================
# FICHIER INCIDENT
# ============================================================

def souligner(titre: str) -> str:

    return (
        titre
        + "\n"
        + ("-" * len(titre))
    )


def creer_fichier_incident(
    entree: dict,
    contexte_avant: list[str]
) -> Path:

    CHEMIN_INCIDENTS.mkdir(
        parents=True,
        exist_ok=True
    )

    nom = datetime.now(
        FUSEAU_LOCAL
    ).strftime(
        "incident_%Y-%m-%d_%H-%M-%S.log"
    )

    chemin = (
        CHEMIN_INCIDENTS
        / nom
    )

    with open(
        chemin,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            f"Incident du "
            f"{formater_timestamp(entree['timestamp'])}"
            "\n\n"
        )

        f.write(
            f"Niveau    : {entree['niveau']}\n"
        )

        f.write(
            f"Ligne log : {entree['numero_ligne']}\n\n"
        )

        if contexte_avant:

            f.write(
                "".join(contexte_avant)
                + "\n"
            )

        # Ligne brute exacte du log
        f.write(
            entree["ligne_brute"]
            + "\n\n"
        )

        if entree["details"].strip():

            f.write(
                souligner(
                    "Détails / stack trace"
                )
                + "\n\n"
            )

            f.write(
                entree["details"]
            )

    return chemin


# ============================================================
# EMAIL ANALYSE
# ============================================================

def envoyer_email(
    sections: dict,
    entree: dict,
    fichier_incident: Path
):

    niveau_court = extraire_niveau_court(
        sections.get(
            "GRAVITE",
            ""
        )
    )

    sujet = (
        f"AIOps : Incident détecté - "
        f"{niveau_court}"
    )

    message = EmailMessage()

    message["Subject"] = sujet
    message["From"] = EMAIL_EXPEDITEUR
    message["To"] = EMAIL_DESTINATAIRE

    corps = f"""
Un incident vient d'être détecté.

Ligne brute du log :
{entree['ligne_brute']}

Description :
{sections.get('DESCRIPTION', '(non disponible)')}

Fonctionnement de l'application :
{sections.get('FONCTIONNEMENT', '(non disponible)')}

Cause :
{sections.get('CAUSE', '(non disponible)')}

Indices :
{sections.get('INDICES', '(non disponible)')}

Gravité :
{sections.get('GRAVITE', '(non disponible)')}

Action :
{sections.get('ACTION', '(non disponible)')}

Le fichier incident complet est joint à cet email.
"""

    message.set_content(
        corps
    )

    # Même fichier incident en pièce jointe
    with open(
        fichier_incident,
        "rb"
    ) as f:

        message.add_attachment(
            f.read(),
            maintype="text",
            subtype="plain",
            filename=fichier_incident.name
        )

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465
    ) as smtp:

        smtp.login(
            EMAIL_EXPEDITEUR,
            EMAIL_MOT_DE_PASSE
        )

        smtp.send_message(
            message
        )


# ============================================================
# EMAIL NOTIFICATION GLPI
# ============================================================

def envoyer_email_notification_ticket(
    ticket_id: int,
    fichier_incident: Path,
    piece_jointe_ok: bool = True
):

    sujet = (
        f"AIOps : Ticket GLPI #{ticket_id} créé"
    )

    message = EmailMessage()

    message["Subject"] = sujet
    message["From"] = EMAIL_EXPEDITEUR
    message["To"] = EMAIL_DESTINATAIRE

    if piece_jointe_ok:

        statut_piece_jointe = (
            "Le fichier incident a également "
            "été ajouté au ticket GLPI comme "
            "pièce jointe."
        )

    else:

        statut_piece_jointe = (
            "ATTENTION : le ticket a été créé, "
            "mais la pièce jointe n'a pas pu "
            "être ajoutée au ticket GLPI."
        )

    corps = f"""
Bonjour,

Le système AIOps a créé automatiquement
un ticket GLPI à la suite de la détection
d'un incident.

Ticket GLPI :
#{ticket_id}

Statut :
Ticket créé avec succès.

{statut_piece_jointe}

Le fichier incident est également joint
à cet email.

Ceci est une notification automatique
du système AIOps.
"""

    message.set_content(
        corps
    )

    # Le fichier incident est aussi joint
    # à l'email de notification GLPI.
    with open(
        fichier_incident,
        "rb"
    ) as f:

        message.add_attachment(
            f.read(),
            maintype="text",
            subtype="plain",
            filename=fichier_incident.name
        )

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465
    ) as smtp:

        smtp.login(
            EMAIL_EXPEDITEUR,
            EMAIL_MOT_DE_PASSE
        )

        smtp.send_message(
            message
        )


# ============================================================
# GLPI - CREATION DU TICKET
# ============================================================

def creer_ticket_glpi(
    sections: dict,
    entree: dict
) -> int:

    url_session = (
        f"{GLPI_URL}/apirest.php/initSession"
    )

    headers_auth = {

        "Content-Type":
            "application/json",

        "App-Token":
            GLPI_APP_TOKEN,

        "Authorization":
            f"user_token {GLPI_USER_TOKEN}",
    }

    print("Connexion GLPI...")

    response = requests.get(
        url_session,
        headers=headers_auth,
        timeout=10
    )

    response.raise_for_status()

    session_token = response.json()[
        "session_token"
    ]

    print(
        "Session GLPI créée avec succès."
    )

    # --------------------------------------------------------
    # Données incident
    # --------------------------------------------------------

    description = sections.get(
        "DESCRIPTION",
        "(non disponible)"
    ).strip()

    fonctionnement = sections.get(
        "FONCTIONNEMENT",
        "(non disponible)"
    ).strip()

    cause = sections.get(
        "CAUSE",
        "(non disponible)"
    ).strip()

    indices = sections.get(
        "INDICES",
        "(non disponible)"
    ).strip()

    gravite = sections.get(
        "GRAVITE",
        "(non disponible)"
    ).strip()

    action = sections.get(
        "ACTION",
        "(non disponible)"
    ).strip()

    niveau = entree.get(
        "niveau",
        "INCONNU"
    )

    logger = entree.get(
        "logger",
        "(non disponible)"
    )

    message = entree.get(
        "message",
        "(non disponible)"
    )

    numero_ligne = entree.get(
        "numero_ligne",
        "(non disponible)"
    )

    timestamp = entree.get(
        "timestamp",
        "(non disponible)"
    )

    ligne_brute = entree.get(
        "ligne_brute",
        "(non disponible)"
    )

    # --------------------------------------------------------
    # Contenu du ticket
    # --------------------------------------------------------

    contenu_ticket = f"""
INCIDENT AIOps - SPRING PETCLINIC


INFORMATIONS DE L'INCIDENT


Date / heure de l'événement :
{timestamp}

Niveau du log :
{niveau}

Ligne du log :
{numero_ligne}

Logger :
{logger}

Message :
{message}


ANALYSE DE L'INCIDENT



DESCRIPTION
{description}


FONCTIONNEMENT DE L'APPLICATION
{fonctionnement}


CAUSE PROBABLE
{cause}


INDICES DANS LE LOG
{indices}


GRAVITÉ
{gravite}


ACTION / SOLUTION RECOMMANDÉE
{action}


LIGNE BRUTE DU LOG

{ligne_brute}


Le fichier incident complet est ajouté
comme pièce jointe au ticket GLPI.
"""

    # --------------------------------------------------------
    # Création du ticket
    # --------------------------------------------------------

    url_ticket = (
        f"{GLPI_URL}/apirest.php/Ticket/"
    )

    headers_ticket = {

        "Content-Type":
            "application/json",

        "Session-Token":
            session_token,

        "App-Token":
            GLPI_APP_TOKEN,
    }

    payload = {

        "input": {

            "name":
                f"[AIOps] Spring Petclinic - {niveau}",

            "content":
                contenu_ticket,
        }
    }

    print(
        "Création du ticket GLPI..."
    )

    response_ticket = requests.post(
        url_ticket,
        headers=headers_ticket,
        json=payload,
        timeout=10
    )

    response_ticket.raise_for_status()

    resultat = response_ticket.json()

    ticket_id = resultat["id"]

    print(
        f"Ticket GLPI créé avec succès : #{ticket_id}"
    )

    return ticket_id


# ============================================================
# GLPI - PIECE JOINTE
# ============================================================

def ajouter_piece_jointe_glpi(
    ticket_id: int,
    chemin_incident: Path
):

    if not chemin_incident.exists():

        raise FileNotFoundError(
            f"Fichier incident introuvable : "
            f"{chemin_incident}"
        )

    # --------------------------------------------------------
    # Nouvelle session GLPI
    # --------------------------------------------------------

    url_session = (
        f"{GLPI_URL}/apirest.php/initSession"
    )

    headers_auth = {

        "Content-Type":
            "application/json",

        "App-Token":
            GLPI_APP_TOKEN,

        "Authorization":
            f"user_token {GLPI_USER_TOKEN}",
    }

    print(
        "Connexion GLPI pour la pièce jointe..."
    )

    response = requests.get(
        url_session,
        headers=headers_auth,
        timeout=10
    )

    response.raise_for_status()

    session_token = response.json()[
        "session_token"
    ]

    # --------------------------------------------------------
    # Upload du document
    # --------------------------------------------------------

    url_document = (
        f"{GLPI_URL}/apirest.php/Document/"
    )

    headers_document = {

        "Session-Token":
            session_token,

        "App-Token":
            GLPI_APP_TOKEN,
    }

    nom_fichier = chemin_incident.name

    upload_manifest = {

        "input": {

            "name":
                nom_fichier,

            "_filename":
                [nom_fichier],
        }
    }

    print(
        f"Envoi de la pièce jointe : "
        f"{nom_fichier}"
    )

    with open(
        chemin_incident,
        "rb"
    ) as fichier:

        files = {

            "uploadManifest": (
                None,
                json.dumps(
                    upload_manifest
                ),
                "application/json"
            ),

            "filename[0]": (
                nom_fichier,
                fichier,
                "text/plain"
            ),
        }

        response_document = requests.post(
            url_document,
            headers=headers_document,
            files=files,
            timeout=30
        )

    response_document.raise_for_status()

    resultat_document = (
        response_document.json()
    )

    document_id = resultat_document[
        "id"
    ]

    print(
        f"Document GLPI créé : #{document_id}"
    )

    # --------------------------------------------------------
    # Association au ticket
    # --------------------------------------------------------

    url_document_item = (
        f"{GLPI_URL}/apirest.php/Document_Item/"
    )

    headers_link = {

        "Content-Type":
            "application/json",

        "Session-Token":
            session_token,

        "App-Token":
            GLPI_APP_TOKEN,
    }

    payload_link = {

        "input": {

            "documents_id":
                document_id,

            "itemtype":
                "Ticket",

            "items_id":
                ticket_id,
        }
    }

    print(
        f"Association du document "
        f"au ticket #{ticket_id}..."
    )

    response_link = requests.post(
        url_document_item,
        headers=headers_link,
        json=payload_link,
        timeout=10
    )

    response_link.raise_for_status()

    print(
        f"Pièce jointe associée "
        f"au ticket #{ticket_id}."
    )

    return document_id


# ============================================================
# TRAITEMENT D'UN INCIDENT
# ============================================================

def traiter_entree(entree: dict):

    niveau = entree["niveau"]

    # --------------------------------------------------------
    # On ne traite que WARN / ERROR / FATAL
    # --------------------------------------------------------

    if niveau not in NIVEAUX_A_ANALYSER:

        return

    timestamp_affiche = formater_timestamp(
        entree["timestamp"]
    )

    print(
        f"[{timestamp_affiche}] "
        f"{niveau} — "
        f"{entree['logger']} "
        f"(ligne {entree['numero_ligne']})"
    )

    print(
        f"   {entree['message']}\n"
    )

    # --------------------------------------------------------
    # 1. Analyse Ollama
    # --------------------------------------------------------

    print(
        "   Analyse Ollama en cours..."
    )

    debut = datetime.now(
        timezone.utc
    )

    sections = analyser_avec_ollama(
        niveau,
        entree["logger"],
        entree["message"],
        entree["details"],
        entree["numero_ligne"]
    )

    duree = (
        datetime.now(timezone.utc)
        - debut
    ).total_seconds()

    print(
        f"---- Analyse Ollama "
        f"(durée : {duree:.1f}s) ----"
    )

    afficher_analyse(
        sections
    )

    # --------------------------------------------------------
    # 2. Création du fichier incident
    # --------------------------------------------------------

    try:

        chemin_incident = (
            creer_fichier_incident(
                entree,
                entree["contexte_avant"]
            )
        )

        print(
            f"Preuve sauvegardée : "
            f"{chemin_incident}"
        )

    except Exception as e:

        print(
            f"ERREUR : impossible de créer "
            f"le fichier incident : {e}"
        )

        return

    # ========================================================
    # 3. EMAIL DE L'ANALYSE
    # ========================================================

    try:

        envoyer_email(
            sections,
            entree,
            chemin_incident
        )

        print(
            "Email de l'analyse envoyé "
            "avec succès."
        )

    except Exception as e:

        print(
            f"Échec de l'envoi de "
            f"l'email d'analyse : {e}"
        )

    # ========================================================
    # 4. CREATION DU TICKET GLPI
    # ========================================================

    ticket_id = None

    try:

        ticket_id = creer_ticket_glpi(
            sections,
            entree
        )

        print(
            f"Ticket GLPI #{ticket_id} "
            f"créé avec succès."
        )

    except Exception as e:

        print(
            f"Échec de création "
            f"du ticket GLPI : {e}"
        )

    # ========================================================
    # 5. PIECE JOINTE GLPI
    # ========================================================

    piece_jointe_ok = False

    if ticket_id is not None:

        try:

            document_id = (
                ajouter_piece_jointe_glpi(
                    ticket_id,
                    chemin_incident
                )
            )

            piece_jointe_ok = True

            print(
                f"Fichier incident ajouté "
                f"au ticket GLPI #{ticket_id} "
                f"(Document #{document_id})."
            )

        except Exception as e:

            print(
                f"Échec de l'ajout de la "
                f"pièce jointe au ticket GLPI : {e}"
            )

    # ========================================================
    # 6. EMAIL DE NOTIFICATION GLPI
    # ========================================================

    if ticket_id is not None:

        try:

            envoyer_email_notification_ticket(
                ticket_id,
                chemin_incident,
                piece_jointe_ok
            )

            print(
                f"Email de notification du "
                f"ticket GLPI #{ticket_id} envoyé."
            )

        except Exception as e:

            print(
                f"Échec de l'envoi de la "
                f"notification GLPI : {e}"
            )

    # ========================================================
    # 7. RAPPORT JSON
    # ========================================================

    enregistrer_rapport({

        "timestamp_evenement":
            entree["timestamp"],

        "timestamp_evenement_lisible":
            timestamp_affiche,

        "numero_ligne":
            entree["numero_ligne"],

        "timestamp_analyse_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "niveau":
            niveau,

        "logger":
            entree["logger"],

        "message":
            entree["message"],

        "ligne_brute":
            entree["ligne_brute"],

        "analyse":
            sections,

        "preuve":
            str(chemin_incident),

        "glpi_ticket_id":
            ticket_id,

        "glpi_piece_jointe":
            piece_jointe_ok,
    })

    print(
        "-------------------------\n"
    )


# ============================================================
# CRASH AU DEMARRAGE
# ============================================================

def analyser_crash_demarrage():

    contenu_stderr = (
        CHEMIN_STDERR.read_text(
            encoding="utf-8",
            errors="replace"
        ).strip()
    )

    if not contenu_stderr:

        print(
            "Le processus s'est arrêté tôt, "
            "mais stderr est vide — "
            "cause indéterminée.\n"
        )

        return

    print(
        "L'application s'est arrêtée "
        "pendant le démarrage — "
        "analyse de stderr..."
    )

    print(
        f"   Extrait : "
        f"{contenu_stderr[:300]}\n"
    )

    print(
        "   Analyse Ollama en cours..."
    )

    debut = datetime.now(
        timezone.utc
    )

    sections = analyser_avec_ollama(
        "ERROR",
        "démarrage (stderr)",
        contenu_stderr[:1500],
        "",
        None
    )

    duree = (
        datetime.now(timezone.utc)
        - debut
    ).total_seconds()

    print(
        f"---- Analyse Ollama "
        f"(durée : {duree:.1f}s) ----"
    )

    afficher_analyse(
        sections
    )

    print(
        "-------------------------\n"
    )

    enregistrer_rapport({

        "timestamp_evenement":
            datetime.now(
                FUSEAU_LOCAL
            ).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3],

        "timestamp_evenement_lisible":
            datetime.now(
                FUSEAU_LOCAL
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            + " heure Madagascar",

        "numero_ligne":
            None,

        "timestamp_analyse_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "niveau":
            "ERROR",

        "logger":
            "démarrage (stderr, avant Log4j2)",

        "message":
            contenu_stderr[:500],

        "analyse":
            sections,
    })


# ============================================================
# SURVEILLANCE TEMPS REEL
# ============================================================

def surveiller_en_temps_reel(
    position_depart: int,
    numero_ligne_initial: int
):

    print(
        f"Surveillance en temps réel de "
        f"{CHEMIN_LOG} "
        f"(Ctrl+C pour arrêter)"
    )

    print(
        "Aucune erreur détectée pour "
        "l'instant — tout va bien.\n"
    )

    while not CHEMIN_LOG.exists():

        time.sleep(0.5)

    contexte = deque(
        maxlen=LIGNES_DE_CONTEXTE
    )

    with open(
        CHEMIN_LOG,
        encoding="utf-8"
    ) as f:

        f.seek(
            position_depart
        )

        numero_ligne = (
            numero_ligne_initial
        )

        entree_courante = None

        cycles_vides_consecutifs = 0

        SEUIL_SILENCE = 3

        while True:

            ligne = f.readline()

            if not ligne:

                cycles_vides_consecutifs += 1

                if (
                    entree_courante
                    and cycles_vides_consecutifs
                    >= SEUIL_SILENCE
                ):

                    traiter_entree(
                        entree_courante
                    )

                    entree_courante = None

                    cycles_vides_consecutifs = 0

                time.sleep(0.5)

                continue

            cycles_vides_consecutifs = 0

            numero_ligne += 1

            ligne_brute = (
                ligne
                if ligne.endswith("\n")
                else ligne + "\n"
            )

            ligne_nettoyee = (
                ligne.rstrip("\n")
            )

            correspondance = (
                MOTIF_LIGNE.match(
                    ligne_nettoyee
                )
            )

            if correspondance:

                if entree_courante:

                    traiter_entree(
                        entree_courante
                    )

                entree_courante = {

                    "timestamp":
                        correspondance.group(
                            "timestamp"
                        ),

                    "niveau":
                        correspondance.group(
                            "niveau"
                        ),

                    "logger":
                        correspondance.group(
                            "logger"
                        ),

                    "message":
                        correspondance.group(
                            "message"
                        ),

                    "details":
                        "",

                    "numero_ligne":
                        numero_ligne,

                    "contexte_avant":
                        list(contexte),

                    "ligne_brute":
                        ligne_nettoyee,
                }

            elif entree_courante:

                entree_courante["details"] += (
                    ligne_nettoyee
                    + "\n"
                )

            contexte.append(
                ligne_brute
            )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if not construire_projet():

        sys.exit(1)

    (
        position_avant_lancement,
        lignes_avant_lancement
    ) = obtenir_position_et_nombre_lignes()

    processus_app, fichier_stderr = (
        lancer_application()
    )

    def arret_propre(
        signum,
        frame
    ):

        print(
            "\nArrêt demandé — "
            "fermeture de l'application..."
        )

        processus_app.terminate()

        try:

            processus_app.wait(
                timeout=10
            )

        except subprocess.TimeoutExpired:

            processus_app.kill()

            processus_app.wait()

        fichier_stderr.close()

        print(
            "Application arrêtée. "
            "Fin du script."
        )

        sys.exit(0)

    signal.signal(
        signal.SIGINT,
        arret_propre
    )

    print(
        "Attente du démarrage de "
        "l'application (10s)...\n"
    )

    time.sleep(10)

    if (
        processus_app.poll()
        is not None
    ):

        fichier_stderr.close()

        analyser_crash_demarrage()

        print(
            "L'application n'a pas pu "
            "démarrer. Fin du script."
        )

        sys.exit(1)

    try:

        surveiller_en_temps_reel(
            position_avant_lancement,
            lignes_avant_lancement
        )

    except KeyboardInterrupt:

        arret_propre(
            None,
            None
        )