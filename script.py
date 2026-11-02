#!/usr/bin/env python3

"""
run_and_analyze_glpi_routing.py

PIPELINE AIOps
==============

1. Build Spring Petclinic
2. Démarrage de l'application
3. Surveillance de petclinic.log
4. Détection WARN / ERROR / FATAL
5. Analyse avec Ollama
6. Création du fichier incident
7. Email de l'analyse + fichier incident
8. Création du ticket GLPI
9. Ajout du fichier incident comme pièce jointe
10. Classification domaine -> catégorie -> groupe -> utilisateurs
11. Urgence / impact cohérents avec la gravité
12. Email de notification GLPI + pièce jointe

IMPORTANT
=========

Les groupes, utilisateurs et catégories doivent exister dans GLPI
avec les noms indiqués dans la configuration ci-dessous.

Les IDs GLPI ne sont pas codés en dur :
le script recherche automatiquement les IDs à partir des noms.

Ordre GLPI :

    création ticket
          ↓
    récupération ticket_id
          ↓
    pièce jointe
          ↓
    groupe
          ↓
    utilisateurs
          ↓
    notification

Une erreur d'affectation ne doit jamais empêcher la pièce jointe.
"""


import os
import re
import json
import signal
import smtplib
import subprocess
import sys
import time

from collections import deque
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

import requests


# ============================================================
# CONFIGURATION GENERALE
# ============================================================

DOSSIER_PROJET = Path(__file__).resolve().parent

CHEMIN_LOG = (
    DOSSIER_PROJET
    / "logs"
    / "petclinic.log"
)

CHEMIN_STDERR = (
    DOSSIER_PROJET
    / "logs"
    / "demarrage_stderr.log"
)

CHEMIN_INCIDENTS = (
    DOSSIER_PROJET
    / "logs"
    / "incidents"
)

NOM_MODELE = os.getenv(
    "OLLAMA_MODEL",
    "llama3.2:3b",
)

FUSEAU_LOCAL = ZoneInfo(
    "Indian/Antananarivo"
)

URL_OLLAMA = os.getenv(
    "OLLAMA_URL",
    "http://localhost:11434/api/generate",
)

TIMEOUT_OLLAMA = 300

NIVEAUX_A_ANALYSER = {
    "WARN",
    "ERROR",
    "FATAL",
}

LIGNES_DE_CONTEXTE = 20


# ============================================================
# APPLICATION
# ============================================================

APPLICATION_NAME = os.getenv(
    "AIOPS_APPLICATION_NAME",
    "Spring Petclinic",
)

APPLICATION_SHORT_NAME = os.getenv(
    "AIOPS_APPLICATION_SHORT_NAME",
    "Petclinic",
)


# ============================================================
# GLPI
# ============================================================

GLPI_URL = os.getenv(
    "GLPI_URL",
    "http://localhost",
)

GLPI_APP_TOKEN = os.getenv(
    "GLPI_APP_TOKEN"
)

GLPI_USER_TOKEN = os.getenv(
    "GLPI_USER_TOKEN"
)


# ============================================================
# GROUPES GLPI
# ============================================================

GLPI_GROUP_NAMES = {

    "BASE_DE_DONNEES":
        "DBA",

    "SECURITE":
        "Sécurité",

    "PRODUCTION":
        "Production",

    "APPLICATION":
        "DevOps",

    "RESEAU":
        "Réseau",

    "AUTRE":
        "Support applicatif",
}


# ============================================================
# UTILISATEURS GLPI
# ============================================================

GLPI_USER_NAMES = {

    "BASE_DE_DONNEES":
        ["dba"],

    "SECURITE":
        ["sécurité"],

    "PRODUCTION":
        ["devopsUser2"],

    "APPLICATION":
        ["devopsUser2"],

    "RESEAU":
        ["réseau"],

    "AUTRE":
        ["glpi"],
}


# ============================================================
# CATEGORIES ITIL GLPI
# ============================================================

GLPI_CATEGORY_NAMES = {

    "BASE_DE_DONNEES":
        "Base de données",

    "SECURITE":
        "Sécurité",

    "PRODUCTION":
        "Production",

    "APPLICATION":
        "Application",
}


# ============================================================
# EMAIL
# ============================================================

EMAIL_EXPEDITEUR = os.getenv(
    "EMAIL_EXPEDITEUR"
)

EMAIL_MOT_DE_PASSE = os.getenv(
    "EMAIL_MOT_DE_PASSE"
)

EMAIL_DESTINATAIRE = os.getenv(
    "EMAIL_DESTINATAIRE"
)

SMTP_HOST = os.getenv(
    "SMTP_HOST",
    "smtp.gmail.com",
)

SMTP_PORT = int(
    os.getenv(
        "SMTP_PORT",
        "465",
    )
)


# ============================================================
# REGEX LOG4J2
# ============================================================

MOTIF_LIGNE = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}\.\d{3}"
    r")"
    r"\s+\[(?P<thread>.*?)\]\s+"
    r"(?P<niveau>"
    r"TRACE|DEBUG|INFO|WARN|ERROR|FATAL"
    r")\s+"
    r"(?P<logger>\S+)"
    r"\s+-\s+"
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
    "DOMAINE",
    "ACTION",
]


TITRES_AFFICHAGE = {

    "DESCRIPTION":
        "Description",

    "FONCTIONNEMENT":
        "Fonctionnement de l'application",

    "CAUSE":
        "Cause probable",

    "INDICES":
        "Indices dans le log",

    "GRAVITE":
        "Gravité",

    "DOMAINE":
        "Domaine",

    "ACTION":
        "Action recommandée",
}


GRAVITE_CANONIQUE = {

    "critique":
        "Critique",

    "critical":
        "Critique",

    "élevé":
        "Élevé",

    "eleve":
        "Élevé",

    "éleve":
        "Élevé",

    "high":
        "Élevé",

    "moyen":
        "Moyen",

    "medium":
        "Moyen",

    "faible":
        "Faible",

    "low":
        "Faible",
}


DOMAINES = {

    "BASE_DE_DONNEES",
    "SECURITE",
    "PRODUCTION",
    "APPLICATION",
    "RESEAU",
    "AUTRE",
}


# ============================================================
# VERIFICATION CONFIGURATION
# ============================================================

def verifier_configuration():

    manquants = []

    configuration = {

        "GLPI_APP_TOKEN":
            GLPI_APP_TOKEN,

        "GLPI_USER_TOKEN":
            GLPI_USER_TOKEN,

        "EMAIL_EXPEDITEUR":
            EMAIL_EXPEDITEUR,

        "EMAIL_MOT_DE_PASSE":
            EMAIL_MOT_DE_PASSE,

        "EMAIL_DESTINATAIRE":
            EMAIL_DESTINATAIRE,
    }

    for nom, valeur in configuration.items():

        if not valeur:
            manquants.append(nom)

    if manquants:

        raise RuntimeError(
            "Variables d'environnement manquantes : "
            + ", ".join(manquants)
        )


# ============================================================
# HEADERS GLPI
# ============================================================

def glpi_headers(
    session_token=None,
    content_type=True,
):

    headers = {

        "App-Token":
            GLPI_APP_TOKEN,
    }

    if session_token:

        headers[
            "Session-Token"
        ] = session_token

    if content_type:

        headers[
            "Content-Type"
        ] = "application/json"

    return headers


# ============================================================
# SESSION GLPI
# ============================================================

def glpi_init_session():

    url = (
        f"{GLPI_URL}"
        "/apirest.php/initSession"
    )

    headers = {

        "App-Token":
            GLPI_APP_TOKEN,

        "Authorization":
            f"user_token {GLPI_USER_TOKEN}",

        "Content-Type":
            "application/json",
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=10,
    )

    response.raise_for_status()

    data = response.json()

    token = data.get(
        "session_token"
    )

    if not token:

        raise RuntimeError(
            "GLPI n'a pas fourni "
            f"de session_token : {data}"
        )

    return token


# ============================================================
# RECUPERATION DES OBJETS GLPI
# ============================================================

def glpi_get_all(
    session_token,
    itemtype,
):

    resultats = []

    debut = 0

    taille_page = 100

    while True:

        fin = (
            debut
            + taille_page
            - 1
        )

        response = requests.get(

            f"{GLPI_URL}"
            f"/apirest.php/{itemtype}/",

            headers=glpi_headers(
                session_token
            ),

            params={
                "range":
                    f"{debut}-{fin}"
            },

            timeout=15,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(
            data,
            list,
        ):
            break

        resultats.extend(data)

        content_range = (
            response.headers.get(
                "Content-Range",
                "",
            )
        )

        match = re.search(
            r"/(\d+)$",
            content_range,
        )

        if len(data) < taille_page:
            break

        if (
            match
            and fin
            >= int(match.group(1)) - 1
        ):
            break

        debut += taille_page

    return resultats


# ============================================================
# RECHERCHE ID PAR NOM
# ============================================================

def normaliser_nom(valeur):

    return re.sub(
        r"\s+",
        " ",
        str(valeur)
        .strip()
        .casefold(),
    )


def trouver_id_par_nom(
    elements,
    nom,
):

    cible = normaliser_nom(
        nom
    )

    for element in elements:

        if (
            normaliser_nom(
                element.get(
                    "name",
                    "",
                )
            )
            == cible
        ):

            return int(
                element["id"]
            )

    return None


# ============================================================
# RESOLUTION CONFIGURATION GLPI
# ============================================================

def glpi_resoudre_configuration(
    session_token,
):

    print(
        "Lecture de la configuration GLPI..."
    )

    groupes = glpi_get_all(
        session_token,
        "Group",
    )

    utilisateurs = glpi_get_all(
        session_token,
        "User",
    )

    categories = glpi_get_all(
        session_token,
        "ITILCategory",
    )

    groupes_ids = {}

    utilisateurs_ids = {}

    categories_ids = {}

    # --------------------------------------------------------
    # GROUPES
    # --------------------------------------------------------

    for domaine, nom_groupe in (
        GLPI_GROUP_NAMES.items()
    ):

        groupes_ids[domaine] = (
            trouver_id_par_nom(
                groupes,
                nom_groupe,
            )
        )

    # --------------------------------------------------------
    # UTILISATEURS
    # --------------------------------------------------------

    for domaine, noms in (
        GLPI_USER_NAMES.items()
    ):

        utilisateurs_ids[domaine] = []

        for nom in noms:

            user_id = (
                trouver_id_par_nom(
                    utilisateurs,
                    nom,
                )
            )

            if user_id is not None:

                utilisateurs_ids[
                    domaine
                ].append(user_id)

    # --------------------------------------------------------
    # CATEGORIES
    # --------------------------------------------------------

    for domaine, nom_categorie in (
        GLPI_CATEGORY_NAMES.items()
    ):

        categories_ids[domaine] = (
            trouver_id_par_nom(
                categories,
                nom_categorie,
            )
        )

    return (
        groupes_ids,
        utilisateurs_ids,
        categories_ids,
    )


# ============================================================
# BUILD MAVEN
# ============================================================

def construire_projet():

    print(
        "Build Maven en cours "
        "(peut prendre 1-2 minutes)..."
    )

    resultat = subprocess.run(

        [
            "./mvnw",
            "clean",
            "package",
            "-DskipTests",
            "-Dcheckstyle.skip=true",
        ],

        cwd=DOSSIER_PROJET,

        capture_output=True,

        text=True,
    )

    if resultat.returncode != 0:

        print(
            "Le build a échoué :"
        )

        print(
            resultat.stdout[-3000:]
        )

        print(
            resultat.stderr[-1500:]
        )

        return False

    print(
        "Build réussi.\n"
    )

    return True


# ============================================================
# POSITION DU LOG
# ============================================================

def obtenir_position_et_nombre_lignes():

    if not CHEMIN_LOG.exists():

        return 0, 0

    nombre_lignes = 0

    with open(
        CHEMIN_LOG,
        encoding="utf-8",
    ) as fichier:

        for _ in fichier:

            nombre_lignes += 1

    taille = (
        CHEMIN_LOG.stat()
        .st_size
    )

    return (
        taille,
        nombre_lignes,
    )


# ============================================================
# LANCEMENT APPLICATION
# ============================================================

def lancer_application():

    jars = list(
        (
            DOSSIER_PROJET
            / "target"
        ).glob("*.jar")
    )

    jars = [

        jar
        for jar in jars

        if "original"
        not in jar.name
    ]

    if not jars:

        raise FileNotFoundError(
            "Aucun .jar trouvé "
            "dans target/ après le build."
        )

    print(
        f"Lancement de "
        f"{jars[0].name}..."
    )

    CHEMIN_STDERR.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fichier_stderr = open(
        CHEMIN_STDERR,
        "w",
        encoding="utf-8",
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

    return (
        processus,
        fichier_stderr,
    )


# ============================================================
# TIMESTAMP
# ============================================================

def formater_timestamp(
    ts_texte,
):

    try:

        dt_naif = datetime.strptime(
            ts_texte,
            "%Y-%m-%d %H:%M:%S.%f",
        )

        dt_local = (
            dt_naif.replace(
                tzinfo=FUSEAU_LOCAL
            )
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
    niveau,
    logger,
    message,
    details_suivants,
    numero_ligne,
):

    reference_ligne = (

        f"Numéro de ligne "
        f"dans le fichier de log : "
        f"{numero_ligne}\n"

        if numero_ligne is not None

        else
        "Numéro de ligne : "
        "non disponible.\n"
    )

    return f"""
Tu es un ingénieur SRE senior spécialisé Spring Boot.
Tu aides un développeur débutant.

RÈGLE ABSOLUE :

Pour DESCRIPTION et CAUSE,
appuie chaque affirmation sur les informations
réellement présentes dans le log.

Si une information n'est pas déductible du log,
dis exactement :

"je ne peux pas le confirmer avec ce log seul"

FORMAT DE RÉPONSE OBLIGATOIRE,
texte brut :

DESCRIPTION:
1 à 2 phrases.

FONCTIONNEMENT:
L'application continue-t-elle à fonctionner ?
Explique brièvement.

CAUSE:
Cause la plus probable, sans inventer.

INDICES:
Cite les mots ou phrases exacts présents dans le log.

GRAVITE:
Un seul mot parmi :
Critique / Élevé / Moyen / Faible

Puis une phrase de justification.

DOMAINE:
Un seul mot parmi :

BASE_DE_DONNEES
SECURITE
PRODUCTION
APPLICATION
RESEAU
AUTRE

ACTION:
Action immédiate recommandée.

IMPORTANT POUR LE DOMAINE :

- BASE_DE_DONNEES :
  SQL, JDBC, PostgreSQL, MySQL, Hibernate,
  datasource, connexion DB, migration DB,
  timeout DB, pool DB.

- SECURITE :
  authentification, autorisation, certificat,
  TLS/SSL, vulnérabilité,
  accès non autorisé, sécurité.

- PRODUCTION :
  démarrage/arrêt de service,
  déploiement, port occupé,
  processus, disponibilité,
  panne en production.

- APPLICATION :
  erreur métier ou applicative Spring/Java
  qui ne relève pas principalement
  des domaines ci-dessus.

- RESEAU :
  DNS, connexion réseau, HTTP réseau,
  timeout réseau, socket, proxy,
  connectivité.

- AUTRE :
  impossible à classer avec certitude.

{reference_ligne}

Niveau du log :
{niveau}

Classe (logger) :
{logger}

Message :
{message}

Détails complémentaires :
{
    details_suivants[:2000]
    if details_suivants
    else "aucun"
}
"""


# ============================================================
# NETTOYAGE OLLAMA
# ============================================================

def nettoyer_markdown(texte):

    texte = re.sub(
        r"\*\*(.*?)\*\*",
        r"\1",
        texte,
    )

    texte = re.sub(
        r"^#+\s*",
        "",
        texte,
        flags=re.MULTILINE,
    )

    return texte.strip()


# ============================================================
# EXTRACTION SECTIONS
# ============================================================

def extraire_sections(texte):

    motif = re.compile(

        r"^\s*"
        r"("
        + "|".join(SECTIONS)
        + r")\s*:\s*$",

        re.IGNORECASE
        | re.MULTILINE,
    )

    matches = list(
        motif.finditer(texte)
    )

    resultat = {
        cle: ""
        for cle in SECTIONS
    }

    if not matches:

        resultat[
            "DESCRIPTION"
        ] = texte.strip()

        return resultat

    for index, match in enumerate(
        matches
    ):

        cle = (
            match.group(1)
            .upper()
        )

        debut = match.end()

        fin = (

            matches[index + 1].start()

            if index + 1
            < len(matches)

            else len(texte)
        )

        contenu = (
            texte[
                debut:fin
            ].strip()
        )

        if cle in resultat:

            resultat[cle] = contenu

    return resultat


# ============================================================
# NORMALISATION GRAVITE
# ============================================================

def normaliser_gravite(
    texte,
    niveau_log,
):

    texte_normalise = (
        texte or ""
    ).strip().casefold()

    for cle, valeur in (
        GRAVITE_CANONIQUE.items()
    ):

        if cle in texte_normalise:

            return valeur

    if niveau_log == "FATAL":

        return "Critique"

    if niveau_log == "ERROR":

        return "Moyen"

    if niveau_log == "WARN":

        return "Faible"

    return "Moyen"


# ============================================================
# NORMALISATION DOMAINE
# ============================================================

def normaliser_domaine(
    texte,
    niveau_log,
    logger,
    message,
):

    texte_normalise = (
        texte or ""
    ).strip().upper()

    for domaine in DOMAINES:

        if domaine in texte_normalise:

            return domaine

    contenu = (
        f"{logger} {message}"
    ).casefold()

    mots_db = [

        "jdbc",
        "database",
        "datasource",
        "postgres",
        "mysql",
        "hibernate",
        "sql",
        "hikari",
        "connection pool",
    ]

    mots_securite = [

        "authentication",
        "authorization",
        "unauthorized",
        "forbidden",
        "certificate",
        "tls",
        "ssl",
        "security",
    ]

    mots_reseau = [

        "dns",
        "socket",
        "connection refused",
        "timeout",
        "network",
        "connection reset",
    ]

    mots_prod = [

        "port ",
        "already in use",
        "failed to start",
        "application failed to start",
        "startup",
        "deployment",
        "process",
        "server failed",
    ]

    if any(
        mot in contenu
        for mot in mots_db
    ):

        return "BASE_DE_DONNEES"

    if any(
        mot in contenu
        for mot in mots_securite
    ):

        return "SECURITE"

    if any(
        mot in contenu
        for mot in mots_reseau
    ):

        return "RESEAU"

    if any(
        mot in contenu
        for mot in mots_prod
    ):

        return "PRODUCTION"

    return "APPLICATION"


# ============================================================
# GRAVITE -> URGENCE GLPI
# ============================================================

def gravite_vers_urgence(
    gravite,
):

    return {

        "Critique": 5,

        "Élevé": 4,

        "Moyen": 3,

        "Faible": 2,

    }.get(
        gravite,
       3,
    )


# ============================================================
# GRAVITE -> IMPACT GLPI
# ============================================================

def gravite_vers_impact(
    gravite,
):

    return {

        "Critique": 5,

        "Élevé": 4,

        "Moyen": 3,

        "Faible": 2,

    }.get(
        gravite,
        3,
    )


# ============================================================
# ANALYSE OLLAMA
# ============================================================

def analyser_avec_ollama(
    niveau,
    logger,
    message,
    details,
    numero_ligne,
):

    prompt = construire_prompt(

        niveau,
        logger,
        message,
        details,
        numero_ligne,
    )

    try:

        response = requests.post(

            URL_OLLAMA,

            json={

                "model":
                    NOM_MODELE,

                "prompt":
                    prompt,

                "stream":
                    False,
            },

            timeout=TIMEOUT_OLLAMA,
        )

        response.raise_for_status()

        texte_brut = (
            response.json()
            .get(
                "response",
                "",
            )
        )

        texte_brut = (
            nettoyer_markdown(
                texte_brut
            )
        )

        sections = (
            extraire_sections(
                texte_brut
            )
        )

        gravite = (
            normaliser_gravite(
                sections.get(
                    "GRAVITE",
                    "",
                ),
                niveau,
            )
        )

        domaine = (
            normaliser_domaine(

                sections.get(
                    "DOMAINE",
                    "",
                ),

                niveau,

                logger,

                message,
            )
        )

        sections[
            "GRAVITE"
        ] = gravite

        sections[
            "DOMAINE"
        ] = domaine

        reference = (

            f"ligne {numero_ligne} "
            f"du fichier de log"

            if numero_ligne
            is not None

            else
            "avant écriture "
            "dans le fichier de log"
        )

        if sections[
            "INDICES"
        ]:

            sections[
                "INDICES"
            ] += (
                f"\n(Référence : "
                f"{reference})"
            )

        else:

            sections[
                "INDICES"
            ] = (
                f"(Référence : "
                f"{reference})"
            )

        return sections

    except requests.exceptions.ConnectionError:

        return {

            "DESCRIPTION":
                "[Impossible de "
                "joindre Ollama]",

            "GRAVITE":
                normaliser_gravite(
                    "",
                    niveau,
                ),

            "DOMAINE":
                "APPLICATION",
        }

    except requests.exceptions.Timeout:

        return {

            "DESCRIPTION":
                f"[Timeout Ollama "
                f"après "
                f"{TIMEOUT_OLLAMA}s]",

            "GRAVITE":
                normaliser_gravite(
                    "",
                    niveau,
                ),

            "DOMAINE":
                "APPLICATION",
        }

    except requests.exceptions.RequestException as exc:

        return {

            "DESCRIPTION":
                f"[Erreur Ollama : "
                f"{exc}]",

            "GRAVITE":
                normaliser_gravite(
                    "",
                    niveau,
                ),

            "DOMAINE":
                "APPLICATION",
        }


# ============================================================
# AFFICHAGE ANALYSE
# ============================================================

def afficher_analyse(
    sections,
):

    for cle in SECTIONS:

        contenu = (
            sections.get(
                cle,
                "",
            ).strip()
        )

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

def chemin_rapport_du_jour():

    aujourd_hui = (
        datetime.now(
            FUSEAU_LOCAL
        ).strftime(
            "%Y-%m-%d"
        )
    )

    return (

        DOSSIER_PROJET
        / "logs"
        / (
            f"rapport_analyses_"
            f"{aujourd_hui}.log"
        )
    )


def enregistrer_rapport(
    entree,
):

    maintenant_local = (
        datetime.now(
            FUSEAU_LOCAL
        )
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

        encoding="utf-8",

    ) as fichier:

        fichier.write(

            json.dumps(

                entree_complete,

                ensure_ascii=False,
            )
            + "\n"
        )


# ============================================================
# FICHIER INCIDENT
# ============================================================

def souligner(titre):

    return (
        titre
        + "\n"
        + "-" * len(titre)
    )


# ============================================================
# FICHIER INCIDENT
# ============================================================

def creer_fichier_incident(
    entree,
    contexte_avant,
):
    """
    Création du fichier incident synthétique.

    Le fichier contient uniquement les informations utiles
    pour constituer la preuve de l'incident :

        - date / heure
        - application
        - niveau du log
        - numéro de ligne
        - contexte précédent
        - ligne brute ayant déclenché l'incident

    On NE met PAS dans ce fichier :

        - Détails / stack trace
        - APPLICATION FAILED TO START
        - Description:
        - Action:
        - le bloc stderr complet

    ATTENTION :
    entree["details"] reste conservé dans la mémoire du programme
    car il est toujours utilisé pour l'analyse Ollama.

    On ne fait donc que supprimer son écriture dans le fichier.
    """

    # --------------------------------------------------------
    # Création du dossier incidents
    # --------------------------------------------------------

    CHEMIN_INCIDENTS.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Nom du fichier incident
    # --------------------------------------------------------

    nom = (
        datetime.now(
            FUSEAU_LOCAL
        ).strftime(
            "incident_%Y-%m-%d_%H-%M-%S.log"
        )
    )

    chemin = (
        CHEMIN_INCIDENTS
        / nom
    )

    # --------------------------------------------------------
    # Écriture du fichier incident
    # --------------------------------------------------------

    with open(
        chemin,
        "w",
        encoding="utf-8",
    ) as fichier:

        # ----------------------------------------------------
        # Date / heure
        # ----------------------------------------------------

        fichier.write(
            f"Incident du "
            f"{formater_timestamp(entree['timestamp'])}"
            "\n\n"
        )

        # ----------------------------------------------------
        # Application
        # ----------------------------------------------------

        fichier.write(
            f"Application : "
            f"{APPLICATION_NAME}\n"
        )

        # ----------------------------------------------------
        # Niveau
        # ----------------------------------------------------

        fichier.write(
            f"Niveau    : "
            f"{entree['niveau']}\n"
        )

        # ----------------------------------------------------
        # Numéro de ligne
        # ----------------------------------------------------

        fichier.write(
            f"Ligne log : "
            f"{entree['numero_ligne']}\n\n"
        )

        # ----------------------------------------------------
        # Contexte avant l'incident
        # ----------------------------------------------------

        if contexte_avant:
            fichier.write(
                "".join(
                    contexte_avant
                )
            )

            fichier.write(
                "\n"
            )

        # ----------------------------------------------------
        # LIGNE BRUTE DE L'INCIDENT
        # ----------------------------------------------------
        #
        # C'est ici que nous nous arrêtons volontairement.
        #
        # IMPORTANT :
        # On ne fait PAS :
        #
        # if entree["details"]:
        #     fichier.write(entree["details"])
        #
        # Donc :
        #
        # APPLICATION FAILED TO START
        # Description:
        # Action:
        # etc.
        #
        # ne seront plus copiés dans le fichier incident.
        # ----------------------------------------------------

        fichier.write(
            entree["ligne_brute"]
            + "\n"
        )

    # --------------------------------------------------------
    # VERIFICATION IMPORTANTE
    # --------------------------------------------------------

    if not chemin.exists():
        raise RuntimeError(
            "Le fichier incident "
            "n'a pas été créé."
        )

    if chemin.stat().st_size == 0:
        raise RuntimeError(
            "Le fichier incident "
            "est vide."
        )

    print(
        f"Fichier incident confirmé : "
        f"{chemin}"
    )

    print(
        f"Taille du fichier : "
        f"{chemin.stat().st_size} octets"
    )

    return chemin

# ============================================================
# EMAIL ANALYSE
# ============================================================

def envoyer_email(
    sections,
    entree,
    fichier_incident,
):

    sujet = (

        f"AIOps : "
        f"{APPLICATION_NAME} "
        f"- Incident - "
        f"{sections.get('GRAVITE', 'Moyen')}"
    )

    message = EmailMessage()

    message["Subject"] = sujet

    message["From"] = (
        EMAIL_EXPEDITEUR
    )

    message["To"] = (
        EMAIL_DESTINATAIRE
    )

    corps = f"""
Un incident vient d'être détecté.

Application :
{APPLICATION_NAME}

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

Domaine :
{sections.get('DOMAINE', '(non disponible)')}

Action :
{sections.get('ACTION', '(non disponible)')}

Le fichier incident complet est joint à cet email.
"""

    message.set_content(
        corps
    )

    with open(
        fichier_incident,
        "rb",
    ) as fichier:

        message.add_attachment(

            fichier.read(),

            maintype="text",

            subtype="plain",

            filename=
                fichier_incident.name,
        )

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
    ) as smtp:

        smtp.login(
            EMAIL_EXPEDITEUR,
            EMAIL_MOT_DE_PASSE,
        )

        smtp.send_message(
            message
        )


# ============================================================
# GLPI - CREATION DU TICKET
# ============================================================

def creer_ticket_glpi(
    sections,
    entree,
    session_token,
    groupes_ids,
    utilisateurs_ids,
    categories_ids,
):

    description = (
        sections.get(
            "DESCRIPTION",
            "(non disponible)",
        ).strip()
    )

    fonctionnement = (
        sections.get(
            "FONCTIONNEMENT",
            "(non disponible)",
        ).strip()
    )

    cause = (
        sections.get(
            "CAUSE",
            "(non disponible)",
        ).strip()
    )

    indices = (
        sections.get(
            "INDICES",
            "(non disponible)",
        ).strip()
    )

    gravite = (
        sections.get(
            "GRAVITE",
            "Moyen",
        ).strip()
    )

    domaine = (
        sections.get(
            "DOMAINE",
            "APPLICATION",
        ).strip()
    )

    action = (
        sections.get(
            "ACTION",
            "(non disponible)",
        ).strip()
    )

    niveau = entree.get(
        "niveau",
        "INCONNU",
    )

    logger = entree.get(
        "logger",
        "(non disponible)",
    )

    message_log = entree.get(
        "message",
        "(non disponible)",
    )

    numero_ligne = entree.get(
        "numero_ligne",
        "(non disponible)",
    )

    timestamp = entree.get(
        "timestamp",
        "(non disponible)",
    )

    ligne_brute = entree.get(
        "ligne_brute",
        "(non disponible)",
    )

    urgence = (
        gravite_vers_urgence(
            gravite
        )
    )

    impact = (
        gravite_vers_impact(
            gravite
        )
    )

    categorie_id = (
        categories_ids.get(
            domaine
        )
    )

    groupe_id = (
        groupes_ids.get(
            domaine
        )
    )

    user_ids = (
        utilisateurs_ids.get(
            domaine,
            [],
        )
    )

    titre = (

        f"[AIOps]"
        f"[{APPLICATION_SHORT_NAME}] "
        f"[{domaine}] "
        f"[{niveau}] "
        f"{gravite}"
    )

    contenu_ticket = f"""
INCIDENT AIOps - {APPLICATION_NAME}

APPLICATION
{APPLICATION_NAME}

DOMAINE
{domaine}

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
{message_log}

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




Le fichier incident complet sera ajouté
comme pièce jointe au ticket GLPI.
"""

    # --------------------------------------------------------
    # CREATION DU TICKET UNIQUEMENT
    # --------------------------------------------------------

    payload_input = {

        "name":
            titre,

        "content":
            contenu_ticket,

        # 1 = Incident
        "type":
            1,

        "urgency":
            urgence,

        "impact":
            impact,
    }

    if categorie_id is not None:

        payload_input[
            "itilcategories_id"
        ] = categorie_id

    payload = {

        "input":
            payload_input,
    }

    print(
        "Création du ticket GLPI..."
    )

    response = requests.post(

        f"{GLPI_URL}"
        "/apirest.php/Ticket/",

        headers=glpi_headers(
            session_token
        ),

        json=payload,

        timeout=15,
    )

    response.raise_for_status()

    resultat = response.json()

    if "id" not in resultat:

        raise RuntimeError(

            "GLPI n'a pas retourné "
            f"l'ID du ticket : "
            f"{resultat}"
        )

    ticket_id = int(
        resultat["id"]
    )

    print(
        f"Ticket GLPI créé avec succès : "
        f"#{ticket_id}"
    )

    # IMPORTANT :
    #
    # On retourne immédiatement le ticket_id.
    #
    # L'affectation du groupe/utilisateur
    # ne doit jamais empêcher la suite du pipeline.

    return (
        ticket_id,
        groupe_id,
        user_ids,
    )


# ============================================================
# GLPI - AFFECTATION GROUPE
# ============================================================

def ajouter_groupe_ticket(
    session_token,
    ticket_id,
    groupe_id,
):

    if groupe_id is None:

        print(
            "Aucun groupe GLPI "
            "configuré pour ce domaine."
        )

        return False

    payload = {

        "input": {

            "tickets_id":
                ticket_id,

            "groups_id":
                groupe_id,

            # 2 = groupe assigné
            "type":
                2,

            "use_notification":
                1,
        }
    }

    print(
        f"Affectation du groupe "
        f"GLPI #{groupe_id}..."
    )

    response = requests.post(

        f"{GLPI_URL}"
        "/apirest.php/Group_Ticket/",

        headers=glpi_headers(
            session_token
        ),

        json=payload,

        timeout=10,
    )

    if response.status_code >= 400:

        texte = (
            response.text.lower()
        )

        if (
            "duplicate" in texte
            or "existe" in texte
            or "already" in texte
        ):

            print(
                "Le groupe était "
                "déjà affecté."
            )

            return True

        print(
            "ATTENTION : impossible "
            "d'affecter le groupe."
        )

        print(
            response.text
        )

        return False

    print(
        f"Groupe GLPI #{groupe_id} "
        f"affecté au ticket "
        f"#{ticket_id}."
    )

    return True


# ============================================================
# GLPI - AFFECTATION UTILISATEUR
# ============================================================

def ajouter_utilisateur_ticket(
    session_token,
    ticket_id,
    user_id,
):

    if user_id is None:

        return False

    payload = {

        "input": {

            "tickets_id":
                ticket_id,

            "users_id":
                user_id,

            # 2 = technicien assigné
            "type":
                2,

            "use_notification":
                1,
        }
    }

    print(
        f"Affectation de "
        f"l'utilisateur GLPI "
        f"#{user_id}..."
    )

    response = requests.post(

        f"{GLPI_URL}"
        "/apirest.php/Ticket_User/",

        headers=glpi_headers(
            session_token
        ),

        json=payload,

        timeout=10,
    )

    if response.status_code >= 400:

        texte = (
            response.text.lower()
        )

        if (
            "duplicate" in texte
            or "existe" in texte
            or "already" in texte
        ):

            print(
                f"L'utilisateur "
                f"#{user_id} était "
                "déjà affecté."
            )

            return True

        print(
            f"ATTENTION : impossible "
            f"d'affecter "
            f"l'utilisateur "
            f"#{user_id}."
        )

        print(
            response.text
        )

        return False

    print(
        f"Utilisateur GLPI "
        f"#{user_id} affecté au "
        f"ticket #{ticket_id}."
    )

    return True


# ============================================================
# GLPI - PIECE JOINTE
# ============================================================

def ajouter_piece_jointe_glpi(
    ticket_id,
    chemin_incident,
    session_token,
):

    # --------------------------------------------------------
    # 1. VERIFIER LE FICHIER LOCAL
    # --------------------------------------------------------

    if not chemin_incident.exists():

        raise FileNotFoundError(

            "Fichier incident "
            f"introuvable : "
            f"{chemin_incident}"
        )

    if (
        chemin_incident.stat()
        .st_size
        == 0
    ):

        raise RuntimeError(
            "Le fichier incident "
            "est vide."
        )

    nom_fichier = (
        chemin_incident.name
    )

    print(
        "======================================"
    )

    print(
        "AJOUT DE LA PIECE JOINTE GLPI"
    )

    print(
        f"Ticket : #{ticket_id}"
    )

    print(
        f"Fichier : {nom_fichier}"
    )

    print(
        f"Taille : "
        f"{chemin_incident.stat().st_size}"
        " octets"
    )

    print(
        "======================================"
    )

    # --------------------------------------------------------
    # 2. MANIFEST GLPI
    # --------------------------------------------------------

    upload_manifest = {

        "input": {

            "name":
                nom_fichier,

            "_filename":
                [nom_fichier],
        }
    }

    # --------------------------------------------------------
    # 3. UPLOAD DU FICHIER
    # --------------------------------------------------------

    with open(
        chemin_incident,
        "rb",
    ) as fichier:

        files = {

            "uploadManifest": (

                None,

                json.dumps(
                    upload_manifest
                ),

                "application/json",
            ),

            "filename[0]": (

                nom_fichier,

                fichier,

                "text/plain",
            ),
        }

        response = requests.post(

            f"{GLPI_URL}"
            "/apirest.php/Document/",

            headers={

                "Session-Token":
                    session_token,

                "App-Token":
                    GLPI_APP_TOKEN,
            },

            files=files,

            timeout=30,
        )

    response.raise_for_status()

    resultat = response.json()

    print(
        "Réponse upload GLPI :"
    )

    print(
        resultat
    )

    # --------------------------------------------------------
    # 4. VERIFIER QUE GLPI A BIEN ACCEPTE LE FICHIER
    # --------------------------------------------------------

    upload_result = (
        resultat.get(
            "upload_result",
            {},
        )
    )

    fichiers = (
        upload_result.get(
            "filename",
            [],
        )
    )

    if not fichiers:

        raise RuntimeError(

            "GLPI n'a pas retourné "
            "le fichier uploadé : "
            f"{resultat}"
        )

    fichier_resultat = (
        fichiers[0]
    )

    erreur = (
        fichier_resultat.get(
            "error"
        )
    )

    if erreur:

        raise RuntimeError(

            "GLPI a refusé le fichier : "
            f"{erreur}"
        )

    document_id = int(
        resultat["id"]
    )

    print(
        f"Document GLPI créé : "
        f"#{document_id}"
    )

    # --------------------------------------------------------
    # 5. ASSOCIATION DOCUMENT -> TICKET
    # --------------------------------------------------------

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
        f"#{document_id} au ticket "
        f"#{ticket_id}..."
    )

    response_link = requests.post(

        f"{GLPI_URL}"
        "/apirest.php/Document_Item/",

        headers=glpi_headers(
            session_token
        ),

        json=payload_link,

        timeout=10,
    )

    response_link.raise_for_status()

    association = (
        response_link.json()
    )

    print(
        "Association GLPI réussie :"
    )

    print(
        association
    )

    print(
        f"Pièce jointe associée "
        f"au ticket #{ticket_id}."
    )

    return document_id


# ============================================================
# EMAIL NOTIFICATION TICKET GLPI
# ============================================================

def envoyer_email_notification_ticket(
    ticket_id,
    fichier_incident,
    piece_jointe_ok=True,
):

    sujet = (

        f"AIOps : "
        f"[{APPLICATION_SHORT_NAME}] "
        f"Ticket GLPI #{ticket_id} créé"
    )

    message = EmailMessage()

    message["Subject"] = sujet

    message["From"] = (
        EMAIL_EXPEDITEUR
    )

    message["To"] = (
        EMAIL_DESTINATAIRE
    )

    if piece_jointe_ok:

        statut = (
            "Le fichier incident a "
            "également été ajouté au "
            "ticket GLPI comme "
            "pièce jointe."
        )

    else:

        statut = (
            "ATTENTION : le ticket "
            "a été créé, mais la "
            "pièce jointe n'a pas "
            "pu être ajoutée au "
            "ticket GLPI."
        )

    corps = f"""
Bonjour,

Le système AIOps a créé automatiquement
un ticket GLPI à la suite de la détection
d'un incident.

Application :
{APPLICATION_NAME}

Ticket GLPI :
#{ticket_id}

Statut :
Ticket créé avec succès.

{statut}

Le fichier incident est également joint
à cet email.

Ceci est une notification automatique
du système AIOps.
"""

    message.set_content(
        corps
    )

    with open(
        fichier_incident,
        "rb",
    ) as fichier:

        message.add_attachment(

            fichier.read(),

            maintype="text",

            subtype="plain",

            filename=
                fichier_incident.name,
        )

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
    ) as smtp:

        smtp.login(

            EMAIL_EXPEDITEUR,

            EMAIL_MOT_DE_PASSE,
        )

        smtp.send_message(
            message
        )


# ============================================================
# TRAITEMENT D'UN INCIDENT
# ============================================================

def traiter_entree(
    entree,
    glpi_session,
    glpi_config,
):

    niveau = entree[
        "niveau"
    ]

    if niveau not in (
        NIVEAUX_A_ANALYSER
    ):

        return

    timestamp_affiche = (
        formater_timestamp(
            entree[
                "timestamp"
            ]
        )
    )

    print(
        f"[{timestamp_affiche}] "
        f"{niveau} — "
        f"{entree['logger']} "
        f"(ligne "
        f"{entree['numero_ligne']})"
    )

    print(
        f"   {entree['message']}\n"
    )

    # ========================================================
    # 1. ANALYSE OLLAMA
    # ========================================================

    print(
        "1/6 - Analyse Ollama..."
    )

    debut = datetime.now(
        timezone.utc
    )

    sections = (
        analyser_avec_ollama(

            niveau,

            entree["logger"],

            entree["message"],

            entree["details"],

            entree["numero_ligne"],
        )
    )

    duree = (

        datetime.now(
            timezone.utc
        )
        - debut
    ).total_seconds()

    print(
        f"Analyse terminée "
        f"(durée : {duree:.1f}s)"
    )

    afficher_analyse(
        sections
    )

    # ========================================================
    # 2. CREATION FICHIER INCIDENT
    # ========================================================

    print(
        "2/6 - Création du "
        "fichier incident..."
    )

    try:

        chemin_incident = (
            creer_fichier_incident(

                entree,

                entree[
                    "contexte_avant"
                ],
            )
        )

        print(
            "Fichier incident prêt."
        )

    except Exception as exc:

        print(
            "ERREUR : impossible "
            "de créer le fichier "
            f"incident : {exc}"
        )

        return

    # ========================================================
    # 3. EMAIL ANALYSE
    # ========================================================

    print(
        "3/6 - Envoi email analyse..."
    )

    try:

        envoyer_email(

            sections,

            entree,

            chemin_incident,
        )

        print(
            "Email de l'analyse "
            "envoyé avec succès."
        )

    except Exception as exc:

        print(
            "Échec de l'envoi "
            f"de l'email d'analyse : "
            f"{exc}"
        )

    # ========================================================
    # 4. CREATION DU TICKET GLPI
    # ========================================================

    print(
        "4/6 - Création du "
        "ticket GLPI..."
    )

    ticket_id = None

    groupe_id = None

    user_ids = []

    piece_jointe_ok = False

    document_id = None

    try:

        (
            ticket_id,
            groupe_id,
            user_ids,
        ) = creer_ticket_glpi(

            sections,

            entree,

            glpi_session,

            glpi_config[0],

            glpi_config[1],

            glpi_config[2],
        )

    except Exception as exc:

        print(
            "Échec de création "
            f"du ticket GLPI : {exc}"
        )

    # ========================================================
    # 5. PIECE JOINTE
    # ========================================================

    #
    # IMPORTANT :
    #
    # La pièce jointe est maintenant traitée
    # AVANT les affectations groupe/utilisateurs.
    #
    # Ainsi une erreur de routage ne peut pas
    # empêcher l'ajout du fichier incident.
    #

    if ticket_id is not None:

        print(
            "5/6 - Ajout de la "
            "pièce jointe..."
        )

        try:

            document_id = (
                ajouter_piece_jointe_glpi(

                    ticket_id,

                    chemin_incident,

                    glpi_session,
                )
            )

            piece_jointe_ok = True

            print(
                "SUCCÈS : fichier incident "
                "ajouté au ticket GLPI."
            )

        except Exception as exc:

            print(
                "ÉCHEC : ajout de la "
                "pièce jointe : "
                f"{exc}"
            )

    # ========================================================
    # 6. ROUTAGE GROUPE + UTILISATEURS
    # ========================================================

    if ticket_id is not None:

        print(
            "6/6 - Affectation "
            "groupe/utilisateurs..."
        )

        #
        # Groupe
        #

        try:

            ajouter_groupe_ticket(

                glpi_session,

                ticket_id,

                groupe_id,
            )

        except Exception as exc:

            print(
                "ATTENTION : erreur "
                "d'affectation du groupe : "
                f"{exc}"
            )

        #
        # Utilisateurs
        #

        for user_id in user_ids:

            try:

                ajouter_utilisateur_ticket(

                    glpi_session,

                    ticket_id,

                    user_id,
                )

            except Exception as exc:

                print(
                    "ATTENTION : erreur "
                    "d'affectation de "
                    f"l'utilisateur "
                    f"#{user_id} : {exc}"
                )

    # ========================================================
    # NOTIFICATION EMAIL GLPI
    # ========================================================

    if ticket_id is not None:

        try:

            envoyer_email_notification_ticket(

                ticket_id,

                chemin_incident,

                piece_jointe_ok,
            )

            print(
                f"Email de notification "
                f"du ticket #{ticket_id} "
                "envoyé."
            )

        except Exception as exc:

            print(
                "Échec de l'envoi "
                "de la notification GLPI : "
                f"{exc}"
            )

    # ========================================================
    # RAPPORT
    # ========================================================

    enregistrer_rapport({

        "application":
            APPLICATION_NAME,

        "timestamp_evenement":
            entree[
                "timestamp"
            ],

        "timestamp_evenement_lisible":
            timestamp_affiche,

        "numero_ligne":
            entree[
                "numero_ligne"
            ],

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
            entree[
                "ligne_brute"
            ],

        "analyse":
            sections,

        "preuve":
            str(
                chemin_incident
            ),

        "glpi_ticket_id":
            ticket_id,

        "glpi_document_id":
            document_id,

        "glpi_piece_jointe":
            piece_jointe_ok,
    })

    print(
        "\n======================================"
    )

    print(
        "FIN DU TRAITEMENT"
    )

    print(
        f"Ticket GLPI : "
        f"{ticket_id}"
    )

    print(
        f"Document GLPI : "
        f"{document_id}"
    )

    print(
        f"Pièce jointe : "
        f"{'OUI' if piece_jointe_ok else 'NON'}"
    )

    print(
        "======================================\n"
    )


# ============================================================
# CRASH DEMARRAGE
# ============================================================

def analyser_crash_demarrage(
    glpi_session,
    glpi_config,
):

    contenu_stderr = (
        CHEMIN_STDERR.read_text(

            encoding="utf-8",

            errors="replace",
        ).strip()
    )

    if not contenu_stderr:

        print(
            "Le processus s'est "
            "arrêté tôt, mais stderr "
            "est vide."
        )

        return

    print(
        "L'application s'est "
        "arrêtée pendant le "
        "démarrage."
    )

    print(
        "Analyse de stderr..."
    )

    sections = (
        analyser_avec_ollama(

            "ERROR",

            "démarrage (stderr)",

            contenu_stderr[:1500],

            "",

            None,
        )
    )

    afficher_analyse(
        sections
    )

    entree = {

        "timestamp":
            datetime.now(
                FUSEAU_LOCAL
            ).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3],

        "niveau":
            "ERROR",

        "logger":
            "démarrage "
            "(stderr, avant Log4j2)",

        "message":
            contenu_stderr[:500],

        "details":
            contenu_stderr,

        "numero_ligne":
            None,

        "contexte_avant":
            [],

        "ligne_brute":
            contenu_stderr[:500],
    }

    traiter_entree(

        entree,

        glpi_session,

        glpi_config,
    )


# ============================================================
# SURVEILLANCE TEMPS REEL
# ============================================================

def surveiller_en_temps_reel(
    position_depart,
    numero_ligne_initial,
    glpi_session,
    glpi_config,
):

    print(
        f"Surveillance en temps réel "
        f"de {CHEMIN_LOG}"
    )

    print(
        "(Ctrl+C pour arrêter)"
    )

    print(
        "Aucune erreur détectée "
        "pour l'instant — "
        "tout va bien.\n"
    )

    while not CHEMIN_LOG.exists():

        time.sleep(0.5)

    contexte = deque(
        maxlen=LIGNES_DE_CONTEXTE
    )

    with open(

        CHEMIN_LOG,

        encoding="utf-8",

    ) as fichier:

        fichier.seek(
            position_depart
        )

        numero_ligne = (
            numero_ligne_initial
        )

        entree_courante = None

        cycles_vides_consecutifs = 0

        SEUIL_SILENCE = 3

        while True:

            ligne = (
                fichier.readline()
            )

            if not ligne:

                cycles_vides_consecutifs += 1

                if (

                    entree_courante

                    and
                    cycles_vides_consecutifs
                    >= SEUIL_SILENCE

                ):

                    traiter_entree(

                        entree_courante,

                        glpi_session,

                        glpi_config,
                    )

                    entree_courante = None

                    cycles_vides_consecutifs = 0

                time.sleep(0.5)

                continue

            cycles_vides_consecutifs = 0

            numero_ligne += 1

            ligne_brute = (

                ligne

                if ligne.endswith(
                    "\n"
                )

                else
                ligne + "\n"
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

                        entree_courante,

                        glpi_session,

                        glpi_config,
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
                        list(
                            contexte
                        ),

                    "ligne_brute":
                        ligne_nettoyee,
                }

            elif entree_courante:

                entree_courante[
                    "details"
                ] += (

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

    try:

        # ----------------------------------------------------
        # 1. Vérification
        # ----------------------------------------------------

        verifier_configuration()

        # ----------------------------------------------------
        # 2. Build
        # ----------------------------------------------------

        if not construire_projet():

            sys.exit(1)

        # ----------------------------------------------------
        # 3. Connexion GLPI
        # ----------------------------------------------------

        print(
            "Connexion GLPI..."
        )

        glpi_session = (
            glpi_init_session()
        )

        print(
            "Session GLPI créée "
            "avec succès."
        )

        # ----------------------------------------------------
        # 4. Résolution configuration
        # ----------------------------------------------------

        glpi_config = (
            glpi_resoudre_configuration(
                glpi_session
            )
        )

        (
            groupes_ids,
            utilisateurs_ids,
            categories_ids,
        ) = glpi_config

        print(
            "\nConfiguration de "
            "routage GLPI :"
        )

        for domaine in DOMAINES:

            print(

                f"  {domaine}: "

                f"groupe="
                f"{groupes_ids.get(domaine)}, "

                f"users="
                f"{utilisateurs_ids.get(domaine)}, "

                f"categorie="
                f"{categories_ids.get(domaine)}"
            )

        print()

        # ----------------------------------------------------
        # 5. Position initiale du log
        # ----------------------------------------------------

        (
            position_avant_lancement,
            lignes_avant_lancement,
        ) = (
            obtenir_position_et_nombre_lignes()
        )

        # ----------------------------------------------------
        # 6. Lancement application
        # ----------------------------------------------------

        (
            processus_app,
            fichier_stderr,
        ) = (
            lancer_application()
        )

        # ----------------------------------------------------
        # ARRET PROPRE
        # ----------------------------------------------------

        def arret_propre(
            signum,
            frame,
        ):

            print(
                "\nArrêt demandé — "
                "fermeture de "
                "l'application..."
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
            arret_propre,
        )

        # ----------------------------------------------------
        # 7. Attente démarrage
        # ----------------------------------------------------

        print(
            "Attente du démarrage "
            "de l'application "
            "(10s)...\n"
        )

        time.sleep(10)

        # ----------------------------------------------------
        # 8. Vérification crash
        # ----------------------------------------------------

        if (
            processus_app.poll()
            is not None
        ):

            fichier_stderr.close()

            analyser_crash_demarrage(

                glpi_session,

                glpi_config,
            )

            print(
                "L'application n'a "
                "pas pu démarrer. "
                "Fin du script."
            )

            sys.exit(1)

        # ----------------------------------------------------
        # 9. Surveillance
        # ----------------------------------------------------

        try:

            surveiller_en_temps_reel(

                position_avant_lancement,

                lignes_avant_lancement,

                glpi_session,

                glpi_config,
            )

        except KeyboardInterrupt:

            arret_propre(
                None,
                None,
            )

    except Exception as exc:

        print(
            "\nERREUR FATALE "
            f"DU SCRIPT : {exc}"
        )

        sys.exit(1)

"""
 AFFECTATION AUTOMATIQUE

Domaine :
{domaine}

Urgence GLPI :
{urgence}

Impact GLPI :
{impact}

Catégorie GLPI :
{categorie_id if categorie_id else 'non configurée'}

Groupe GLPI :
{groupe_id if groupe_id else 'non configuré'}

Utilisateurs GLPI :
{', '.join(map(str, user_ids)) if user_ids else 'aucun'} 
"""
