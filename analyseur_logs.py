"""
analyseur_logs.py

Script d'analyse automatique de logs Spring Boot (format JSON/ECS),
avec appel conditionnel à Ollama (LLM local) uniquement sur les erreurs.

Principe :
  1. On lit le fichier de log ligne par ligne (chaque ligne = un objet JSON)
  2. On regarde le niveau (INFO / WARN / ERROR) de chaque ligne
  3. Selon le niveau, on décide de l'action :
       - INFO  -> on ignore, rien à faire
       - WARN  -> on note dans la console, pas d'appel au LLM
       - ERROR -> on appelle Ollama pour obtenir une analyse
  4. Chaque événement traité est horodaté :
       - en UTC (standard international, présent dans le log d'origine,
         reconnaissable au "Z" final -> Zulu time = UTC)
       - en heure locale (Indian/Antananarivo, UTC+3) pour une lecture
         plus intuitive au quotidien
     Les deux sont affichés en parallèle, rien n'est perdu.
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


# Nom exact du modèle installé localement.
# Vérifie le tien avec : ollama list
NOM_MODELE = "llama3.2:3b"

# Fuseau horaire local (Madagascar = UTC+3, pas de changement d'heure saisonnier)
FUSEAU_LOCAL = ZoneInfo("Indian/Antananarivo")

# Fichier où on garde une trace de toutes les analyses effectuées.
FICHIER_RAPPORT = "logs/rapport_analyses.log"

# Temps maximum accordé à Ollama pour répondre (en secondes).
# Augmenté à 300s (5 min) car le premier chargement du modèle en mémoire
# peut être lent selon les ressources de la machine.
TIMEOUT_OLLAMA = 300


# ----------------------------------------------------------------------
# Fonction utilitaire : convertit un timestamp ISO (UTC, avec "Z")
# en un texte lisible affichant à la fois UTC et heure locale.
# ----------------------------------------------------------------------
def formater_timestamp(timestamp_iso: str) -> str:
    """
    Prend un timestamp du type '2026-07-15T08:10:47.705720417Z'
    (le 'Z' signifie UTC, aussi appelé 'Zulu time') et retourne une
    chaîne affichant l'heure UTC ET l'heure locale de Madagascar.
    """
    if timestamp_iso == "inconnu":
        return "inconnu"

    try:
        # Python ne comprend pas nativement le "Z" -> on le remplace
        # par "+00:00", équivalent explicite pour UTC.
        ts_propre = timestamp_iso.replace("Z", "+00:00")

        # Les timestamps Java ont parfois des nanosecondes (9 chiffres),
        # alors que Python n'accepte que des microsecondes (6 chiffres).
        # On tronque si besoin pour éviter une erreur de parsing.
        if "." in ts_propre:
            partie_date, reste = ts_propre.split(".")
            decimales, offset = reste[:6], reste[6:]
            # on retrouve le "+00:00" original s'il a été coupé
            if not offset.startswith(("+", "-")):
                offset = reste[9:] if len(reste) > 9 else "+00:00"
            ts_propre = f"{partie_date}.{decimales}{offset}"

        dt_utc = datetime.fromisoformat(ts_propre)
        dt_local = dt_utc.astimezone(FUSEAU_LOCAL)

        return (
            f"{dt_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC "
            f"(= {dt_local.strftime('%Y-%m-%d %H:%M:%S')} heure Madagascar)"
        )
    except (ValueError, IndexError):
        # Si le format est inattendu, on retourne la valeur brute
        # plutôt que de faire planter tout le script pour un détail
        # d'affichage.
        return timestamp_iso


# ----------------------------------------------------------------------
# 1. Fonction qui décide de la gravité d'une ligne de log
# ----------------------------------------------------------------------
def niveau_de_gravite(entry: dict) -> str:
    return entry.get("log", {}).get("level", "")


# ----------------------------------------------------------------------
# 2. Fonction qui construit le prompt et appelle Ollama
# ----------------------------------------------------------------------
def analyser_avec_ollama(entry: dict) -> str:
    erreur = entry.get("error", {})
    message = entry.get("message", "")

    prompt = f"""Tu es un expert Spring Boot. Analyse ce log JSON (ECS).

IMPORTANT : appuie chaque affirmation sur une citation exacte d'un champ
du JSON fourni. Si une information n'est pas déductible du log, dis
"je ne peux pas le confirmer avec ce log seul" plutôt que de deviner.

1. Que s'est-il passé exactement ?
2. Quelle ligne de code est responsable ? (cite error.stack_trace)
3. Le message contient-il un indice sur l'intention du code
   (ex: mots comme "Expected", "test", "demo") ? Si oui, cite-le.
4. Avant de répondre à ce point, relis ta réponse au point 3.
   Si le comportement semble intentionnel/pédagogique, ne parle PAS
   de "bug" ici. Ne recommande une correction que si un vrai
   dysfonctionnement est confirmé par les données du log.

Message : {message}
Type d'erreur : {erreur.get("type", "inconnu")}
Message d'erreur : {erreur.get("message", "inconnu")}
"""

    try:
        resultat = subprocess.run(
            ["ollama", "run", NOM_MODELE, prompt],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_OLLAMA,
        )
    except subprocess.TimeoutExpired:
        return f"[Timeout après {TIMEOUT_OLLAMA}s — Ollama n'a pas répondu à temps]"

    if resultat.returncode != 0:
        return f"[Erreur lors de l'appel à Ollama] {resultat.stderr}"

    return resultat.stdout


# ----------------------------------------------------------------------
# 3. Fonction qui écrit une trace horodatée dans le fichier de rapport
# ----------------------------------------------------------------------
def enregistrer_rapport(timestamp_original: str, niveau: str, message: str, analyse: str = ""):
    timestamp_analyse = datetime.now(timezone.utc).isoformat()

    ligne_rapport = {
        "timestamp_evenement_utc": timestamp_original,
        "timestamp_evenement_lisible": formater_timestamp(timestamp_original),
        "timestamp_analyse_utc": timestamp_analyse,
        "niveau": niveau,
        "message": message,
        "analyse_llm": analyse,
    }

    Path("logs").mkdir(exist_ok=True)
    with open(FICHIER_RAPPORT, "a", encoding="utf-8") as f:
        f.write(json.dumps(ligne_rapport, ensure_ascii=False) + "\n")


# ----------------------------------------------------------------------
# 4. Fonction principale : lit le fichier et applique la logique
# ----------------------------------------------------------------------
def analyser_fichier_log(chemin_fichier: str):
    chemin = Path(chemin_fichier)

    if not chemin.exists():
        print(f"❌ Fichier introuvable : {chemin_fichier}")
        return

    with open(chemin, encoding="utf-8") as f:
        for numero_ligne, ligne in enumerate(f, start=1):
            ligne = ligne.strip()
            if not ligne:
                continue

            try:
                entry = json.loads(ligne)
            except json.JSONDecodeError:
                continue

            niveau = niveau_de_gravite(entry)
            timestamp_original = entry.get("@timestamp", "inconnu")
            timestamp_affiche = formater_timestamp(timestamp_original)
            message = entry.get("message", "")

            if niveau == "INFO":
                continue

            elif niveau == "WARN":
                print(f"⚠️  [{timestamp_affiche}] [ligne {numero_ligne}] WARN : {message}")
                enregistrer_rapport(timestamp_original, "WARN", message)

            elif niveau == "ERROR":
                print(f"🔴 [{timestamp_affiche}] [ligne {numero_ligne}] ERROR détectée, analyse en cours...")
                print(f"   Message brut : {message}\n")

                heure_debut_analyse = datetime.now(timezone.utc)
                analyse = analyser_avec_ollama(entry)
                heure_fin_analyse = datetime.now(timezone.utc)
                duree = (heure_fin_analyse - heure_debut_analyse).total_seconds()

                print(f"---- Analyse Ollama (durée : {duree:.1f}s) ----")
                print(analyse)
                print("-------------------------\n")

                enregistrer_rapport(timestamp_original, "ERROR", message, analyse)


# ----------------------------------------------------------------------
# Point d'entrée du script
# ----------------------------------------------------------------------
if __name__ == "__main__":
    CHEMIN_LOG = "logs/petclinic.log"

    maintenant_utc = datetime.now(timezone.utc)
    maintenant_local = maintenant_utc.astimezone(FUSEAU_LOCAL)
    print(
        f"=== Démarrage de l'analyse : "
        f"{maintenant_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC "
        f"(= {maintenant_local.strftime('%Y-%m-%d %H:%M:%S')} heure Madagascar) ===\n"
    )

    analyser_fichier_log(CHEMIN_LOG)

    print(f"\n=== Fin de l'analyse ===")
    print(f"Rapport complet enregistré dans : {FICHIER_RAPPORT}")