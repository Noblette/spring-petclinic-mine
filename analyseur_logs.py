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
"""

import json
import subprocess
from pathlib import Path


# ----------------------------------------------------------------------
# 1. Fonction qui décide de la gravité d'une ligne de log
# ----------------------------------------------------------------------
def niveau_de_gravite(entry: dict) -> str:
    """
    Extrait le niveau de log (INFO / WARN / ERROR) d'une entrée JSON.
    Retourne une chaîne vide si le champ est introuvable (log mal formé).
    """
    return entry.get("log", {}).get("level", "")


# ----------------------------------------------------------------------
# 2. Fonction qui construit le prompt et appelle Ollama
#    (SEULEMENT appelée pour les vraies erreurs)
# ----------------------------------------------------------------------
def analyser_avec_ollama(entry: dict) -> str:
    """
    Envoie le contenu de l'erreur à Ollama (modèle llama3 en local)
    et retourne la réponse textuelle du modèle.
    """
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

    resultat = subprocess.run(
        ["ollama", "run", "llama3", prompt],
        capture_output=True,
        text=True,
        timeout=120,  # évite un blocage infini si Ollama ne répond pas
    )

    if resultat.returncode != 0:
        return f"[Erreur lors de l'appel à Ollama] {resultat.stderr}"

    return resultat.stdout


# ----------------------------------------------------------------------
# 3. Fonction principale : lit le fichier et applique la logique
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
                continue  # ignore les lignes vides

            try:
                entry = json.loads(ligne)
            except json.JSONDecodeError:
                # Certaines lignes peuvent ne pas être du JSON valide
                # (ex: lignes de démarrage, stack traces multi-lignes mal
                # capturées) -> on les ignore proprement plutôt que de planter
                continue

            niveau = niveau_de_gravite(entry)

            if niveau == "INFO":
                continue  # rien à faire, on ignore volontairement

            elif niveau == "WARN":
                print(f"⚠️  [ligne {numero_ligne}] WARN : {entry.get('message', '')}")

            elif niveau == "ERROR":
                print(f"🔴 [ligne {numero_ligne}] ERROR détectée, analyse en cours...")
                print(f"   Message brut : {entry.get('message', '')}\n")

                analyse = analyser_avec_ollama(entry)

                print("---- Analyse Ollama ----")
                print(analyse)
                print("-------------------------\n")


# ----------------------------------------------------------------------
# Point d'entrée du script
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Adapte ce chemin à l'emplacement réel de ton fichier de log
    CHEMIN_LOG = "logs/petclinic.log"
    analyser_fichier_log(CHEMIN_LOG)
