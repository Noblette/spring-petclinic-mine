"""
analyseur_logs.py

Script d'analyse automatique de logs Spring Boot (format JSON/ECS),
avec appel conditionnel à Ollama (LLM local) uniquement sur les erreurs.

Changement important par rapport aux versions précédentes :
  On n'utilise plus la commande terminal "ollama run ..." (via subprocess),
  car elle produit des codes de contrôle ANSI illisibles une fois capturés
  par un script. On utilise à la place l'API HTTP locale d'Ollama
  (http://localhost:11434), qui renvoie une réponse JSON propre,
  sans aucun artefact d'affichage.

  Nécessite le paquet "requests" :
      pip install requests --break-system-packages
"""

import json
import re
import requests
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


NOM_MODELE = "llama3.2:3b"
FUSEAU_LOCAL = ZoneInfo("Indian/Antananarivo")
FICHIER_RAPPORT = "logs/rapport_analyses.log"
TIMEOUT_OLLAMA = 300

# URL de l'API locale d'Ollama (démarrée automatiquement par "ollama serve"
# ou par le service système si Ollama est installé normalement).
URL_OLLAMA = "http://localhost:11434/api/generate"


# ----------------------------------------------------------------------
# Nettoyage du texte renvoyé par le modèle : enlève le formatage Markdown
# (les ** de gras, les # de titres...) pour un texte brut plus lisible
# dans un fichier de log.
# ----------------------------------------------------------------------
def nettoyer_markdown(texte: str) -> str:
    texte = re.sub(r"\*\*(.+?)\*\*", r"\1", texte)  # **gras** -> gras
    texte = re.sub(r"^#+\s*", "", texte, flags=re.MULTILINE)  # # Titre -> Titre
    return texte.strip()


# ----------------------------------------------------------------------
# Conversion de timestamp (inchangé par rapport à la version précédente)
# ----------------------------------------------------------------------
def formater_timestamp(timestamp_iso: str) -> str:
    if timestamp_iso == "inconnu":
        return "inconnu"
    try:
        ts_propre = timestamp_iso.replace("Z", "+00:00")
        if "." in ts_propre:
            partie_date, reste = ts_propre.split(".")
            decimales, offset = reste[:6], reste[6:]
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
        return timestamp_iso


def niveau_de_gravite(entry: dict) -> str:
    return entry.get("log", {}).get("level", "")


# ----------------------------------------------------------------------
# Appel à Ollama via son API HTTP locale (au lieu du terminal)
# ----------------------------------------------------------------------
def analyser_avec_ollama(entry: dict) -> str:
    erreur = entry.get("error", {})
    message = entry.get("message", "")

    prompt = f"""Tu es un expert Spring Boot. Analyse ce log JSON (ECS).

IMPORTANT : appuie chaque affirmation sur une citation exacte d'un champ
du JSON fourni. Si une information n'est pas déductible du log, dis
"je ne peux pas le confirmer avec ce log seul" plutôt que de deviner.
N'utilise PAS de formatage Markdown (pas de **, pas de #) : réponds en
texte brut simple.

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
        reponse = requests.post(
            URL_OLLAMA,
            json={
                "model": NOM_MODELE,
                "prompt": prompt,
                "stream": False,  # on veut la réponse complète d'un coup,
                                  # pas un flux token par token
            },
            timeout=TIMEOUT_OLLAMA,
        )
        reponse.raise_for_status()
        texte_brut = reponse.json().get("response", "")
        return nettoyer_markdown(texte_brut)

    except requests.exceptions.ConnectionError:
        return (
            "[Impossible de joindre Ollama sur http://localhost:11434 — "
            "vérifie qu'il tourne avec : ollama serve]"
        )
    except requests.exceptions.Timeout:
        return f"[Timeout après {TIMEOUT_OLLAMA}s — Ollama n'a pas répondu à temps]"
    except requests.exceptions.RequestException as e:
        return f"[Erreur lors de l'appel à Ollama] {e}"


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

                heure_debut = datetime.now(timezone.utc)
                analyse = analyser_avec_ollama(entry)
                duree = (datetime.now(timezone.utc) - heure_debut).total_seconds()

                print(f"---- Analyse Ollama (durée : {duree:.1f}s) ----")
                print(analyse)
                print("-------------------------\n")

                enregistrer_rapport(timestamp_original, "ERROR", message, analyse)


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