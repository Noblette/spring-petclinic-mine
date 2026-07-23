"""
analyseur_logs.py

Script d'analyse automatique de logs Spring Boot (format JSON/ECS),
avec appel conditionnel à Ollama (LLM local) uniquement sur les erreurs.

Fonctionne sur N'IMPORTE QUELLE application Spring Boot, à condition
qu'elle ait activé le format de log structuré ECS
(logging.structured.format.file=ecs dans application.properties).
Rien dans ce script n'est spécifique à PetClinic : il ne lit que des
champs génériques du standard ECS (log.level, message, error.*).

Utilise l'API HTTP locale d'Ollama (http://localhost:11434) plutôt que
la commande terminal, pour éviter les artefacts d'affichage (codes ANSI).

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
URL_OLLAMA = "http://localhost:11434/api/generate"


def nettoyer_markdown(texte: str) -> str:
    texte = re.sub(r"\*\*(.+?)\*\*", r"\1", texte)
    texte = re.sub(r"^#+\s*", "", texte, flags=re.MULTILINE)
    return texte.strip()


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


def analyser_avec_ollama(entry: dict) -> str:
    erreur = entry.get("error", {})
    message = entry.get("message", "")
    stack_trace = erreur.get("stack_trace", "")
    stack_trace_resume = stack_trace[:1500] if stack_trace else "non disponible"

    prompt = f"""Tu es un expert Spring Boot. Analyse ce log JSON (ECS).

IMPORTANT : appuie chaque affirmation sur une citation exacte d'un champ
du JSON fourni. Si une information n'est pas déductible du log, dis
"je ne peux pas le confirmer avec ce log seul" plutôt que de deviner.
N'utilise PAS de formatage Markdown (pas de **, pas de #) : réponds en
texte brut simple.

1. Que s'est-il passé exactement ?
2. Quelle ligne de code est responsable ? (cite la première ligne du
   stack_trace ci-dessous, qui indique généralement la classe et le
   numéro de ligne à l'origine de l'erreur ; si stack_trace est "non
   disponible", dis-le clairement)
3. Le message contient-il un indice sur l'intention du code
   (ex: mots comme "Expected", "test", "demo") ? Si oui, cite-le.
4. Avant de répondre à ce point, relis ta réponse au point 3.
   Si le comportement semble intentionnel/pédagogique, ne parle PAS
   de "bug" ici. Ne recommande une correction que si un vrai
   dysfonctionnement est confirmé par les données du log.

Message : {message}
Type d'erreur : {erreur.get("type", "inconnu")}
Message d'erreur : {erreur.get("message", "inconnu")}
Stack trace (premières lignes) : {stack_trace_resume}
"""

    try:
        reponse = requests.post(
            URL_OLLAMA,
            json={"model": NOM_MODELE, "prompt": prompt, "stream": False},
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


def analyser_fichier_log(chemin_fichier: str) -> dict:
    """
    Lit le fichier de log et retourne un compteur des événements trouvés,
    pour permettre un résumé clair à la fin (au lieu de laisser
    l'utilisateur deviner ce qui s'est passé en lisant le rapport brut).
    """
    compteurs = {"info": 0, "warn": 0, "error": 0, "lignes_ignorees": 0}

    chemin = Path(chemin_fichier)
    if not chemin.exists():
        print(f"❌ Fichier introuvable : {chemin_fichier}")
        return compteurs

    with open(chemin, encoding="utf-8") as f:
        for numero_ligne, ligne in enumerate(f, start=1):
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                entry = json.loads(ligne)
            except json.JSONDecodeError:
                compteurs["lignes_ignorees"] += 1
                continue

            niveau = niveau_de_gravite(entry)
            timestamp_original = entry.get("@timestamp", "inconnu")
            timestamp_affiche = formater_timestamp(timestamp_original)
            message = entry.get("message", "")

            if niveau == "INFO":
                compteurs["info"] += 1
                continue

            elif niveau == "WARN":
                compteurs["warn"] += 1
                print(f"⚠️  [{timestamp_affiche}] [ligne {numero_ligne}] WARN : {message}")
                enregistrer_rapport(timestamp_original, "WARN", message)

            elif niveau == "ERROR":
                compteurs["error"] += 1
                print(f"🔴 [{timestamp_affiche}] [ligne {numero_ligne}] ERROR détectée, analyse en cours...")
                print(f"   Message brut : {message}\n")

                heure_debut = datetime.now(timezone.utc)
                analyse = analyser_avec_ollama(entry)
                duree = (datetime.now(timezone.utc) - heure_debut).total_seconds()

                print(f"---- Analyse Ollama (durée : {duree:.1f}s) ----")
                print(analyse)
                print("-------------------------\n")

                enregistrer_rapport(timestamp_original, "ERROR", message, analyse)

    return compteurs


if __name__ == "__main__":
    CHEMIN_LOG = "logs/petclinic.log"

    maintenant_utc = datetime.now(timezone.utc)
    maintenant_local = maintenant_utc.astimezone(FUSEAU_LOCAL)
    print(
        f"=== Démarrage de l'analyse : "
        f"{maintenant_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC "
        f"(= {maintenant_local.strftime('%Y-%m-%d %H:%M:%S')} heure Madagascar) ===\n"
    )

    resultats = analyser_fichier_log(CHEMIN_LOG)

    # ------------------------------------------------------------------
    # RÉSUMÉ FINAL EN LANGAGE HUMAIN — c'est la partie qui manquait.
    # Peu importe le contenu technique du rapport, l'utilisateur doit
    # pouvoir comprendre l'état général de l'application en une phrase,
    # sans avoir à ouvrir et interpréter le fichier JSON.
    # ------------------------------------------------------------------
    print("=" * 60)
    print("RÉSUMÉ")
    print("=" * 60)

    if resultats["error"] == 0 and resultats["warn"] == 0:
        print("✅ Aucune erreur ni avertissement détecté.")
        print(f"   Tout va bien : {resultats['info']} événements normaux (INFO) observés.")
    else:
        print(f"📊 {resultats['info']} événements normaux (INFO, ignorés)")
        print(f"⚠️  {resultats['warn']} avertissement(s) (WARN)")
        print(f"🔴 {resultats['error']} erreur(s) (ERROR) — analysée(s) par Ollama ci-dessus")

    if resultats["lignes_ignorees"] > 0:
        print(
            f"ℹ️  {resultats['lignes_ignorees']} ligne(s) du fichier n'ont pas pu être lues "
            f"(format inattendu, ignorées sans risque)"
        )

    print("=" * 60)
    print(f"\nDétail complet enregistré dans : {FICHIER_RAPPORT}")