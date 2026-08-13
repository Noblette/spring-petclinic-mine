import requests

GLPI_URL = "http://localhost"

APP_TOKEN = "Oh8MZhNDNF5bNhgRnv8VpKkHVTbbNdVNvQlXt6xl"
USER_TOKEN = "JB84o3AtMEUpxvUGxw8tLLEVTaGqYUD7QTNrDjfo"


# --------------------------------------------------
# 1. Initialisation de la session GLPI
# --------------------------------------------------

headers = {
    "Content-Type": "application/json",
    "App-Token": APP_TOKEN,
    "Authorization": f"user_token {USER_TOKEN}",
}

url_session = f"{GLPI_URL}/apirest.php/initSession/"

response = requests.get(url_session, headers=headers)

print("Connexion GLPI")
print("Code HTTP :", response.status_code)

if response.status_code != 200:
    print("Erreur :", response.text)
    exit(1)

session_token = response.json()["session_token"]

print("Session GLPI créée avec succès")


# --------------------------------------------------
# 2. Création du ticket
# --------------------------------------------------

ticket_headers = {
    "Content-Type": "application/json",
    "App-Token": APP_TOKEN,
    "Session-Token": session_token,
}

ticket_data = {
    "input": {
        "name": "[TEST AIOps] Incident Spring Petclinic",
        "content": """
Test de création automatique d'un ticket GLPI.

Ce ticket a été créé depuis Python via l'API REST GLPI.

Dans le projet final, cette partie sera alimentée
par l'analyse des logs avec Ollama.
"""
    }
}

url_ticket = f"{GLPI_URL}/apirest.php/Ticket/"

response = requests.post(
    url_ticket,
    headers=ticket_headers,
    json=ticket_data
)

print("\nCréation du ticket")
print("Code HTTP :", response.status_code)
print("Réponse :", response.text)


# --------------------------------------------------
# 3. Fermeture de la session
# --------------------------------------------------

headers_close = {
    "App-Token": APP_TOKEN,
    "Session-Token": session_token,
}

requests.get(
    f"{GLPI_URL}/apirest.php/killSession/",
    headers=headers_close
)
