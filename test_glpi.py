import requests

#GLPI_URL = "http://localhost/glpi/api"
GLPI_URL = "http://localhost"

APP_TOKEN = "Oh8MZhNDNF5bNhgRnv8VpKkHVTbbNdVNvQlXt6xl"
USER_TOKEN = "JB84o3AtMEUpxvUGxw8tLLEVTaGqYUD7QTNrDjfo"


headers = {
    "Content-Type": "application/json",
    "App-Token": APP_TOKEN,
    "Authorization": f"user_token {USER_TOKEN}",
}

#url = f"{GLPI_URL}/initSession"
url = f"{GLPI_URL}/apirest.php/initSession/"

response = requests.get(url, headers=headers)

print("Code HTTP :", response.status_code)
print("Réponse :", response.text)