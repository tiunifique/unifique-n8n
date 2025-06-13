import os
import json
import requests
from dotenv import load_dotenv

# Carrega variáveis do arquivo .env
load_dotenv()

# Lê variáveis de ambiente
host = os.getenv("HOST")
port = os.getenv("PORT")
user = os.getenv("USER")
password = os.getenv("PASSWORD")

base_url = f"{host}:{port}"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}

# Realizando o login
login_url = f"{base_url}/api/login"
payload = json.dumps({"username": user, "password": password})
session = requests.Session()
response = session.post(login_url, data=payload, headers=headers)

if response.status_code != 200:
    raise Exception(f"Login failed with status code {response.status_code}: {response.text}")

# Obtendo a lista de sites
try:
    response = session.get(f"{base_url}/api/stat/sites")
    response.raise_for_status()
    sites_data = response.json()
except Exception as e:
    raise Exception("No JSON Response from sites endpoint") from e

if not isinstance(sites_data.get("data"), list):
    raise Exception(f"Expected response.data to be an array, but got: {json.dumps(sites_data.get('data'))}")

sites = sites_data["data"]
result = []

# Para cada site, buscar as informações dos dispositivos (APs)
for site in sites:
    site_id = site.get("_id")
    site_name = site.get("name") or site.get("desc")
    site_desc = site.get("desc")

    try:
        url = f"{base_url}/api/s/{site_name}/stat/device"
        site_response = session.get(url)
        site_response.raise_for_status()

        print(f"Response from devices endpoint for site {site_id}: {site_response.text}")
        site_data = site_response.json()

        if not isinstance(site_data.get("data"), list):
            raise Exception(f"Expected site_data.data to be an array, but got: {json.dumps(site_data.get('data'))}")

        for device in site_data["data"]:
            mac = device.get("mac", "").replace(":", "-")
            result.append({
                "{#NOME}": device.get("name"),
                "{#MAC}": mac,
                "{#DEVICE.MAC}": device.get("mac"),
                "{#IP}": device.get("ip"),
                "{#SITE.ID}": site_id,
                "{#SITE.NOME}": site_name,
                "{#SITE.DESC}": site_desc
            })

    except Exception as e:
        print(f"Error fetching devices for site {site_id}: {e}")

# Verifica se não há dispositivos encontrados
if not result:
    print(f"No devices found for any site. Result: {json.dumps(result)}")
    raise Exception("No devices found for any site")

# Resultado final em formato JSON
print(json.dumps(result))
