import os
import json
import requests
from dotenv import load_dotenv
from delinea.secrets.vault import (
    PasswordGrantAuthorizer,
    SecretsVault,
    VaultSecret,
    SecretsVaultAccessError,
    SecretsVaultError
)

# Caminho para o .env
current_dir = os.path.dirname(os.path.realpath(__file__))
env_path = os.path.join(current_dir, ".env")

# Carrega variáveis de ambiente
if os.path.exists(env_path):
    load_dotenv(env_path)

    BASE_URL = os.getenv("BASE_URL")
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    PATH_ID = f"{os.getenv('PATH_ID')}/tenable"

    if BASE_URL and CLIENT_ID and CLIENT_SECRET and PATH_ID:
        try:
            # Autentica no Delinea e obtém as chaves do Tenable
            authorizer = PasswordGrantAuthorizer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
            vault = SecretsVault(BASE_URL, authorizer)
            secret = VaultSecret(**vault.get_secret(PATH_ID))

            ACCESS_KEY = secret.data["CLIENT_ID"]
            SECRET_KEY = secret.data["SECRET_ID"]

            # Requisição ao endpoint da Tenable
            url = "https://cloud.tenable.com/workbenches/assets/vulnerabilities"
            headers = {
                "accept": "application/json",
                "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}"
            }

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()

                # Formata a saída por asset
                formatted_assets = []

                for asset in data.get("assets", []):
                    agent = asset.get("agent_name", [])
                    fqdn = asset.get("fqdn", [])
                    ipv4 = asset.get("ipv4", [])
                    
                    if agent:
                        asset_name = agent[0]
                    elif fqdn:
                        asset_name = fqdn[0]
                    elif ipv4:
                        asset_name = ipv4[0]
                    else:
                        asset_name = "Desconhecido"

                    severities = {
                        "info": 0,
                        "low": 0,
                        "medium": 0,
                        "high": 0,
                        "critical": 0
                    }

                    for sev in asset.get("severities", []):
                        name = sev.get("name", "").lower()
                        count = sev.get("count", 0)
                        if name in severities:
                            severities[name] = count

                    formatted_assets.append({
                        "asset": asset_name,
                        "ip": ip,
                        **severities,
                        "total": total
                    })

                # Exibe resultado limpo
                print(json.dumps(formatted_assets, indent=4))

            else:
                print(f"Erro {response.status_code}: {response.text}")

        except SecretsVaultAccessError as e:
            print(f"[Delinea Access Error] {e.message}")
        except SecretsVaultError as e:
            print(f"[Delinea Vault Error] {e.response.text}")
    else:
        print(".env file existe mas está incompleto!")
else:
    print(".env file não encontrado!")
