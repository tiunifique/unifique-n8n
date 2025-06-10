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

# Carrega .env
if os.path.exists(env_path):
    load_dotenv(env_path)

    BASE_URL = os.getenv("BASE_URL")
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    PATH_ID = f"{os.getenv('PATH_ID')}/tenable"

    if BASE_URL and CLIENT_ID and CLIENT_SECRET and PATH_ID:
        try:
            # Autenticando no Delinea
            authorizer = PasswordGrantAuthorizer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
            vault = SecretsVault(BASE_URL, authorizer)
            secret = VaultSecret(**vault.get_secret(PATH_ID))

            # Obtém as chaves do Tenable armazenadas no segredo
            ACCESS_KEY = secret.data["CLIENT_ID"]
            SECRET_KEY = secret.data["SECRET_ID"]

            # Chamada autenticada à API do Tenable
            url = "https://cloud.tenable.com/workbenches/assets/vulnerabilities"
            headers = {
                "accept": "application/json",
                "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}"
            }

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                print(json.dumps(data, indent=4))
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
