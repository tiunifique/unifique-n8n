import os
import json
from dotenv import load_dotenv
from delinea.secrets.vault import (
    PasswordGrantAuthorizer,
    SecretsVault,
    SecretsVaultAccessError,
    SecretsVaultError,
    VaultSecret
)

# Caminho para o .env
current_dir = os.path.dirname(os.path.realpath(__file__))
env_path = os.path.join(current_dir, ".env")
null = "-"

if os.path.exists(env_path):
    load_dotenv(env_path)

    BASE_URL = os.getenv("BASE_URL")
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    PATH_ID = f'{os.getenv("PATH_ID")}/tenable'

    if BASE_URL and CLIENT_ID and CLIENT_SECRET and PATH_ID:
        try:
            # Autenticando no Delinea
            authorizer = PasswordGrantAuthorizer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
            vault = SecretsVault(BASE_URL, authorizer)
            secret = VaultSecret(**vault.get_secret(PATH_ID))

            API_CLIENT = secret.data["CLIENT_ID"]
            API_SECRET = secret.data["SECRET_ID"]

            # Conectando ao Tenable.io
            from tenable.io import TenableIO
            tio = TenableIO(API_CLIENT, API_SECRET)

            results = []

            # Itera sobre ativos e faz chamada direta ao endpoint de vulnerabilidades
            for asset in tio.workbenches.assets():
                asset_id = asset.get("id")
                name = asset.get("hostname") or asset.get("ipv4") or asset.get("ipv6") or "Desconhecido"

                # Chamada direta via GET e extração do JSON
                vuln_resp = tio.get(f"workbenches/assets/{asset_id}/vulnerabilities").json()
                vuln_count = len(vuln_resp.get("vulnerabilities", []))

                results.append({
                    "name": name,
                    "vulnerabilities": vuln_count
                })

            print(json.dumps(results, indent=4))

        except SecretsVaultAccessError as e:
            print(f"[Delinea Access Error] {e.message}")
        except SecretsVaultError as e:
            print(f"[Delinea Vault Error] {e.response.text}")
    else:
        print(".env file existe mas está incompleto!")
else:
    print(".env file não encontrado!")
