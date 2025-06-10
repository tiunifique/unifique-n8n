import os
import json
from collections import defaultdict
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

if os.path.exists(env_path):
    load_dotenv(env_path)

    BASE_URL = os.getenv("BASE_URL")
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    PATH_ID = f'{os.getenv("PATH_ID")}/tenable'

    if BASE_URL and CLIENT_ID and CLIENT_SECRET and PATH_ID:
        try:
            # Autenticação no Delinea
            authorizer = PasswordGrantAuthorizer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
            vault = SecretsVault(BASE_URL, authorizer)
            secret = VaultSecret(**vault.get_secret(PATH_ID))

            ACCESS_KEY = secret.data["CLIENT_ID"]
            SECRET_KEY = secret.data["SECRET_ID"]

            # Conecta ao Tenable
            from tenable.io import TenableIO
            tio = TenableIO(ACCESS_KEY, SECRET_KEY)

            # Faz chamada direta ao endpoint de vulnerabilidades por asset
            response = tio.get("workbenches/assets/vulnerabilities").json()
            asset_vulns = response.get("vulnerabilities", [])

            # Agrupa resultados por asset_id
            result_by_asset = defaultdict(lambda: {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0
            })

            for item in asset_vulns:
                aid = item.get("asset_id")
                severity = item.get("severity", "info").lower()
                count = item.get("count", 0)

                if aid:
                    result_by_asset[aid][severity] += count
                    result_by_asset[aid]["total"] += count

            # Converte para lista de dicionários
            final_output = []
            for aid, data in result_by_asset.items():
                entry = {"asset_id": aid}
                entry.update(data)
                final_output.append(entry)

            # Exibe em formato JSON
            print(json.dumps(final_output, indent=4))

        except SecretsVaultAccessError as e:
            print(f"[Delinea Access Error] {e.message}")
        except SecretsVaultError as e:
            print(f"[Delinea Vault Error] {e.response.text}")
    else:
        print(".env file existe mas está incompleto!")
else:
    print(".env file não encontrado!")
