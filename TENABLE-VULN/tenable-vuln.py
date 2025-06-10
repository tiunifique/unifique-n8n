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

# Caminho para o arquivo .env
current_dir = os.path.dirname(os.path.realpath(__file__))
env_path = os.path.join(current_dir, ".env")

# Valor padrão para campos ausentes
null = "-"

# Verifica e carrega o .env
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

            # Extrai credenciais do Tenable armazenadas no cofre
            API_CLIENT = secret.data["CLIENT_ID"]
            API_SECRET = secret.data["SECRET_ID"]

            # Conecta à API do Tenable.io
            from tenable.io import TenableIO
            tio = TenableIO(API_CLIENT, API_SECRET)

            # Lista de ativos com nome e total de vulnerabilidades
            assets_data = []

            # Busca os ativos
            assets = tio.v3.explore.assets.search_host()

            for asset in assets:
                name = asset.get("name") or asset.get("fqdn", [null])[0] or asset.get("ipv4", null)
                vulns = asset.get("vulnerabilities", [])
                vuln_count = sum([v.get("count", 0) for v in vulns])
                assets_data.append({"name": name, "vulnerabilities": vuln_count})

            # Exibe os resultados em formato JSON
            print(json.dumps(assets_data, indent=4))

        except SecretsVaultAccessError as e:
            print(f"[Delinea Access Error] {e.message}")
        except SecretsVaultError as e:
            print(f"[Delinea Vault Error] {e.response.text}")
    else:
        print(".env file existe mas está incompleto!")
else:
    print(".env file não encontrado!")
