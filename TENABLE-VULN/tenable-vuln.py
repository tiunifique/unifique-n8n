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

# Caminho para o arquivo .env na mesma pasta do script
current_dir = os.path.dirname(os.path.realpath(__file__))
env_path = os.path.join(current_dir, ".env")
null = "-"

# Carrega variáveis de ambiente
if os.path.exists(env_path):
    load_dotenv(env_path)

    BASE_URL = os.getenv("BASE_URL")
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    PATH_ID = f'{os.getenv("PATH_ID")}/tenable'

    if BASE_URL and CLIENT_ID and CLIENT_SECRET and PATH_ID:
        try:
            # Autenticação com Delinea
            authorizer = PasswordGrantAuthorizer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
            vault = SecretsVault(BASE_URL, authorizer)
            secret = VaultSecret(**vault.get_secret(PATH_ID))

            API_CLIENT = secret.data["CLIENT_ID"]
            API_SECRET = secret.data["SECRET_ID"]

            # Conexão com Tenable.io
            from tenable.io import TenableIO
            tio = TenableIO(API_CLIENT, API_SECRET)

            # Busca ativos e detalhes com contagem de vulnerabilidades
            assets_data = []
            assets = tio.assets.list()  # Lista os ativos com ID

            for asset in assets:
                asset_id = asset.get("id")
                name = None

                # Tenta pegar nome amigável
                for name_field in asset.get("hostnames", []) + asset.get("fqdn", []):
                    if name_field:
                        name = name_field
                        break

                if not name:
                    name = asset.get("ipv4") or asset.get("ipv6") or "Desconhecido"

                # Consulta detalhes do ativo para pegar vulnerabilidades
                details = tio.assets.details(asset_id)
                vulns = details.get("vulnerabilities", [])
                vuln_count = sum(v.get("count", 0) for v in vulns)

                assets_data.append({
                    "name": name,
                    "vulnerabilities": vuln_count
                })

            # Exibe em formato JSON
            print(json.dumps(assets_data, indent=4))

        except SecretsVaultAccessError as e:
            print(f"[Delinea Access Error] {e.message}")
        except SecretsVaultError as e:
            print(f"[Delinea Vault Error] {e.response.text}")
    else:
        print(".env file existe mas está incompleto!")
else:
    print(".env file não encontrado!")
