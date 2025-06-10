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

# Carrega variáveis do .env
current_dir = os.path.dirname(os.path.realpath(__file__))
env_path = os.path.join(current_dir, ".env")

if os.path.exists(env_path):
    load_dotenv(env_path)

    BASE_URL = os.getenv("BASE_URL")
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    PATH_ID = f"{os.getenv('PATH_ID')}/tenable"

    if BASE_URL and CLIENT_ID and CLIENT_SECRET and PATH_ID:
        try:
            # Autentica no Delinea
            authorizer = PasswordGrantAuthorizer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
            vault = SecretsVault(BASE_URL, authorizer)
            secret = VaultSecret(**vault.get_secret(PATH_ID))

            ACCESS_KEY = secret.data["CLIENT_ID"]
            SECRET_KEY = secret.data["SECRET_ID"]

            # Cabeçalhos para a Tenable API
            headers = {
                "accept": "application/json",
                "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}"
            }

            # Requisição principal
            vuln_url = "https://cloud.tenable.com/workbenches/assets/vulnerabilities"
            resp = requests.get(vuln_url, headers=headers)

            if resp.status_code != 200:
                print(f"Erro {resp.status_code}: {resp.text}")
                exit()

            data = resp.json()
            formatted_assets = []

            for asset in data.get("assets", []):
                asset_id = asset.get("id", "unknown")

                # Asset name
                agent = asset.get("agent_name", [])
                fqdn = asset.get("fqdn", [])
                ipv4_list = asset.get("ipv4", [])

                if agent:
                    asset_name = agent[0]
                elif fqdn:
                    asset_name = fqdn[0]
                elif ipv4_list:
                    asset_name = ipv4_list[0]
                else:
                    asset_name = "Desconhecido"

                ip = ipv4_list[0] if ipv4_list else "-"
                total = asset.get("total", 0)

                # Inicializa severidades
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

                # Obtem MAC address via /workbenches/assets/{asset_id}/info
                info_url = f"https://cloud.tenable.com/workbenches/assets/{asset_id}/info"
                info_resp = requests.get(info_url, headers=headers)
                macs = []
                if info_resp.status_code == 200:
                    info_data = info_resp.json()
                    macs = info_data.get("info", {}).get("mac_address", [])

                formatted_assets.append({
                    "tenable_id": asset_id,
                    "tenable_name": asset_name,
                    "tenable_macs": macs,
                    **severities,
                    "total": total
                })
                # INÍCIO do envio ao NocoDB
                noco_token = os.getenv("NOCO_API_TOKEN")
                noco_url = os.getenv("NOCO_API_URL")
                noco_table = os.getenv("NOCO_TABLE_ID")
                noco_view = os.getenv("NOCO_VIEW_ID")
                
                noco_headers = {
                    "xc-token": noco_token,
                    "Content-Type": "application/json"
                }
                
                # Busca registros existentes
                get_url = f"{noco_url}/tables/{noco_table}/records"
                params = {
                    "offset": "0",
                    "limit": "999",
                    "where": "",
                    "viewId": noco_view
                }
                existing_resp = requests.get(get_url, headers=noco_headers, params=params)
                
                existing_asset_ids = {}
                if existing_resp.status_code == 200:
                    for item in existing_resp.json().get("list", []):
                        tenable_id = item.get("tenable_id")
                        row_id = item.get("Id")
                        if tenable_id:
                            existing_asset_ids[tenable_id] = row_id
                else:
                    print(f"Erro ao buscar registros do NocoDB: {existing_resp.text}")
                    exit()
                
                # Cria ou atualiza registros
                for asset in formatted_assets:
                    tenable_id = asset["tenable_id"]
                
                    if tenable_id in existing_asset_ids:
                        # Atualizar
                        row_id = existing_asset_ids[tenable_id]
                        put_url = f"{noco_url}/tables/{noco_table}/records/{row_id}"
                        put_resp = requests.put(put_url, headers=noco_headers, json=asset)
                        print(f"[UPDATE] {tenable_id} | Status {put_resp.status_code}")
                    else:
                        # Criar
                        post_url = f"{noco_url}/tables/{noco_table}/records"
                        post_resp = requests.post(post_url, headers=noco_headers, json=asset)
                        print(f"[CREATE] {tenable_id} | Status {post_resp.status_code}")
                # FIM do envio ao NocoDB

            print(json.dumps(formatted_assets, indent=4))

        except SecretsVaultAccessError as e:
            print(f"[Delinea Access Error] {e.message}")
        except SecretsVaultError as e:
            print(f"[Delinea Vault Error] {e.response.text}")
    else:
        print(".env file existe mas está incompleto!")
else:
    print(".env file não encontrado!")
