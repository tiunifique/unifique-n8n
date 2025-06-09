#!/usr/bin/python3

import requests
import json
import urllib3
import hashlib
import re

# Desativar avisos de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Definir variáveis
OMADA_URL = "https://wifibusiness.unifique.com.br"
USERNAME = "admin"
PASSWORD = "Bt92rVzZhczSYZ%v"

# Função para obter o controller ID
def get_controller_id():
    response = requests.get(f"{OMADA_URL}/api/info", verify=False)
    return response.json()['result']['omadacId']

# Função para login e obter o token
def login(controller_id):
    login_url = f"{OMADA_URL}/{controller_id}/api/v2/login"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "username": USERNAME,
        "password": PASSWORD
    }
    session = requests.Session()
    response = session.post(login_url, headers=headers, data=json.dumps(data), verify=False)
    token = response.json()['result']['token']
    return session, token

# Função para obter a lista de sites
def get_sites(controller_id, session, token):
    sites_url = f"{OMADA_URL}/{controller_id}/api/v2/sites?token={token}&currentPage=1&currentPageSize=1000"
    headers = {
        "Content-Type": "application/json",
        "Csrf-Token": token
    }
    response = session.get(sites_url, headers=headers, verify=False)
    return response.json()

# Função para obter a lista de devices de um site
def get_devices(controller_id, session, token, site_id):
    devices_url = f"{OMADA_URL}/{controller_id}/api/v2/sites/{site_id}/devices?token={token}"
    headers = {
        "Content-Type": "application/json",
        "Csrf-Token": token
    }
    response = session.get(devices_url, headers=headers, verify=False)
    return response.json()

# Função para gerar um ID numérico baseado na MAC Address
def generate_numeric_id_from_mac(mac):
    numeric = re.sub(r'[^0-9]', '', mac)
    if numeric:
        return int(numeric[:15])  # Limita para não ultrapassar tamanho de int
    return 0

# Fluxo principal
controller_id = get_controller_id()
session, token = login(controller_id)
sites_info = get_sites(controller_id, session, token)

# Lista para armazenar o resultado final
result = []

# Verificação da estrutura de sites_info
if 'result' in sites_info and 'data' in sites_info['result']:
    # Filtrar apenas os campos 'id' e 'name' dos sites
    filtered_sites = [{"id": site["id"], "name": site["name"]} for site in sites_info['result']['data']]

    # Para cada site, obter os dispositivos
    for site in filtered_sites:
        site_id = site['id']
        site_name = site['name']

        # Obter os dispositivos do site
        devices_info = get_devices(controller_id, session, token, site_id)

        # Verificar se a resposta contém os dispositivos corretamente
        if 'result' in devices_info:
            for device in devices_info['result']:
                # Aplicar filtro: ignorar devices com status 24
                if device.get('status') == 24:
                    continue

                mac = device.get('mac', '')
                unique_id = generate_numeric_id_from_mac(mac) if mac else None

                # Coletar campos
                result.append({
                    "Id": unique_id,
                    "site_nome": site_name,
                    "site_id": site_id,
                    "device_type": device.get('type'),
                    "device_nome": device.get('name'),
                    "device_mac": mac,
                    "device_ip": device.get('ip'),
                    "device_publicip": device.get('publicIp'),
                    "device_uptime": device.get('uptime'),
                    "device_status": device.get('statusCategory'),
                    "device_status1": device.get('status'),
                    "device_adoptFailType": device.get('adoptFailType'),
                    "device_cpuutil": device.get('cpuUtil'),
                    "device_memutil": device.get('memUtil'),
                    "device_download": device.get('download'),
                    "device_upload": device.get('upload'),
                    "device_clientnum": device.get('clientNum')
                })

# Imprimir o JSON final formatado com os campos desejados
print(json.dumps(result, indent=4))
