from tenable.io import TenableIO

# Substitua com suas credenciais
ACCESS_KEY = 'SUA_ACCESS_KEY'
SECRET_KEY = 'SUA_SECRET_KEY'

# Inicializa o cliente
tio = TenableIO(ACCESS_KEY, SECRET_KEY)

# Dicionário para armazenar resultado
asset_vuln_data = {}

# Itera sobre os ativos
for asset in tio.assets.list():
    asset_id = asset.get('id')
    asset_name = None

    # Tenta extrair nome amigável
    for name in asset.get('hostnames', []) + asset.get('fqdn', []):
        if name:
            asset_name = name
            break

    if not asset_name:
        asset_name = asset.get('ipv4') or asset.get('ipv6') or 'Desconhecido'

    # Obtém o resumo de vulnerabilidades do ativo
    vuln_summary = tio.assets.details(asset_id).get('vulnerabilities', [])
    vuln_count = sum([v.get('count', 0) for v in vuln_summary])

    asset_vuln_data[asset_name] = vuln_count

# Exibe o resultado
for name, count in asset_vuln_data.items():
    print(f"{name}: {count} vulnerabilidades")
