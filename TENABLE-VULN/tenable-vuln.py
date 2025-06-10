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
from tenable.io import TenableIO

# Path to the .env file in the same directory as the script
current_dir = os.path.dirname(os.path.realpath(__file__))
env_path = os.path.join(current_dir, ".env")

# Load environment variables from .env file
if os.path.exists(env_path):
    load_dotenv(env_path)

    BASE_URL = os.getenv("BASE_URL")
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    # Ensure PATH_ID is correctly formatted for Delinea
    PATH_ID = f'{os.getenv("PATH_ID")}/tenable'

    if BASE_URL and CLIENT_ID and CLIENT_SECRET and PATH_ID:
        try:
            # Authenticate with Delinea Secrets Vault
            authorizer = PasswordGrantAuthorizer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
            vault = SecretsVault(BASE_URL, authorizer)
            # Retrieve the secret containing Tenable.io API credentials
            secret = VaultSecret(**vault.get_secret(PATH_ID))

            API_CLIENT = secret.data["CLIENT_ID"]
            API_SECRET = secret.data["SECRET_ID"]

            # Initialize Tenable.io API client
            tio = TenableIO(API_CLIENT, API_SECRET)

            # List to store asset data with vulnerability counts
            assets_data = []
            print("Fetching assets from Tenable.io...")
            # List all assets
            assets = tio.assets.list()

            for asset in assets:
                asset_id = asset.get("id")
                name = None

                # Try to get a friendly name (hostname or FQDN)
                for name_field in asset.get("hostnames", []) + asset.get("fqdn", []):
                    if name_field:
                        name = name_field
                        break

                # If no friendly name, use IP address or "Unknown"
                if not name:
                    name = asset.get("ipv4") or asset.get("ipv6") or "Desconhecido"

                vuln_count = 0
                asset_uuid = asset.get("uuid") # Get the UUID from the initial asset list

                if asset_uuid:
                    try:
                        # Attempt to count vulnerabilities using the UUID from the initial list
                        vulnerabilities_for_asset = tio.vulnerabilities.list(asset_uuid=asset_uuid)
                        for _ in vulnerabilities_for_asset:
                            vuln_count += 1
                        print(f"Asset: {name} (UUID: {asset_uuid}), Vulnerabilities: {vuln_count} (via UUID)")
                    except Exception as e:
                        print(f"Error fetching vulnerabilities for asset {name} (UUID: {asset_uuid}) using vulnerabilities.list: {e}")
                        # Fallback to details if UUID list fails, though unlikely if UUID is present
                        details = tio.assets.details(asset_id)
                        vulns_from_details = details.get("vulnerabilities", [])
                        vuln_count = sum(v.get("count", 0) for v in vulns_from_details)
                        print(f"  --> Falling back to sum from asset details. Vulnerabilities: {vuln_count}")
                else:
                    print(f"Asset: {name} (ID: {asset_id}) has no UUID in initial list. Fetching details...")
                    try:
                        # If UUID is missing from the initial list, fetch full asset details
                        details = tio.assets.details(asset_id)
                        asset_uuid_from_details = details.get("uuid") # Check for UUID in details

                        if asset_uuid_from_details:
                            # If UUID found in details, use it to count vulnerabilities
                            vulnerabilities_for_asset = tio.vulnerabilities.list(asset_uuid=asset_uuid_from_details)
                            for _ in vulnerabilities_for_asset:
                                vuln_count += 1
                            print(f"Asset: {name} (UUID: {asset_uuid_from_details}), Vulnerabilities: {vuln_count} (via UUID from details)")
                        else:
                            # Fallback: If UUID is still missing after details fetch,
                            # sum counts from the 'vulnerabilities' field in the details response.
                            # Note: This usually sums vulnerabilities by severity, not total findings.
                            vulns_from_details = details.get("vulnerabilities", [])
                            vuln_count = sum(v.get("count", 0) for v in vulns_from_details)
                            print(f"  Asset: {name} (ID: {asset_id}) still no UUID. Falling back to sum from asset details. Vulnerabilities: {vuln_count}")

                    except Exception as e:
                        print(f"Error fetching details or vulnerabilities for asset {name} (ID: {asset_id}): {e}")
                        print(f"  --> Setting vulnerability count to 0 for this asset due to error.")
                        vuln_count = 0 # Ensure count is 0 if an error occurs

                assets_data.append({
                    "name": name,
                    "vulnerabilities": vuln_count
                })

            # Print the results in JSON format
            print("\n--- Total Vulnerabilities per Asset ---")
            print(json.dumps(assets_data, indent=4))

        except SecretsVaultAccessError as e:
            print(f"[Delinea Access Error] Failed to access Delinea Vault: {e.message}")
        except SecretsVaultError as e:
            print(f"[Delinea Vault Error] An error occurred with Delinea Vault: {e.response.text}")
        except Exception as e:
            print(f"[General Error] An unexpected error occurred: {e}")
    else:
        print(".env file exists but is incomplete. Ensure BASE_URL, CLIENT_ID, CLIENT_SECRET, and PATH_ID are set.")
else:
    print(".env file not found! Please create a .env file with BASE_URL, CLIENT_ID, CLIENT_SECRET, and PATH_ID.")

