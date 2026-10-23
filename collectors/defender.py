import os
import subprocess
import requests


DEFENDER_API_URL = (
    "https://api.security.microsoft.com"
    "/api/machines/SoftwareVulnerabilitiesExport"
)

# Inventaire logiciel complet par machine (export par fichiers), pour le
# calcul des équipements touchés selon NVD (sync_software_inventory.py).
# Permission API requise : Software.Read.All.
SOFTWARE_INVENTORY_EXPORT_URL = (
    "https://api.security.microsoft.com"
    "/api/machines/SoftwareInventoryExport"
)


AZ_PATHS = [
    r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
    r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az",
    r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.exe",
    r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
    r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az",
    r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.exe",
]


def find_az():

    for path in AZ_PATHS:

        if os.path.isfile(path):
            return path

    for command in ["az.cmd", "az.exe", "az"]:

        result = subprocess.run(
            ["where.exe", command],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:

            path = result.stdout.strip().splitlines()[0]

            if path:
                return path

    raise FileNotFoundError(
        "Azure CLI not found."
    )


def get_access_token():
    """
    Jeton pour l'API Defender : application Entra ID si elle est
    configurée et activée (Interface > Application Azure), sinon le
    compte connecté à Azure CLI.
    """

    from services.azure_auth import (
        is_azure_app_configured,
        request_app_token,
        DEFENDER_RESOURCE
    )

    if is_azure_app_configured():
        return request_app_token(DEFENDER_RESOURCE)

    return _get_azure_cli_token()


def _get_azure_cli_token():

    az = find_az()

    result = subprocess.run(
        [
            az,
            "account",
            "get-access-token",
            "--resource",
            "https://api.securitycenter.microsoft.com",
            "--query",
            "accessToken",
            "-o",
            "tsv"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        # Sans ce message, l'erreur se résumait à "returned non-zero exit
        # status 1" : on remonte ce qu'Azure CLI a réellement répondu
        # (session expirée, mauvais compte, MFA requise...).
        message = (result.stderr or result.stdout or "").strip()

        raise RuntimeError(
            "Azure CLI n'a pas pu fournir de jeton pour l'API Defender "
            f"(compte Windows : {os.getenv('USERNAME') or os.getenv('USER') or 'inconnu'}). "
            "Ouvrez une console avec ce compte et lancez "
            "« az login » (ou « az login --tenant <id-du-tenant> »), ou "
            "configurez une application Azure (barre latérale > "
            "Application Azure) pour ne plus dépendre d'un compte. "
            f"Réponse d'Azure CLI : {message}"
        )

    token = result.stdout.strip()

    if not token:
        raise RuntimeError(
            "Azure CLI returned an empty token."
        )

    return token


def request_export(
    sas_valid_hours=6,
    url=DEFENDER_API_URL
):

    token = get_access_token()

    headers = {
        "Authorization": f"Bearer {token}"
    }

    params = {
        "sasValidHours": sas_valid_hours
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=120
    )

    response.raise_for_status()

    data = response.json()

    export_files = data.get(
        "exportFiles",
        []
    )

    generated_time = data.get(
        "generatedTime"
    )

    if not export_files:

        raise RuntimeError(
            "Defender returned no export files."
        )

    return {
        "generated_time": generated_time,
        "export_files": export_files
    }


def download_export_file(
    url,
    destination
):

    response = requests.get(
        url,
        stream=True,
        timeout=300
    )

    response.raise_for_status()

    with open(
        destination,
        "wb"
    ) as output:

        for chunk in response.iter_content(
            chunk_size=1024 * 1024
        ):

            if chunk:
                output.write(chunk)

    return destination


# =========================================================
# ADVANCED HUNTING (inventaire logiciel complet, par lots de machines)
# =========================================================
#
# L'export par fichiers et les exports CSV du portail peuvent être
# incomplets ; un export de résultats Advanced Hunting est plafonné à
# 100 000 lignes. On interroge donc la table DeviceTvmSoftwareInventory
# (mêmes colonnes que l'export CSV) par LOTS de machines dont le total
# reste sous ce plafond, et on recoupe un lot qui l'atteindrait.
# Permission API (application) : AdvancedQuery.Read.All.

HUNTING_URL = "https://api.security.microsoft.com/api/advancedqueries/run"

HUNTING_ROW_LIMIT = 100_000
HUNTING_BATCH_ROWS = 80_000
HUNTING_BATCH_DEVICES = 500

INVENTORY_COLUMNS = (
    "DeviceId, DeviceName, OSPlatform, OSVersion, OSArchitecture, "
    "SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, "
    "EndOfSupportDate, ProductCodeCpe"
)


def run_hunting_query(query, token=None):
    """
    Exécute une requête Advanced Hunting et retourne ses lignes (dicts).
    Limites Microsoft : 45 requêtes / minute, 100 000 lignes, 10 minutes
    par requête ; un 429 est retenté après le délai Retry-After.
    """

    import time

    token = token or get_access_token()

    for attempt in range(6):

        response = requests.post(
            HUNTING_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            json={"Query": query},
            timeout=660
        )

        if response.status_code == 429 or response.status_code >= 500:
            wait = int(response.headers.get("Retry-After") or 30 * (attempt + 1))
            print(f"    Advanced Hunting {response.status_code} : nouvel essai dans {wait} s")
            time.sleep(wait)
            continue

        if response.status_code >= 400:
            raise RuntimeError(
                f"Advanced Hunting a refusé la requête ({response.status_code}) : "
                f"{response.text[:300]}"
            )

        return response.json().get("Results", [])

    raise RuntimeError("Advanced Hunting indisponible après plusieurs essais.")


def _kql_ids(device_ids):

    return ", ".join(f'"{device_id}"' for device_id in device_ids)


def hunting_inventory_for_devices(device_ids, token=None):
    """
    Inventaire logiciel des machines données. Si le résultat atteint le
    plafond de 100 000 lignes, le lot est coupé en deux et redemandé.
    """

    rows = run_hunting_query(
        "DeviceTvmSoftwareInventory "
        f"| where DeviceId in ({_kql_ids(device_ids)}) "
        f"| project {INVENTORY_COLUMNS}",
        token
    )

    if len(rows) >= HUNTING_ROW_LIMIT and len(device_ids) > 1:

        middle = len(device_ids) // 2

        return (
            hunting_inventory_for_devices(device_ids[:middle], token)
            + hunting_inventory_for_devices(device_ids[middle:], token)
        )

    return rows


def hunting_fingerprints(token=None):
    """
    Une ligne par machine : DeviceId, Rows (nombre de logiciels) et
    Fingerprint, empreinte SHA-256 de la liste triée
    "éditeur:logiciel:version". Une seule requête légère (une ligne par
    machine) : seules les machines dont l'empreinte a changé depuis le
    dernier import sont ensuite retéléchargées.
    """

    return run_hunting_query(
        "DeviceTvmSoftwareInventory "
        "| summarize Items = make_set(strcat(SoftwareVendor, ':', SoftwareName, "
        "':', SoftwareVersion)) by DeviceId "
        "| extend Rows = array_length(Items), "
        "Fingerprint = hash_sha256(strcat_array(array_sort_asc(Items), '|')) "
        "| project DeviceId, Rows, Fingerprint",
        token
    )


def iter_hunting_inventory_for(counts, token=None, progress=None):
    """
    Inventaire des machines de `counts` ([{"DeviceId", "Rows"}]), par lots
    sous la limite de 100 000 lignes. progress(lot, nombre de lots,
    machines, lignes) est appelé à chaque lot.
    """

    token = token or get_access_token()

    batches = []
    batch, batch_rows = [], 0

    for row in sorted(counts, key=lambda r: r["DeviceId"]):

        rows = int(row.get("Rows") or 0)

        if batch and (
            batch_rows + rows > HUNTING_BATCH_ROWS
            or len(batch) >= HUNTING_BATCH_DEVICES
        ):
            batches.append(batch)
            batch, batch_rows = [], 0

        batch.append(row["DeviceId"])
        batch_rows += rows

    if batch:
        batches.append(batch)

    total_rows = sum(int(row.get("Rows") or 0) for row in counts)

    print(
        f"Advanced Hunting : {len(counts)} machine(s), {total_rows} ligne(s) "
        f"d'inventaire, {len(batches)} lot(s)"
    )

    for index, device_ids in enumerate(batches, start=1):

        rows = hunting_inventory_for_devices(device_ids, token)

        if progress:
            progress(index, len(batches), len(device_ids), len(rows))

        print(f"    lot {index}/{len(batches)} : {len(device_ids)} machine(s), {len(rows)} ligne(s)")

        yield from rows


def iter_hunting_inventory(progress=None):
    """Inventaire logiciel complet de toutes les machines, lot par lot."""

    token = get_access_token()

    counts = run_hunting_query(
        "DeviceTvmSoftwareInventory | summarize Rows = count() by DeviceId",
        token
    )

    yield from iter_hunting_inventory_for(counts, token, progress)
