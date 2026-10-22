import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from collectors.defender import find_az, get_access_token


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "vulnwatch.db"

DEFENDER_API = "https://api.security.microsoft.com"
GRAPH_API = "https://graph.microsoft.com/v1.0/users"

# =========================================================
# CONFIGURATION
# =========================================================

# Pour les premiers tests, conserver 5.
# Une fois validé, mettre None pour traiter tout le parc Windows.
TEST_LIMIT = None

# Délai entre deux appels Defender pour rester sous la limite API.
REQUEST_DELAY = 1.0

# Comptes qui ne doivent pas être considérés comme propriétaires.
TECHNICAL_ACCOUNT_PATTERNS = (
    "_$",
    "system",
    "local service",
    "network service",
    "defaultuser",
    "defaultuser0",
)


# =========================================================
# TOKENS
# =========================================================

def get_graph_token():
    """
    Récupère un token Microsoft Graph : application Entra ID si elle est
    configurée (Interface > Application Azure), sinon Azure CLI.

    Utilise find_az() du collector Defender afin de fonctionner
    même si az.exe n'est pas présent dans le PATH PowerShell.
    """
    from services.azure_auth import (
        is_azure_app_configured,
        request_app_token,
        GRAPH_RESOURCE
    )

    if is_azure_app_configured():
        return request_app_token(GRAPH_RESOURCE)

    az = find_az()

    result = subprocess.run(
        [
            az,
            "account",
            "get-access-token",
            "--resource",
            "https://graph.microsoft.com",
            "--query",
            "accessToken",
            "-o",
            "tsv",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    token = result.stdout.strip()

    if not token:
        raise RuntimeError("Azure CLI returned an empty Graph token.")

    return token


# =========================================================
# DEVICES
# =========================================================

def get_devices(conn):
    """
    Retourne les devices Windows présents dans
    defender_vulnerabilities.

    TEST_LIMIT = None pour les premiers tests.
    Mettre TEST_LIMIT = None pour tout le parc.
    """

    sql = """
        SELECT
            device_id,
            device_name
        FROM defender_vulnerabilities
        WHERE device_id IS NOT NULL
          AND TRIM(device_id) <> ''
          AND device_name IS NOT NULL
          AND TRIM(device_name) <> ''
          AND LOWER(COALESCE(os_platform, '')) LIKE '%windows%'
        GROUP BY
            device_id,
            device_name
        ORDER BY
            device_name
    """

    params = []

    if TEST_LIMIT is not None:
        sql += " LIMIT ?"
        params.append(TEST_LIMIT)

    return conn.execute(sql, params).fetchall()


# =========================================================
# DEFENDER - LOGON USERS
# =========================================================

def get_logon_users(device_id, defender_token):
    """
    Récupère les utilisateurs vus sur un device Defender.
    """

    headers = {
        "Authorization": f"Bearer {defender_token}"
    }

    url = f"{DEFENDER_API}/api/machines/{device_id}/logonusers"

    response = requests.get(
        url,
        headers=headers,
        timeout=60,
    )

    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After")

        try:
            wait_seconds = int(retry_after)
        except (TypeError, ValueError):
            wait_seconds = 60

        print(
            f"    Rate limit Defender atteint. "
            f"Nouvel essai dans {wait_seconds}s..."
        )

        time.sleep(wait_seconds)

        response = requests.get(
            url,
            headers=headers,
            timeout=60,
        )

    response.raise_for_status()

    return response.json().get("value", [])


def is_technical_account(user):
    """
    Exclut les comptes techniques évidents.
    """

    account = str(
        user.get("accountName") or ""
    ).strip().lower()

    user_id = str(
        user.get("id") or ""
    ).strip().lower()

    for value in (account, user_id):
        if not value:
            continue

        if value.endswith("_$"):
            return True

        if value in {
            "system",
            "local service",
            "network service",
            "defaultuser",
            "defaultuser0",
        }:
            return True

        if any(
            value.endswith(pattern)
            for pattern in TECHNICAL_ACCOUNT_PATTERNS
            if pattern != "_$"
        ):
            return True

    return False


def parse_last_seen(user):
    """
    Convertit lastSeen en datetime UTC pour permettre
    une comparaison fiable.
    """

    value = user.get("lastSeen")

    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def select_owner(users):
    """
    Sélectionne le meilleur candidat propriétaire :

    1. non technique
    2. Interactive
    3. dernier utilisateur vu
    """

    candidates = []

    for user in users:
        if is_technical_account(user):
            continue

        logon_types = user.get("logonTypes") or []

        if isinstance(logon_types, str):
            logon_types = [logon_types]

        interactive = any(
            str(logon_type).lower() == "interactive"
            for logon_type in logon_types
        )

        if not interactive:
            continue

        account_name = str(
            user.get("accountName") or ""
        ).strip()

        if not account_name:
            continue

        candidates.append(user)

    if not candidates:
        return None

    candidates.sort(
        key=parse_last_seen,
        reverse=True,
    )

    return candidates[0]


# =========================================================
# MICROSOFT GRAPH
# =========================================================

def lookup_graph_user(account_name, graph_token):
    """
    Cherche l'utilisateur Entra ID correspondant au compte Defender.

    Recherche :
      1. userPrincipalName
      2. mail
    """

    headers = {
        "Authorization": f"Bearer {graph_token}"
    }

    account_name = str(account_name).strip()

    if not account_name:
        return None

    # Pour un compte du type DOMAIN\\cmillet,
    # on utilise uniquement la partie utilisateur.
    if "\\" in account_name:
        account_name = account_name.split("\\", 1)[1].strip()

    # -----------------------------------------------------
    # Recherche UPN
    # -----------------------------------------------------

    response = requests.get(
        GRAPH_API,
        headers=headers,
        params={
            "$filter": f"startswith(userPrincipalName,'{account_name.replace(chr(39), chr(39) + chr(39))}')",
            "$select": "id,displayName,mail,userPrincipalName",
            "$top": "10",
        },
        timeout=60,
    )

    response.raise_for_status()

    users = response.json().get("value", [])

    if users:
        return users[0]

    # -----------------------------------------------------
    # Recherche mail
    # -----------------------------------------------------

    response = requests.get(
        GRAPH_API,
        headers=headers,
        params={
            "$filter": f"startswith(mail,'{account_name.replace(chr(39), chr(39) + chr(39))}')",
            "$select": "id,displayName,mail,userPrincipalName",
            "$top": "10",
        },
        timeout=60,
    )

    response.raise_for_status()

    users = response.json().get("value", [])

    if users:
        return users[0]

    return None


# =========================================================
# DATABASE
# =========================================================

def ensure_asset_owners_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_owners (
            device_id TEXT PRIMARY KEY,
            device_name TEXT NOT NULL,
            owner_name TEXT,
            owner_email TEXT,
            last_logon_account TEXT,
            last_logon_timestamp TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )

    columns = {row[1] for row in conn.execute("PRAGMA table_info(asset_owners)").fetchall()}

    if "last_logon_account" not in columns:
        conn.execute("ALTER TABLE asset_owners ADD COLUMN last_logon_account TEXT")

    if "last_logon_timestamp" not in columns:
        conn.execute("ALTER TABLE asset_owners ADD COLUMN last_logon_timestamp TEXT")

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_asset_owners_device_name
        ON asset_owners(device_name)
        """
    )

    conn.commit()


def save_owner(
    conn,
    device_id,
    device_name,
    owner_name,
    owner_email,
    last_logon_account=None,
    last_logon_timestamp=None,
):
    updated_at = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """
        INSERT INTO asset_owners (
            device_id,
            device_name,
            owner_name,
            owner_email,
            last_logon_account,
            last_logon_timestamp,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id)
        DO UPDATE SET
            device_name = excluded.device_name,
            owner_name = COALESCE(excluded.owner_name, asset_owners.owner_name),
            owner_email = COALESCE(excluded.owner_email, asset_owners.owner_email),
            last_logon_account = COALESCE(excluded.last_logon_account, asset_owners.last_logon_account),
            last_logon_timestamp = COALESCE(excluded.last_logon_timestamp, asset_owners.last_logon_timestamp),
            updated_at = excluded.updated_at
        """,
        (
            device_id,
            device_name,
            owner_name,
            owner_email,
            last_logon_account,
            last_logon_timestamp,
            updated_at,
        ),
    )

    conn.commit()


# =========================================================
# MAIN
# =========================================================

def main():
    print("=" * 70)
    print("VulnWatch AI - Synchronisation Asset Owners")
    print("=" * 70)
    print()

    # -----------------------------------------------------
    # Tokens
    # -----------------------------------------------------

    print("Récupération du token Defender...")
    defender_token = get_access_token()

    print("Récupération du token Microsoft Graph...")
    graph_token = get_graph_token()

    # -----------------------------------------------------
    # DB
    # -----------------------------------------------------

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    ensure_asset_owners_table(conn)

    devices = get_devices(conn)

    print()

    if TEST_LIMIT is None:
        print("Mode : PARC COMPLET WINDOWS")
    else:
        print(f"Mode : TEST - {TEST_LIMIT} devices maximum")

    print(f"Devices à traiter : {len(devices):,}")
    print()

    stats = {
        "devices": 0,
        "owners": 0,
        "no_logon": 0,
        "no_graph": 0,
        "errors": 0,
    }

    try:
        for index, row in enumerate(devices, start=1):

            device_id = row["device_id"]
            device_name = row["device_name"]

            stats["devices"] += 1

            print(
                f"[{index}/{len(devices)}] "
                f"{device_name}"
            )

            try:
                # -------------------------------------------------
                # Defender /logonusers
                # -------------------------------------------------

                users = get_logon_users(
                    device_id,
                    defender_token,
                )

                if not users:
                    print("    Aucun utilisateur retourné.")
                    save_owner(conn, device_id, device_name, None, None, None, None)
                    stats["no_logon"] += 1
                    time.sleep(REQUEST_DELAY)
                    continue

                print(
                    f"    Utilisateurs Defender : {len(users)}"
                )

                # -------------------------------------------------
                # Sélection owner
                # -------------------------------------------------

                owner = select_owner(users)

                if not owner:
                    print(
                        "    Aucun utilisateur Interactive "
                        "exploitable."
                    )
                    save_owner(conn, device_id, device_name, None, None, None, None)
                    stats["no_logon"] += 1
                    time.sleep(REQUEST_DELAY)
                    continue

                account_name = str(
                    owner.get("accountName") or ""
                ).strip()

                last_logon_timestamp = owner.get("lastSeen")

                print(
                    f"    Compte candidat : {account_name}"
                )
                print(
                    f"    Dernière session : {last_logon_timestamp or 'N/A'}"
                )

                # -------------------------------------------------
                # Graph
                # -------------------------------------------------

                graph_user = lookup_graph_user(
                    account_name,
                    graph_token,
                )

                if not graph_user:
                    print(
                        "    Utilisateur introuvable dans Graph."
                    )
                    save_owner(
                        conn,
                        device_id,
                        device_name,
                        None,
                        None,
                        account_name,
                        last_logon_timestamp,
                    )
                    stats["no_graph"] += 1
                    time.sleep(REQUEST_DELAY)
                    continue

                owner_name = (
                    graph_user.get("displayName")
                    or account_name
                )

                owner_email = (
                    graph_user.get("mail")
                    or graph_user.get("userPrincipalName")
                    or ""
                )

                # -------------------------------------------------
                # Save
                # -------------------------------------------------

                save_owner(
                    conn,
                    device_id,
                    device_name,
                    owner_name,
                    owner_email,
                    account_name,
                    last_logon_timestamp,
                )

                stats["owners"] += 1

                print(
                    f"    Owner : {owner_name}"
                )
                print(
                    f"    Email : {owner_email}"
                )

            except requests.HTTPError as exc:
                print(
                    f"    HTTP ERROR : {exc}"
                )
                stats["errors"] += 1

            except requests.RequestException as exc:
                print(
                    f"    REQUEST ERROR : {exc}"
                )
                stats["errors"] += 1

            except Exception as exc:
                print(
                    f"    ERROR : {exc}"
                )
                stats["errors"] += 1

            time.sleep(REQUEST_DELAY)

    finally:
        conn.close()

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    print()
    print("=" * 70)
    print("Synchronisation terminée")
    print("=" * 70)
    print(
        f"Devices traités      : {stats['devices']:,}"
    )
    print(
        f"Owners trouvés       : {stats['owners']:,}"
    )
    print(
        f"Sans utilisateur     : {stats['no_logon']:,}"
    )
    print(
        f"Absent de Graph      : {stats['no_graph']:,}"
    )
    print(
        f"Erreurs              : {stats['errors']:,}"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()