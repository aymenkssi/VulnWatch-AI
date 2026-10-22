"""
Connexion aux API Microsoft (Defender for Endpoint, Microsoft Graph) avec
une application Entra ID (identifiant client + secret), au lieu du compte
Azure CLI d'un utilisateur : pas d'expiration au changement de mot de
passe, pas de MFA, droits limités à ce dont VulnWatch a besoin.

Configuration (onglet latéral « Application Azure ») stockée en base
(app_config). Les variables d'environnement VULNWATCH_AZURE_TENANT_ID,
VULNWATCH_AZURE_CLIENT_ID et VULNWATCH_AZURE_CLIENT_SECRET sont
prioritaires (pour ne pas stocker le secret en base).

Sans application configurée (ou désactivée), les synchros utilisent
Azure CLI comme avant (collectors/defender.py).
"""

import base64
import hashlib
import json
import os
import time

import requests

from database import get_app_config, set_app_config


DEFENDER_RESOURCE = "https://api.securitycenter.microsoft.com"
GRAPH_RESOURCE = "https://graph.microsoft.com"

# Permissions APPLICATION requises (consentement administrateur).
REQUIRED_ROLES = {
    DEFENDER_RESOURCE: {
        "Vulnerability.Read.All": "Export des vulnérabilités Defender (sync_defender.py)",
        "Software.Read.All": "Export de l'inventaire logiciel (sync_software_inventory.py)",
        "User.Read.All": "Utilisateurs connectés aux machines (sync_asset_owners.py)"
    },
    GRAPH_RESOURCE: {
        "User.Read.All": "Nom et e-mail des propriétaires (sync_asset_owners.py)"
    }
}

API_LABELS = {
    DEFENDER_RESOURCE: "Microsoft Defender for Endpoint (WindowsDefenderATP)",
    GRAPH_RESOURCE: "Microsoft Graph"
}

_CONFIG_KEYS = {
    "tenant_id": "azure_app_tenant_id",
    "client_id": "azure_app_client_id",
    "client_secret": "azure_app_client_secret",
    "enabled": "azure_app_enabled"
}

_ENV_KEYS = {
    "tenant_id": "VULNWATCH_AZURE_TENANT_ID",
    "client_id": "VULNWATCH_AZURE_CLIENT_ID",
    "client_secret": "VULNWATCH_AZURE_CLIENT_SECRET"
}

_token_cache = {}


# =========================================================
# CONFIGURATION
# =========================================================

def get_azure_app_config():
    """
    {"tenant_id", "client_id", "client_secret", "enabled",
    "secret_from_env"} : variables d'environnement prioritaires sur la base.
    """

    config = {}

    for name, key in _CONFIG_KEYS.items():
        config[name] = get_app_config(key) or ""

    config["secret_from_env"] = bool(os.getenv(_ENV_KEYS["client_secret"]))

    for name, env_key in _ENV_KEYS.items():
        if os.getenv(env_key):
            config[name] = os.getenv(env_key)

    config["enabled"] = config["enabled"] == "1"

    return config


def set_azure_app_config(tenant_id, client_id, client_secret, enabled):
    """Le secret n'est remplacé que s'il est renseigné (champ vide = inchangé)."""

    set_app_config(_CONFIG_KEYS["tenant_id"], (tenant_id or "").strip())
    set_app_config(_CONFIG_KEYS["client_id"], (client_id or "").strip())

    if client_secret:
        set_app_config(_CONFIG_KEYS["client_secret"], client_secret.strip())

    set_app_config(_CONFIG_KEYS["enabled"], "1" if enabled else "0")

    _token_cache.clear()


def clear_azure_app_config():

    for key in _CONFIG_KEYS.values():
        set_app_config(key, "")

    _token_cache.clear()


def is_azure_app_configured(config=None):

    config = config or get_azure_app_config()

    return bool(
        config["enabled"]
        and config["tenant_id"]
        and config["client_id"]
        and config["client_secret"]
    )


# =========================================================
# JETONS
# =========================================================

def request_app_token(resource, config=None, use_cache=True):
    """
    Jeton d'application (flux client credentials) pour `resource`.
    Mis en cache jusqu'à 5 minutes avant son expiration ; use_cache=False
    (bouton « Tester ») en redemande toujours un.
    """

    config = config or get_azure_app_config()

    # Le secret fait partie de la clé : un secret modifié (ou erroné)
    # ne réutilise jamais un jeton obtenu avec l'ancien.
    cache_key = (
        config["tenant_id"],
        config["client_id"],
        hashlib.sha256(config["client_secret"].encode("utf-8")).hexdigest(),
        resource
    )
    cached = _token_cache.get(cache_key)

    if use_cache and cached and cached["expires_at"] - 300 > time.time():
        return cached["token"]

    response = requests.post(
        f"https://login.microsoftonline.com/{config['tenant_id']}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "scope": f"{resource}/.default"
        },
        timeout=30
    )

    if response.status_code != 200:

        try:
            body = response.json()
            message = body.get("error_description") or body.get("error")
        except ValueError:
            message = response.text[:300]

        raise RuntimeError(
            f"Entra ID a refusé l'application ({response.status_code}) : "
            f"{(message or '').splitlines()[0] if message else 'sans détail'}"
        )

    data = response.json()

    _token_cache[cache_key] = {
        "token": data["access_token"],
        "expires_at": time.time() + int(data.get("expires_in", 3600))
    }

    return data["access_token"]


def token_roles(token):
    """Permissions d'application accordées, lues dans le jeton (claim "roles")."""

    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError):
        return set()

    return set(claims.get("roles", []))


# =========================================================
# TEST DE CONNEXION
# =========================================================

# Appels légers pour vérifier qu'une permission fonctionne vraiment
# (une seule ligne demandée).
_TEST_CALLS = {
    (DEFENDER_RESOURCE, "Vulnerability.Read.All"):
        "https://api.security.microsoft.com/api/vulnerabilities?$top=1",
    (DEFENDER_RESOURCE, "Software.Read.All"):
        "https://api.security.microsoft.com/api/Software?$top=1",
    (GRAPH_RESOURCE, "User.Read.All"):
        "https://graph.microsoft.com/v1.0/users?$top=1&$select=id"
}


def test_azure_app(config=None):
    """
    Vérifie la connexion de l'application et chaque permission requise.
    Retourne une liste de {"api", "check", "ok", "detail"}.
    """

    config = config or get_azure_app_config()
    results = []

    for resource, roles in REQUIRED_ROLES.items():

        api = API_LABELS[resource]

        try:
            token = request_app_token(resource, config, use_cache=False)
        except Exception as error:
            results.append({
                "api": api, "check": "Connexion", "ok": False,
                "detail": str(error)
            })
            continue

        results.append({
            "api": api, "check": "Connexion", "ok": True,
            "detail": "Jeton obtenu"
        })

        granted = token_roles(token)

        for role, usage in roles.items():

            if role not in granted:
                results.append({
                    "api": api, "check": role, "ok": False,
                    "detail": f"Permission absente du jeton (ajouter la "
                              f"permission Application et accorder le "
                              f"consentement administrateur). Sert à : {usage}"
                })
                continue

            url = _TEST_CALLS.get((resource, role))

            if not url:
                results.append({
                    "api": api, "check": role, "ok": True,
                    "detail": f"Accordée. Sert à : {usage}"
                })
                continue

            try:
                response = requests.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30
                )
                ok = response.status_code == 200
                detail = (
                    f"Accordée, appel de test réussi. Sert à : {usage}" if ok
                    else f"Accordée mais l'appel de test renvoie "
                         f"{response.status_code} : {response.text[:200]}"
                )
            except requests.RequestException as error:
                ok = False
                detail = f"Appel de test impossible : {error}"

            results.append({"api": api, "check": role, "ok": ok, "detail": detail})

    return results
