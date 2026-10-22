"""
Client pour l'API publique Hexiosec ASM (https://asm.hexiosec.com),
d'après la spec OpenAPI officielle (asm.hexiosec.com/api/openapi.yml) :

- Authentification : header "X-Hexiosec-API-Key: <clé>" (pas de préfixe
  "Bearer", contrairement à beaucoup d'API REST).
- Endpoint utilisé : GET /v1/scan_data/{scan_id}/risks
  (nécessite l'ID du scan, ex: celui de "SCC France" dans l'app
  Hexiosec — visible dans l'URL de la page du scan, ou via
  GET /v1/scans/by-org).
- Pagination : par `limit` / `offset` (pas de curseur). La dernière
  page est celle où le nombre d'éléments reçus est < limit demandé.
- Réponse : tableau JSON de ScanDataRiskResponse (severity parmi
  info/low/medium/high/critical, pas toujours de CVE associée — le
  cas échéant l'identifiant CVE apparaît dans `urn` ou `name`).
"""

import re

import requests


REQUEST_TIMEOUT = (10, 30)

PAGE_SIZE = 200
MAX_PAGES = 100

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _resolve_url(config):

    endpoint_path = config["endpoint_path"]

    if "{scan_id}" in endpoint_path:

        if not config.get("scan_id"):
            raise ValueError(
                "L'endpoint configuré nécessite un ID de scan "
                "(\"scan_id\"), non renseigné."
            )

        endpoint_path = endpoint_path.replace(
            "{scan_id}",
            config["scan_id"]
        )

    return config["base_url"].rstrip("/") + endpoint_path


def _headers(config):

    header_name = config.get("auth_header") or "X-Hexiosec-API-Key"
    prefix = config.get("auth_prefix") or ""

    return {
        header_name: f"{prefix}{config.get('api_key', '')}",
        "Accept": "application/json"
    }


def test_connection(config):
    """
    Appelle l'endpoint configuré avec limit=1 (une seule page, un seul
    risque) pour valider/ajuster base_url, endpoint_path, scan_id,
    auth_header et auth_prefix depuis l'interface. Retourne
    (ok, status_code, payload_ou_message).
    """

    try:
        url = _resolve_url(config)
    except ValueError as error:
        return False, None, str(error)

    try:

        response = requests.get(
            url,
            headers=_headers(config),
            params={"limit": 1, "offset": 0},
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as error:

        return False, None, str(error)

    try:
        payload = response.json()
    except ValueError:
        payload = response.text[:2000]

    return (response.status_code == 200), response.status_code, payload


def _fetch_paginated(url, headers):
    """
    Pagination limit/offset générique (commune à tous les endpoints
    /v1/scan_data/{scan_id}/... de l'API Hexiosec : risks, domains,
    ips, services, components). La dernière page est celle où le
    nombre d'éléments reçus est < PAGE_SIZE.
    """

    all_items = []
    offset = 0

    for _ in range(MAX_PAGES):

        response = requests.get(
            url,
            headers=headers,
            params={
                "limit": PAGE_SIZE,
                "offset": offset,
                "order": "created",
                "dir": "asc"
            },
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        page = response.json()

        if not isinstance(page, list):
            break

        all_items.extend(page)

        if len(page) < PAGE_SIZE:
            break

        offset += PAGE_SIZE

    return all_items


def fetch_hexiosec_risks(config):
    """
    Récupère tous les risques du scan configuré (endpoint configurable
    dans l'onglet Attack Surface). Retourne une liste de dicts bruts
    (ScanDataRiskResponse).
    """

    return _fetch_paginated(_resolve_url(config), _headers(config))


# Endpoints fixes de l'inventaire d'actifs (confirmés dans la spec
# OpenAPI officielle), en complément de l'endpoint "risques" qui reste
# configurable dans l'UI : ce sont ceux qui remplissent les tuiles
# "Discovery" (Domains, IPs, Services, Components) de l'app Hexiosec.
ASSET_ENDPOINTS = {
    "DOMAIN": "/v1/scan_data/{scan_id}/domains",
    "IP": "/v1/scan_data/{scan_id}/ips",
    "SERVICE": "/v1/scan_data/{scan_id}/services",
    "COMPONENT": "/v1/scan_data/{scan_id}/components"
}


def fetch_hexiosec_assets(config, asset_type):
    """
    Récupère tous les actifs d'un type donné (DOMAIN/IP/SERVICE/
    COMPONENT) pour le scan configuré. Retourne une liste de dicts
    bruts (ScanData{Domain,IP,Service,Component}Response).
    """

    if asset_type not in ASSET_ENDPOINTS:
        raise ValueError(f"Type d'actif inconnu : {asset_type}")

    if not config.get("scan_id"):
        raise ValueError(
            "L'ID de scan (\"scan_id\") est requis pour récupérer "
            "l'inventaire des actifs."
        )

    url = (
        config["base_url"].rstrip("/")
        + ASSET_ENDPOINTS[asset_type].replace("{scan_id}", config["scan_id"])
    )

    return _fetch_paginated(url, _headers(config))


def _extract_cve(record):

    for field in ("urn", "name"):

        value = record.get(field)

        if isinstance(value, str):

            match = CVE_PATTERN.search(value)

            if match:
                return match.group(0).upper()

    return None


def normalize_risk(record):
    """
    Normalise un risque brut (ScanDataRiskResponse) vers le schéma
    `hexiosec_findings` de VulnWatch.
    """

    # link_id identifie l'instance du risque sur cet actif précis
    # dans ce scan (contrairement à risk_node_id qui identifie le
    # *type* de risque et peut se répéter sur plusieurs actifs) :
    # c'est la clé stable à utiliser pour le suivi dans le temps.
    external_id = record.get("link_id") or record.get("risk_node_id")

    severity = record.get("severity")

    if isinstance(severity, str):
        severity = severity.strip().upper()

    return {
        "external_id": str(external_id) if external_id else None,
        "asset": record.get("asset_name"),
        "category": record.get("category"),
        "title": record.get("name"),
        "severity": severity,
        "cve_id": _extract_cve(record),
        "description": record.get("description"),
        "status": (
            "EXPLOIT_CONNU"
            if record.get("has_known_exploit")
            else "OUVERT"
        ),
        "first_seen": record.get("created"),
        "last_seen": record.get("last_seen")
    }


def _risk_counts(record):

    counts = record.get("risk_counts") or {}

    return {
        "risk_critical": counts.get("critical", 0) or 0,
        "risk_high": counts.get("high", 0) or 0,
        "risk_medium": counts.get("medium", 0) or 0,
        "risk_low": counts.get("low", 0) or 0,
        "risk_info": counts.get("info", 0) or 0
    }


def normalize_asset(record, asset_type):
    """
    Normalise un actif brut (ScanData{Domain,IP,Service,Component}
    Response) vers le schéma `hexiosec_assets` de VulnWatch. Le champ
    `detail` porte les infos spécifiques au type (port/protocole pour
    un service, vendeur/version pour un composant, pays pour une IP).
    """

    common = {
        "asset_type": asset_type,
        "external_id": record.get("id"),
        "created": record.get("created"),
        "last_seen": record.get("last_seen"),
        **_risk_counts(record)
    }

    if asset_type == "DOMAIN":

        return {
            **common,
            "name": record.get("name"),
            "detail": None
        }

    if asset_type == "IP":

        location = " / ".join(
            part for part in (record.get("city"), record.get("country"))
            if part
        )

        return {
            **common,
            "name": record.get("ip"),
            "detail": location or None
        }

    if asset_type == "SERVICE":

        host = record.get("host") or {}

        detail_parts = [
            part for part in (
                host.get("name"),
                (
                    f"{record.get('port')}/{record.get('protocol')}"
                    if record.get("port")
                    else None
                ),
                record.get("iana_name")
            )
            if part
        ]

        return {
            **common,
            "name": record.get("name") or host.get("name"),
            "detail": " · ".join(detail_parts) or None
        }

    if asset_type == "COMPONENT":

        detail_parts = [
            part for part in (record.get("vendor"), record.get("version"))
            if part
        ]

        return {
            **common,
            "name": record.get("name"),
            "detail": " ".join(detail_parts) or None
        }

    return {
        **common,
        "name": record.get("name"),
        "detail": None
    }
