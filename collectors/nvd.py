import os
import io
import gzip
import json
import re
import zipfile
import requests
import time
from datetime import datetime, timezone

from services.jobs import report_progress


NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

MAX_RETRIES = 4

RETRY_DELAYS = [
    30,
    60,
    120,
    240
]

# Clé API NVD optionnelle (jamais codée en dur — lue depuis la config
# en base par sync_nvd_feed.py, qui la passe ici via variable
# d'environnement du sous-processus, comme VULNWATCH_MAX_CVES pour
# enrich.py). Sans clé : 5 requêtes / 30s. Avec clé : 50 / 30s.
NVD_API_KEY = os.getenv("VULNWATCH_NVD_API_KEY")

# resultsPerPage max autorisé par l'API NVD 2.0.
RESULTS_PER_PAGE = 2000

# Délai entre deux pages pour rester sous la limite publique de 5
# requêtes / 30 secondes (sans clé API) — avec clé API, l'appelant
# peut se permettre un délai bien plus court, mais on reste prudent
# par défaut tant qu'aucune clé n'est configurée.
PAGE_DELAY_SECONDS = 6 if not NVD_API_KEY else 1


def fetch_nvd_cve(cve_id):

    params = {
        "cveId": cve_id
    }

    headers = _headers()

    for attempt in range(1, MAX_RETRIES + 1):

        try:

            print(
                f"    NVD request "
                f"(attempt {attempt}/{MAX_RETRIES})"
            )

            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=(10, 60)
            )

            if response.status_code == 404:
                return None

            if response.status_code in (
                429,
                500,
                502,
                503,
                504
            ):

                if attempt < MAX_RETRIES:

                    delay = RETRY_DELAYS[
                        attempt - 1
                    ]

                    print(
                        f"    NVD returned "
                        f"{response.status_code}. "
                        f"Retrying in {delay}s..."
                    )

                    time.sleep(delay)

                    continue

                response.raise_for_status()

            response.raise_for_status()

            data = response.json()

            vulnerabilities = data.get(
                "vulnerabilities",
                []
            )

            if not vulnerabilities:
                return None

            return parse_nvd_cve(
                vulnerabilities[0]["cve"]
            )

        except requests.exceptions.Timeout:

            if attempt < MAX_RETRIES:

                delay = RETRY_DELAYS[
                    attempt - 1
                ]

                print(
                    f"    Timeout. "
                    f"Retrying in {delay}s..."
                )

                time.sleep(delay)

            else:

                raise

        except requests.exceptions.ConnectionError:

            if attempt < MAX_RETRIES:

                delay = RETRY_DELAYS[
                    attempt - 1
                ]

                print(
                    f"    Connection error. "
                    f"Retrying in {delay}s..."
                )

                time.sleep(delay)

            else:

                raise


def parse_nvd_cve(cve):

    result = {
        "cvss_v3_score": None,
        "cvss_v3_severity": None,
        "cvss_v3_vector": None,

        "cvss_v4_score": None,
        "cvss_v4_severity": None,
        "cvss_v4_vector": None,

        "cwe": None,

        "nvd_description": None,
        "nvd_published": cve.get("published"),
        "nvd_last_modified": cve.get("lastModified"),

        "nvd_enriched_at": datetime.now(
            timezone.utc
        ).isoformat()
    }


    # =====================================================
    # DESCRIPTION
    # =====================================================

    descriptions = cve.get(
        "descriptions",
        []
    )

    for description in descriptions:

        if description.get("lang") == "en":

            result["nvd_description"] = (
                description.get("value")
            )

            break


    # =====================================================
    # CVSS 3.1
    # =====================================================

    cvss31 = cve.get(
        "metrics",
        {}
    ).get(
        "cvssMetricV31",
        []
    )

    if cvss31:

        metric = cvss31[0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        result["cvss_v3_score"] = (
            cvss_data.get("baseScore")
        )

        result["cvss_v3_severity"] = (
            cvss_data.get("baseSeverity")
        )

        result["cvss_v3_vector"] = (
            cvss_data.get("vectorString")
        )


    # =====================================================
    # CVSS 4.0
    # =====================================================

    cvss40 = cve.get(
        "metrics",
        {}
    ).get(
        "cvssMetricV40",
        []
    )

    if cvss40:

        metric = cvss40[0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        result["cvss_v4_score"] = (
            cvss_data.get("baseScore")
        )

        result["cvss_v4_severity"] = (
            cvss_data.get("baseSeverity")
        )

        result["cvss_v4_vector"] = (
            cvss_data.get("vectorString")
        )


    # =====================================================
    # CWE
    # =====================================================

    weaknesses = cve.get(
        "weaknesses",
        []
    )

    cwes = []

    for weakness in weaknesses:

        for description in weakness.get(
            "description",
            []
        ):

            value = description.get("value")

            if value:
                cwes.append(value)

    if cwes:

        result["cwe"] = ", ".join(
            sorted(set(cwes))
        )


    # =====================================================
    # PRODUITS VULNÉRABLES (configurations CPE)
    # =====================================================
    #
    # Servent à calculer, à partir de l'inventaire logiciel des
    # machines, les équipements touchés selon NVD (voir
    # services/inventory_matcher.py).

    result["cpe_matches"] = extract_cpe_matches(cve)


    return result


def split_cpe(criteria):
    """
    "cpe:2.3:a:vendor:product:version:..." -> liste des champs, en
    respectant les ":" échappés ("\\:") et en retirant les échappements.
    """

    parts = re.split(r"(?<!\\):", criteria or "")

    return [part.replace("\\", "") for part in parts]


def extract_cpe_matches(cve):
    """
    Produits marqués VULNÉRABLES dans les configurations NVD d'une CVE :
    [{"part", "vendor", "product", "version", "version_start_including",
    "version_start_excluding", "version_end_including",
    "version_end_excluding"}]. Les entrées "non vulnérables" (plateforme
    sur laquelle tourne le produit, ex. un OS) sont ignorées.
    """

    matches = []
    seen = set()

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):

                if not match.get("vulnerable"):
                    continue

                parts = split_cpe(match.get("criteria"))

                if len(parts) < 6:
                    continue

                entry = {
                    "part": parts[2],
                    "vendor": parts[3].lower(),
                    "product": parts[4].lower(),
                    "version": parts[5],
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding")
                }

                key = tuple(entry.values())

                if key not in seen:
                    seen.add(key)
                    matches.append(entry)

    return matches


def _headers():

    headers = {
        "User-Agent": "VulnWatch-AI/0.1"
    }

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    return headers


def _format_nvd_datetime(dt):
    """
    Format attendu par l'API NVD 2.0 pour pubStartDate/pubEndDate :
    ISO-8601 étendu, UTC, millisecondes à 3 chiffres.
    """

    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _get_cve_page(params, headers):
    """
    Une seule requête paginée vers l'API NVD 2.0, avec les mêmes
    retries (429/5xx/timeout/connexion) que fetch_nvd_cve().
    """

    for attempt in range(1, MAX_RETRIES + 1):

        try:

            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=(10, 60)
            )

            if response.status_code in (429, 500, 502, 503, 504):

                if attempt < MAX_RETRIES:

                    delay = RETRY_DELAYS[attempt - 1]

                    print(
                        f"    NVD returned {response.status_code}. "
                        f"Retrying in {delay}s..."
                    )

                    time.sleep(delay)

                    continue

                response.raise_for_status()

            response.raise_for_status()

            return response.json()

        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            # "Response ended prematurely" : la connexion est coupée en
            # plein transfert d'une grosse page (2000 CVE). Sans ce
            # retry, toute la synchro échouait sur une seule coupure.
            requests.exceptions.ChunkedEncodingError,
            # Réponse tronquée : JSON invalide.
            ValueError
        ):

            if attempt < MAX_RETRIES:

                delay = RETRY_DELAYS[attempt - 1]

                print(f"    Erreur réseau. Nouvelle tentative dans {delay}s...")

                time.sleep(delay)

            else:

                raise

    raise RuntimeError("Échec de la requête NVD après plusieurs tentatives.")


# Champs de date acceptés par l'API NVD 2.0 pour filtrer une fenêtre.
NVD_DATE_FIELDS = {
    "published": ("pubStartDate", "pubEndDate"),
    "modified": ("lastModStartDate", "lastModEndDate")
}


def _window_params(start_dt, end_dt, date_field):

    start_key, end_key = NVD_DATE_FIELDS[date_field]

    return {
        start_key: _format_nvd_datetime(start_dt),
        end_key: _format_nvd_datetime(end_dt)
    }


def count_nvd_cves(start_dt, end_dt, date_field="published"):
    """
    Nombre de CVE que NVD connaît sur la fenêtre, sans les télécharger
    (resultsPerPage=1, on ne lit que totalResults). Sert à comparer la
    base locale avec NVD jour par jour (voir nvd_audit.py).
    """

    params = dict(
        _window_params(start_dt, end_dt, date_field),
        resultsPerPage=1,
        startIndex=0
    )

    data = _get_cve_page(params, _headers())

    return data.get("totalResults", 0)


def fetch_recent_nvd_cves(start_dt, end_dt, date_field="published"):
    """
    Récupère TOUTES les CVE publiées par NVD entre start_dt et end_dt
    (datetimes timezone-aware, bornes incluses), toutes plateformes/
    tous éditeurs confondus — c'est le croisement avec l'inventaire
    XDR (defender_vulnerabilities) qui filtre ensuite ce qui est
    réellement pertinent pour l'environnement (voir sync_nvd_feed.py).

    Paginé (resultsPerPage/startIndex), avec une pause entre pages
    pour respecter la limite de débit NVD (5 requêtes/30s sans clé
    API, 50/30s avec — voir NVD_API_KEY).

    date_field="modified" : CVE dont la fiche NVD a été MODIFIÉE sur la
    fenêtre (score CVSS ajouté après coup, analyse terminée, ...), ce
    qui inclut aussi les nouvelles publications.

    Retourne une liste de tuples (cve_id, enrichment_dict), où
    enrichment_dict a le même format que parse_nvd_cve() — prêt pour
    database.save_nvd_discovery().
    """

    headers = _headers()

    results = []
    start_index = 0
    total_results = None

    params_base = dict(
        _window_params(start_dt, end_dt, date_field),
        resultsPerPage=RESULTS_PER_PAGE
    )

    while total_results is None or start_index < total_results:

        params = dict(params_base, startIndex=start_index)

        print(
            f"    NVD : page à partir de l'index {start_index}"
            + (f" / {total_results} au total" if total_results is not None else "")
        )

        data = _get_cve_page(params, headers)

        total_results = data.get("totalResults", 0)

        report_progress(
            min(start_index + RESULTS_PER_PAGE, total_results),
            total_results,
            "Téléchargement des CVE NVD"
        )

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if not cve_id:
                continue

            results.append(
                (cve_id, parse_nvd_cve(cve))
            )

        start_index += RESULTS_PER_PAGE

        if start_index < total_results:
            time.sleep(PAGE_DELAY_SECONDS)

    return results


def fetch_nvd_cve_record(cve_id):
    """
    Fiche NVD COMPLÈTE d'une CVE (brute, telle que renvoyée par l'API) :
    références, produits concernés (configurations CPE), toutes les
    métriques CVSS, statut d'analyse... Utilisée par l'onglet "CVE NVD"
    pour afficher le détail à la demande.

    Appel interactif : pas de longues pauses de retry comme pour les
    synchros (l'utilisateur attend), une seule nouvelle tentative.
    Retourne None si NVD ne connaît pas la CVE.
    """

    last_error = None

    for attempt in range(2):

        try:

            response = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers=_headers(),
                timeout=(10, 30)
            )

            if response.status_code == 404:
                return None

            response.raise_for_status()

            vulnerabilities = response.json().get("vulnerabilities", [])

            return vulnerabilities[0]["cve"] if vulnerabilities else None

        except (
            requests.exceptions.RequestException,
            ValueError
        ) as error:

            last_error = error
            time.sleep(2)

    raise RuntimeError(f"NVD injoignable : {last_error}")


def describe_nvd_record(cve):
    """
    Extrait d'une fiche NVD brute ce que l'interface affiche :
    statut, CWE, références, produits concernés et métriques CVSS.
    """

    weaknesses = sorted({
        description.get("value")
        for weakness in cve.get("weaknesses", [])
        for description in weakness.get("description", [])
        if description.get("value")
    })

    references = [
        {
            "url": reference.get("url"),
            "source": reference.get("source"),
            "tags": ", ".join(reference.get("tags", []))
        }
        for reference in cve.get("references", [])
    ]

    part_labels = {"a": "Application", "o": "Système", "h": "Matériel"}

    products = []

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):

                # cpe:2.3:<part>:<vendor>:<product>:<version>:...
                parts = split_cpe(match.get("criteria"))

                if len(parts) < 6:
                    continue

                bounds = []

                if match.get("versionStartIncluding"):
                    bounds.append(f">= {match['versionStartIncluding']}")
                if match.get("versionStartExcluding"):
                    bounds.append(f"> {match['versionStartExcluding']}")
                if match.get("versionEndIncluding"):
                    bounds.append(f"<= {match['versionEndIncluding']}")
                if match.get("versionEndExcluding"):
                    bounds.append(f"< {match['versionEndExcluding']}")

                version = parts[5] if parts[5] not in ("*", "-") else ""

                products.append({
                    "type": part_labels.get(parts[2], parts[2]),
                    "vendor": parts[3].replace("_", " "),
                    "product": parts[4].replace("_", " "),
                    "version": version or " ".join(bounds) or "toutes",
                    "vulnerable": "Oui" if match.get("vulnerable") else "Non"
                })

    metrics = []

    for key, label in (
        ("cvssMetricV40", "CVSS 4.0"),
        ("cvssMetricV31", "CVSS 3.1"),
        ("cvssMetricV30", "CVSS 3.0"),
        ("cvssMetricV2", "CVSS 2.0")
    ):
        for metric in cve.get("metrics", {}).get(key, []):

            data = metric.get("cvssData", {})

            metrics.append({
                "version": label,
                "source": metric.get("source"),
                "type": metric.get("type"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or metric.get("baseSeverity"),
                "vector": data.get("vectorString")
            })

    return {
        "status": cve.get("vulnStatus"),
        "source_identifier": cve.get("sourceIdentifier"),
        "weaknesses": weaknesses,
        "references": references,
        "products": products,
        "metrics": metrics
    }


def parse_nvd_feed_bytes(raw_bytes, filename=""):
    """
    Parse un fichier NVD téléchargé MANUELLEMENT (hors appli, par
    exemple via nvd.nist.gov/vuln/data-feeds ou directement l'API
    cves/2.0 dans un navigateur) et envoyé via l'onglet Veille --
    utile quand le poste qui fait tourner VulnWatch n'a pas d'accès
    sortant vers services.nvd.nist.gov (proxy, pare-feu...).

    Formats acceptés : JSON brut, ou compressé .gz/.zip (les flux
    officiels nvd.nist.gov/vuln/data-feeds sont distribués en
    .json.gz, un par année). La structure JSON attendue est celle de
    l'API NVD 2.0 : {"vulnerabilities": [{"cve": {...}}, ...]} -- un
    flux annuel "nvdcve-2.0-2020.json.gz" a exactement cette forme.

    Retourne une liste de tuples (cve_id, enrichment_dict), prête
    pour database.bulk_save_nvd_discoveries().
    """

    name = (filename or "").lower()

    if name.endswith(".gz"):

        raw_bytes = gzip.decompress(raw_bytes)

    elif name.endswith(".zip"):

        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as archive:

            json_names = [
                n for n in archive.namelist()
                if n.lower().endswith(".json")
            ]

            if not json_names:
                raise ValueError(
                    "Aucun fichier .json trouvé dans l'archive .zip."
                )

            raw_bytes = archive.read(json_names[0])

    elif raw_bytes[:2] == b"\x1f\x8b":

        # Magic bytes gzip : le fichier a peut-être été renommé sans
        # son extension .gz (ex: téléchargé puis renommé "export").
        raw_bytes = gzip.decompress(raw_bytes)

    try:

        data = json.loads(raw_bytes.decode("utf-8"))

    except (json.JSONDecodeError, UnicodeDecodeError) as error:

        raise ValueError(
            f"Fichier illisible, JSON attendu : {error}"
        )

    items = data.get("vulnerabilities")

    if items is None:

        raise ValueError(
            "Format non reconnu : clé \"vulnerabilities\" absente. "
            "Ce fichier doit provenir de nvd.nist.gov/vuln/data-feeds "
            "ou de l'API NVD 2.0 (cves/2.0)."
        )

    results = []

    for item in items:

        cve = item.get("cve", {})
        cve_id = cve.get("id")

        if not cve_id:
            continue

        results.append(
            (cve_id, parse_nvd_cve(cve))
        )

    return results
