"""
Équipements touchés selon NVD, calculés par VulnWatch.

Defender décide lui-même, avec son propre catalogue, quels logiciels sont
touchés par quelles CVE (table defender_vulnerabilities). Ici, la
référence est NVD : pour chaque logiciel installé (inventaire importé par
sync_software_inventory.py), on compare l'éditeur, le produit et la
version aux produits déclarés vulnérables par NVD pour chaque CVE
(configurations CPE, table nvd_cpe_matches).

Le résultat est stocké par (produit, version installée) dans
inventory_cve_matches, puis résumé par CVE (nombre de machines) dans
inventory_cve_summary.

Limites (affichées dans l'interface) :
  - NVD n'a pas encore décrit les produits de toutes les CVE (retard
    d'analyse) : une CVE sans configuration CPE ne peut pas être reliée ;
  - le nom éditeur/produit doit correspondre à celui de NVD (Defender
    utilise en général les mêmes noms CPE, sinon la ligne n'est pas
    reliée) ;
  - les conditions de plateforme (ex. "seulement sous Windows") ne sont
    pas prises en compte : le résultat peut être plus large que la
    réalité.
"""

import re
from collections import defaultdict
from datetime import datetime, timezone

from database import get_connection, set_app_config, get_app_config


INVENTORY_MATCHED_AT_KEY = "inventory_matched_at"

_TOKEN = re.compile(r"\d+|[a-z]+")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


# =========================================================
# VERSIONS
# =========================================================

def version_key(version):
    """
    Clé de comparaison d'une version : suite de nombres et de mots
    ("12.2(55)SE3" -> 12, 2, 55, se, 3). Les zéros de fin sont ignorés
    pour que 1.0 == 1.0.0. Un mot est classé avant un nombre
    (1.0.rc1 < 1.0.1).
    """

    tokens = [
        (1, int(token)) if token.isdigit() else (0, token)
        for token in _TOKEN.findall(str(version or "").lower())
    ]

    while tokens and tokens[-1] == (1, 0):
        tokens.pop()

    return tuple(tokens)


def match_rule(cpe_row, installed_version):
    """
    Si la version installée est couverte par cette entrée NVD, retourne
    une description lisible de la règle (ex. ">= 7.4.0, < 7.4.3"),
    sinon None.
    """

    version = cpe_row["version"]

    if version not in (None, "", "*", "-"):

        if version_key(installed_version) == version_key(version):
            return f"= {version}"

        return None

    installed = version_key(installed_version)
    rule = []

    for column, operator, accept in (
        ("version_start_including", ">=", lambda c: c >= 0),
        ("version_start_excluding", ">", lambda c: c > 0),
        ("version_end_including", "<=", lambda c: c <= 0),
        ("version_end_excluding", "<", lambda c: c < 0)
    ):

        bound = cpe_row[column]

        if not bound:
            continue

        bound_key = version_key(bound)
        comparison = (installed > bound_key) - (installed < bound_key)

        if not accept(comparison):
            return None

        rule.append(f"{operator} {bound}")

    return ", ".join(rule) if rule else "toutes versions"


# =========================================================
# INVENTAIRE
# =========================================================

def _cpe_name(value):

    return re.sub(r"\s+", "_", str(value or "").strip().lower())


def normalize_inventory_record(record, imported_at):
    """
    Une ligne d'inventaire (export Defender SoftwareInventoryExport ou
    CSV du portail Defender, mêmes noms de colonnes) -> tuple pour
    software_inventory, ou None si inexploitable.

    L'éditeur/produit "CPE" vient de ProductCodeCpe
    ("editeur:produit:version") quand Defender le fournit, sinon de
    SoftwareVendor / SoftwareName.
    """

    device_id = str(record.get("DeviceId") or "").strip()

    if not device_id:
        return None

    cpe_vendor = cpe_product = None
    product_code = str(record.get("ProductCodeCpe") or "").strip()

    if product_code.count(":") >= 1:
        cpe_vendor, cpe_product = product_code.split(":")[:2]

    cpe_vendor = _cpe_name(cpe_vendor or record.get("SoftwareVendor"))
    cpe_product = _cpe_name(cpe_product or record.get("SoftwareName"))
    version = str(record.get("SoftwareVersion") or "").strip()

    if not cpe_vendor or not cpe_product or not version:
        return None

    device_name = _CONTROL_CHARS.sub(
        "", str(record.get("DeviceName") or "")
    ).strip()

    return (
        device_id,
        device_name or None,
        record.get("OSPlatform") or None,
        record.get("OSVersion") or None,
        record.get("OSArchitecture") or None,
        record.get("SoftwareVendor") or None,
        record.get("SoftwareName") or None,
        version,
        cpe_vendor,
        cpe_product,
        record.get("EndOfSupportStatus") or None,
        # Defender exporte "Invalid date" quand il n'a pas de date.
        (
            None if record.get("EndOfSupportDate") in (None, "", "Invalid date")
            else record.get("EndOfSupportDate")
        ),
        imported_at
    )


def replace_software_inventory(records, progress=None):
    """
    Remplace tout l'inventaire par `records` (itérable de dicts au format
    Defender). Préparé dans une table de travail puis échangé d'un coup :
    l'interface ne voit jamais un inventaire à moitié chargé.
    Retourne (lignes importées, machines distinctes).
    """

    imported_at = datetime.now(timezone.utc).isoformat()

    conn = get_connection()

    conn.execute("DROP TABLE IF EXISTS software_inventory_stage")
    conn.execute(
        "CREATE TABLE software_inventory_stage AS "
        "SELECT * FROM software_inventory WHERE 0"
    )

    insert_sql = (
        "INSERT INTO software_inventory_stage VALUES "
        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )

    batch = []
    count = 0

    for record in records:

        row = normalize_inventory_record(record, imported_at)

        if row is None:
            continue

        batch.append(row)
        count += 1

        if len(batch) >= 5000:

            conn.executemany(insert_sql, batch)
            batch.clear()

            if progress:
                progress(count)

    if batch:
        conn.executemany(insert_sql, batch)

    conn.commit()

    if count == 0:

        conn.execute("DROP TABLE software_inventory_stage")
        conn.commit()
        conn.close()

        raise RuntimeError("Aucune ligne d'inventaire exploitable.")

    conn.execute("BEGIN")
    conn.execute("DELETE FROM software_inventory")
    conn.execute(
        "INSERT INTO software_inventory SELECT * FROM software_inventory_stage"
    )
    conn.execute("DROP TABLE software_inventory_stage")
    conn.commit()

    devices = conn.execute(
        "SELECT COUNT(DISTINCT device_id) FROM software_inventory"
    ).fetchone()[0]

    conn.close()

    return count, devices


# =========================================================
# CORRESPONDANCES
# =========================================================

def _insert_matches(conn, matches):

    conn.executemany(
        """
        INSERT OR REPLACE INTO inventory_cve_matches (
            cve_id, cpe_vendor, cpe_product, software_version, rule
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        matches
    )


def _refresh_summary(conn, cve_ids=None):

    where = ""
    params = []

    if cve_ids is not None:

        placeholders = ", ".join("?" for _ in cve_ids)
        where = f"WHERE m.cve_id IN ({placeholders})"
        params = list(cve_ids)

        conn.execute(
            f"DELETE FROM inventory_cve_summary WHERE cve_id IN ({placeholders})",
            params
        )

    else:

        conn.execute("DELETE FROM inventory_cve_summary")

    conn.execute(
        f"""
        INSERT INTO inventory_cve_summary (
            cve_id, affected_devices, affected_products
        )
        SELECT
            m.cve_id,
            COUNT(DISTINCT i.device_id),
            COUNT(DISTINCT m.cpe_vendor || ':' || m.cpe_product)
        FROM inventory_cve_matches m
        JOIN software_inventory i
            ON i.cpe_vendor = m.cpe_vendor
            AND i.cpe_product = m.cpe_product
            AND i.software_version = m.software_version
        {where}
        GROUP BY m.cve_id
        """,
        params
    )


def rebuild_all_matches(progress=None):
    """
    Recalcule toutes les correspondances inventaire x NVD (après un
    import d'inventaire ou de données produits NVD).
    Retourne (CVE touchant le parc, machines touchées).
    """

    conn = get_connection()

    installed = defaultdict(set)

    for row in conn.execute(
        "SELECT DISTINCT cpe_vendor, cpe_product, software_version "
        "FROM software_inventory"
    ):
        installed[(row[0], row[1])].add(row[2])

    matches = []
    products = list(installed.items())

    for index, ((vendor, product), versions) in enumerate(products):

        if progress and index % 200 == 0:
            progress(index, len(products))

        for cpe_row in conn.execute(
            "SELECT * FROM nvd_cpe_matches WHERE vendor = ? AND product = ?",
            (vendor, product)
        ):
            for version in versions:

                rule = match_rule(cpe_row, version)

                if rule:
                    matches.append(
                        (cpe_row["cve_id"], vendor, product, version, rule)
                    )

    conn.execute("BEGIN")
    conn.execute("DELETE FROM inventory_cve_matches")
    _insert_matches(conn, matches)
    _refresh_summary(conn)
    conn.commit()

    result = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(affected_devices), 0) "
        "FROM inventory_cve_summary"
    ).fetchone()

    conn.close()

    set_app_config(
        INVENTORY_MATCHED_AT_KEY,
        datetime.now(timezone.utc).isoformat()
    )

    return result[0], result[1]


def refresh_matches_for_cves(cve_ids):
    """
    Recalcule les correspondances de quelques CVE seulement (nouvelles ou
    modifiées par la synchro NVD). Retourne l'ensemble des CVE de la liste
    qui touchent au moins une machine de l'inventaire.
    """

    cve_ids = list(dict.fromkeys(cve_ids))

    if not cve_ids:
        return set()

    conn = get_connection()

    has_inventory = conn.execute(
        "SELECT 1 FROM software_inventory LIMIT 1"
    ).fetchone()

    if not has_inventory:
        conn.close()
        return set()

    versions_cache = {}
    matched = set()

    for start in range(0, len(cve_ids), 500):

        chunk = cve_ids[start:start + 500]
        placeholders = ", ".join("?" for _ in chunk)
        matches = []

        for cpe_row in conn.execute(
            f"SELECT * FROM nvd_cpe_matches WHERE cve_id IN ({placeholders})",
            chunk
        ).fetchall():

            key = (cpe_row["vendor"], cpe_row["product"])

            if key not in versions_cache:
                versions_cache[key] = [
                    row[0] for row in conn.execute(
                        "SELECT DISTINCT software_version FROM software_inventory "
                        "WHERE cpe_vendor = ? AND cpe_product = ?",
                        key
                    )
                ]

            for version in versions_cache[key]:

                rule = match_rule(cpe_row, version)

                if rule:
                    matches.append(
                        (cpe_row["cve_id"], key[0], key[1], version, rule)
                    )
                    matched.add(cpe_row["cve_id"])

        conn.execute("BEGIN")
        conn.execute(
            f"DELETE FROM inventory_cve_matches WHERE cve_id IN ({placeholders})",
            chunk
        )
        _insert_matches(conn, matches)
        _refresh_summary(conn, chunk)
        conn.commit()

    conn.close()

    return matched


def get_inventory_matched_at():

    return get_app_config(INVENTORY_MATCHED_AT_KEY)
