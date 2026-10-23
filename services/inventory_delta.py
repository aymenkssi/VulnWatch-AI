"""
Mise à jour de l'inventaire logiciel avec calcul du delta.

apply_inventory_update() remplace l'inventaire des machines données (ou
de tout le parc), recalcule les CVE touchant le parc selon NVD, puis
compare l'ancien et le nouvel inventaire de chaque machine :

  - logiciel ajouté / supprimé / version modifiée ;
  - machine apparue / retirée ;
  - pour chaque changement, CVE introduites (touchent la nouvelle
    version, pas l'ancienne) et CVE corrigées (l'inverse).

Les changements sont enregistrés dans inventory_changes (onglet
Inventaire > Changements). Au tout premier import (inventaire vide),
rien n'est enregistré : c'est la référence de départ.
"""

from collections import defaultdict
from datetime import datetime, timezone

from database import get_connection, record_inventory_changes
from services.inventory_matcher import rebuild_all_matches


_ROW_COLUMNS = (
    "device_id, device_name, software_vendor, software_name, "
    "software_version, cpe_vendor, cpe_product"
)


def _load_rows(conn, device_ids=None):
    """{device_id: [row]} de l'inventaire actuel (toutes les machines si None)."""

    rows = defaultdict(list)

    if device_ids is None:
        cursor = conn.execute(f"SELECT {_ROW_COLUMNS} FROM software_inventory")
        for row in cursor:
            rows[row["device_id"]].append(dict(row))
        return rows

    device_ids = list(device_ids)

    for start in range(0, len(device_ids), 900):
        chunk = device_ids[start:start + 900]
        placeholders = ", ".join("?" for _ in chunk)
        for row in conn.execute(
            f"SELECT {_ROW_COLUMNS} FROM software_inventory "
            f"WHERE device_id IN ({placeholders})",
            chunk
        ):
            rows[row["device_id"]].append(dict(row))

    return rows


def _load_matches(conn):
    """{(cpe_vendor, cpe_product, version): {cve_id}}."""

    matches = defaultdict(set)

    for row in conn.execute(
        "SELECT cve_id, cpe_vendor, cpe_product, software_version "
        "FROM inventory_cve_matches"
    ):
        matches[(row[1], row[2], row[3])].add(row[0])

    return matches


def _software_map(rows):
    """{(éditeur, logiciel): {version: (cpe_vendor, cpe_product)}}."""

    software = defaultdict(dict)

    for row in rows:
        key = (row["software_vendor"] or row["cpe_vendor"], row["software_name"] or row["cpe_product"])
        software[key][row["software_version"]] = (row["cpe_vendor"], row["cpe_product"])

    return software


def _cves(matches, versions):

    found = set()

    for version, (vendor, product) in versions.items():
        found |= matches.get((vendor, product, version), set())

    return found


def _critical(conn, cve_ids):
    """CVE critiques (CVSS 3.1, sinon 4.0) parmi cve_ids."""

    cve_ids = list(cve_ids)
    critical = set()

    for start in range(0, len(cve_ids), 900):
        chunk = cve_ids[start:start + 900]
        placeholders = ", ".join("?" for _ in chunk)
        critical.update(
            row[0] for row in conn.execute(
                f"""
                SELECT cve_id FROM vulnerabilities
                WHERE cve_id IN ({placeholders})
                  AND UPPER(COALESCE(cvss_v3_severity, cvss_v4_severity)) = 'CRITICAL'
                """,
                chunk
            )
        )

    return critical


def apply_inventory_update(new_rows_by_device, removed_device_ids=(), full=False,
                           progress=None):
    """
    new_rows_by_device : {device_id: [tuple software_inventory]} (tuples de
    normalize_inventory_record) ; removed_device_ids : machines à retirer ;
    full=True : tout le parc est fourni, toute machine absente est retirée.

    progress(fait, total) suit le recalcul des correspondances NVD.

    Retourne {"devices_changed", "changes", "critical", "critical_cves",
    "matched_cves", "baseline"} où critical liste les changements qui
    introduisent au moins une CVE critique.
    """

    detected_at = datetime.now(timezone.utc).isoformat()

    conn = get_connection()

    known_devices = {
        row[0] for row in conn.execute("SELECT DISTINCT device_id FROM software_inventory")
    }

    if full:
        removed_device_ids = known_devices - set(new_rows_by_device)

    affected = set(new_rows_by_device) | set(removed_device_ids)

    # Aucune machine modifiée (cas le plus courant d'une vérification
    # delta) : rien à remplacer ni à recalculer.
    if not affected:
        matched_cves = conn.execute("SELECT COUNT(*) FROM inventory_cve_summary").fetchone()[0]
        conn.close()
        return {
            "devices_changed": 0, "changes": 0, "critical": [],
            "critical_cves": set(), "matched_cves": matched_cves,
            "baseline": not known_devices
        }

    old_rows = _load_rows(conn, None if full else affected)
    old_matches = _load_matches(conn)

    # --- Remplacement de l'inventaire des machines concernées ----------
    conn.execute("BEGIN")

    if full:
        conn.execute("DELETE FROM software_inventory")
    else:
        conn.executemany(
            "DELETE FROM software_inventory WHERE device_id = ?",
            [(device_id,) for device_id in affected]
        )

    conn.executemany(
        "INSERT INTO software_inventory VALUES "
        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [row for rows in new_rows_by_device.values() for row in rows]
    )
    conn.commit()
    conn.close()

    matched_cves, _ = rebuild_all_matches(progress=progress)

    conn = get_connection()
    new_matches = _load_matches(conn)
    new_rows = _load_rows(conn, new_rows_by_device.keys())

    # --- Delta ------------------------------------------------------------
    baseline = not known_devices
    changes = []

    for device_id in sorted(affected):

        before = old_rows.get(device_id, [])
        after = new_rows.get(device_id, [])

        device_name = next(
            (row["device_name"] for row in after + before if row["device_name"]),
            None
        )

        old_software = _software_map(before)
        new_software = _software_map(after)

        if device_id not in known_devices:

            introduced = _cves(new_matches, {
                version: cpe
                for versions in new_software.values()
                for version, cpe in versions.items()
            })

            changes.append({
                "device_id": device_id, "device_name": device_name,
                "change_type": "device_added",
                "new_version": f"{len(after)} logiciel(s)",
                "cves_introduced": sorted(introduced)
            })
            continue

        if not after:

            changes.append({
                "device_id": device_id, "device_name": device_name,
                "change_type": "device_removed",
                "old_version": f"{len(before)} logiciel(s)"
            })
            continue

        for software in sorted(set(old_software) | set(new_software), key=str):

            old_versions = old_software.get(software, {})
            new_versions = new_software.get(software, {})

            if set(old_versions) == set(new_versions):
                continue

            if not old_versions:
                change_type = "added"
            elif not new_versions:
                change_type = "removed"
            else:
                change_type = "updated"

            cves_old = _cves(old_matches, old_versions)
            cves_new = _cves(new_matches, new_versions)

            changes.append({
                "device_id": device_id, "device_name": device_name,
                "change_type": change_type,
                "software_vendor": software[0],
                "software_name": software[1],
                "old_version": ", ".join(sorted(old_versions)) or None,
                "new_version": ", ".join(sorted(new_versions)) or None,
                "cves_introduced": sorted(cves_new - cves_old),
                "cves_fixed": sorted(cves_old - cves_new)
            })

    critical = _critical(
        conn,
        {cve for change in changes for cve in change.get("cves_introduced") or []}
    )

    conn.close()

    for change in changes:
        change["detected_at"] = detected_at
        change["critical_introduced"] = len(
            set(change.get("cves_introduced") or []) & critical
        )

    if not baseline:
        record_inventory_changes(changes)

    return {
        "devices_changed": len({c["device_id"] for c in changes}),
        "changes": 0 if baseline else len(changes),
        "critical": [] if baseline else [c for c in changes if c["critical_introduced"]],
        "critical_cves": critical,
        "matched_cves": matched_cves,
        "baseline": baseline
    }
