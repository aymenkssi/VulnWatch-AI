import sqlite3
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "vulnwatch.db"


def severity_rank(value):
    value = str(value or "").upper().strip()
    return {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }.get(value, 0)


def highest_value(values):
    best = ""
    best_rank = 0

    for value in values:
        rank = severity_rank(value)
        if rank > best_rank:
            best = str(value or "")
            best_rank = rank

    return best or None


def ensure_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cisa_defender_exposure (
            cve_id TEXT PRIMARY KEY,
            affected_devices INTEGER NOT NULL,
            affected_products INTEGER NOT NULL,
            defender_severity TEXT,
            exploitability_level TEXT,
            security_update_available INTEGER,
            recommended_security_updates TEXT,
            recommended_security_update_ids TEXT,
            ransomware TEXT,
            generated_at TEXT NOT NULL
        )
    """)
    conn.commit()


def build_exposure():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    ensure_table(conn)

    generated_at = datetime.now(timezone.utc).isoformat()

    # IMPORTANT:
    # asset_owners is an INNER JOIN on purpose.
    # Devices without a resolved owner are considered personal /
    # non-attributed devices and are excluded from remediation exposure.
    rows = conn.execute("""
        SELECT
            d.cve_id,
            d.device_id,
            d.software_vendor,
            d.software_name,
            d.defender_severity,
            d.exploitability_level,
            d.security_update_available,
            d.recommended_security_update,
            d.recommended_security_update_id,
            v.known_ransomware
        FROM defender_vulnerabilities d
        INNER JOIN vulnerabilities v
            ON UPPER(d.cve_id) = UPPER(v.cve_id)
        INNER JOIN asset_owners ao
            ON ao.device_id = d.device_id
        WHERE v.source = 'CISA KEV'
          AND ao.owner_name IS NOT NULL
          AND TRIM(ao.owner_name) <> ''
          AND ao.owner_email IS NOT NULL
          AND TRIM(ao.owner_email) <> ''
          AND d.cve_id IS NOT NULL
    """).fetchall()

    grouped = {}

    for row in rows:
        cve_id = str(row["cve_id"]).strip().upper()

        item = grouped.setdefault(
            cve_id,
            {
                "devices": set(),
                "products": set(),
                "defender_severities": [],
                "exploitability": [],
                "updates_available": set(),
                "recommended_updates": set(),
                "recommended_update_ids": set(),
                "ransomware": row["known_ransomware"],
            },
        )

        if row["device_id"]:
            item["devices"].add(row["device_id"])

        vendor = str(row["software_vendor"] or "").strip()
        software = str(row["software_name"] or "").strip()

        if vendor or software:
            item["products"].add(
                f"{vendor}|{software}"
            )

        if row["defender_severity"]:
            item["defender_severities"].append(
                row["defender_severity"]
            )

        if row["exploitability_level"]:
            item["exploitability"].append(
                row["exploitability_level"]
            )

        item["updates_available"].add(
            1 if row["security_update_available"] else 0
        )

        if row["recommended_security_update"]:
            item["recommended_updates"].add(
                str(row["recommended_security_update"]).strip()
            )

        if row["recommended_security_update_id"]:
            item["recommended_update_ids"].add(
                str(row["recommended_security_update_id"]).strip()
            )

    conn.execute("DELETE FROM cisa_defender_exposure")

    insert_sql = """
        INSERT INTO cisa_defender_exposure (
            cve_id,
            affected_devices,
            affected_products,
            defender_severity,
            exploitability_level,
            security_update_available,
            recommended_security_updates,
            recommended_security_update_ids,
            ransomware,
            generated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    for cve_id, item in grouped.items():
        severity = highest_value(
            item["defender_severities"]
        )

        exploitability = None
        if item["exploitability"]:
            # Keep a deterministic single value.
            # Prefer the strongest observed Defender state.
            rank = {
                "EXPLOITISINWILD": 4,
                "EXPLOITISVERIFIED": 3,
                "EXPLOITISINKIT": 3,
                "NONE": 1,
            }

            exploitability = sorted(
                item["exploitability"],
                key=lambda x: rank.get(
                    str(x).upper().replace(" ", ""),
                    0
                ),
                reverse=True,
            )[0]

        update_available = (
            1 if 1 in item["updates_available"] else 0
        )

        recommended_updates = "; ".join(
            sorted(item["recommended_updates"])
        ) or None

        recommended_update_ids = "; ".join(
            sorted(item["recommended_update_ids"])
        ) or None

        conn.execute(
            insert_sql,
            (
                cve_id,
                len(item["devices"]),
                len(item["products"]),
                severity,
                exploitability,
                update_available,
                recommended_updates,
                recommended_update_ids,
                item["ransomware"],
                generated_at,
            ),
        )

    conn.commit()

    exposure_count = conn.execute("""
        SELECT COUNT(*)
        FROM cisa_defender_exposure
    """).fetchone()[0]

    affected_devices = conn.execute("""
        SELECT COALESCE(SUM(affected_devices), 0)
        FROM cisa_defender_exposure
    """).fetchone()[0]

    conn.close()

    print("=" * 70)
    print("VulnWatch AI - Build CISA Defender Exposure")
    print("=" * 70)
    print(f"CISA CVEs with owned-device exposure : {exposure_count:,}")
    print(f"Owned-device/CVE exposure total      : {affected_devices:,}")
    print("=" * 70)


if __name__ == "__main__":
    build_exposure()
