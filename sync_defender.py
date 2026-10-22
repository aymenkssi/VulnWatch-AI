import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

from database import (
    get_connection,
    initialize_database
)

from collectors.defender import (
    request_export,
    download_export_file
)


IMPORT_DIR = Path("data/defender_exports")

BATCH_SIZE = 5000


# =========================================================
# CREATE STAGING TABLE
# =========================================================

def create_stage_table(conn):

    conn.execute("""
        DROP TABLE IF EXISTS defender_vulnerabilities_stage
    """)

    conn.execute("""
        CREATE TABLE defender_vulnerabilities_stage (

            device_id TEXT,
            device_name TEXT,

            os_platform TEXT,
            os_version TEXT,

            software_vendor TEXT,
            software_name TEXT,
            software_version TEXT,

            cve_id TEXT,

            defender_severity TEXT,

            cvss_score REAL,

            recommended_security_update TEXT,
            recommended_security_update_id TEXT,

            exploitability_level TEXT,

            security_update_available INTEGER,

            first_seen_timestamp TEXT,
            last_seen_timestamp TEXT,

            imported_at TEXT,

            UNIQUE (
                device_id,
                software_vendor,
                software_name,
                software_version,
                cve_id
            )
        )
    """)

    conn.commit()


# =========================================================
# PARSE DEFENDER RECORD
# =========================================================

def parse_record(
    record,
    imported_at
):

    cve_id = record.get("CveId")

    # Ignore records without a CVE
    if not cve_id:

        return None

    cve_id = str(cve_id).strip().upper()

    if not cve_id.startswith("CVE-"):

        return None

    return (
        record.get("DeviceId"),
        record.get("DeviceName"),

        record.get("OSPlatform"),
        record.get("OSVersion"),

        record.get("SoftwareVendor"),
        record.get("SoftwareName"),
        record.get("SoftwareVersion"),

        cve_id,

        record.get(
            "VulnerabilitySeverityLevel"
        ),

        record.get(
            "CvssScore"
        ),

        record.get(
            "RecommendedSecurityUpdate"
        ),

        record.get(
            "RecommendedSecurityUpdateId"
        ),

        record.get(
            "ExploitabilityLevel"
        ),

        int(
            bool(
                record.get(
                    "SecurityUpdateAvailable",
                    False
                )
            )
        ),

        record.get(
            "FirstSeenTimestamp"
        ),

        record.get(
            "LastSeenTimestamp"
        ),

        imported_at
    )


# =========================================================
# INSERT BATCH
# =========================================================

def insert_batch(
    conn,
    batch
):

    conn.executemany("""
        INSERT OR REPLACE INTO
        defender_vulnerabilities_stage (

            device_id,
            device_name,

            os_platform,
            os_version,

            software_vendor,
            software_name,
            software_version,

            cve_id,

            defender_severity,

            cvss_score,

            recommended_security_update,
            recommended_security_update_id,

            exploitability_level,

            security_update_available,

            first_seen_timestamp,
            last_seen_timestamp,

            imported_at

        )

        VALUES (
            ?, ?, ?, ?,
            ?, ?, ?,
            ?,
            ?,
            ?,
            ?, ?,
            ?,
            ?,
            ?, ?,
            ?
        )
    """, batch)

    conn.commit()


# =========================================================
# PROCESS FILE
# =========================================================

def process_file(
    file_path,
    conn,
    imported_at
):

    total_lines = 0
    valid_cves = 0

    batch = []

    print(
        f"Processing: {file_path.name}"
    )

    with gzip.open(
        file_path,
        "rt",
        encoding="utf-8-sig"
    ) as source:

        for line in source:

            total_lines += 1

            line = line.strip()

            if not line:
                continue

            try:

                record = json.loads(line)

            except json.JSONDecodeError as error:

                print(
                    f"    JSON error on line "
                    f"{total_lines}: {error}"
                )

                continue

            parsed = parse_record(
                record,
                imported_at
            )

            if parsed is None:

                continue

            batch.append(
                parsed
            )

            valid_cves += 1

            if len(batch) >= BATCH_SIZE:

                insert_batch(
                    conn,
                    batch
                )

                batch.clear()

    if batch:

        insert_batch(
            conn,
            batch
        )

        batch.clear()

    print(
        f"    Lines read : {total_lines:,}"
    )

    print(
        f"    CVE records: {valid_cves:,}"
    )

    return valid_cves


# =========================================================
# PROMOTE STAGING
# =========================================================

def promote_stage(conn):

    stage_count = conn.execute("""
        SELECT COUNT(*)
        FROM defender_vulnerabilities_stage
    """).fetchone()[0]

    if stage_count == 0:

        raise RuntimeError(
            "Staging table contains zero CVE records."
        )

    print()
    print(
        f"Staging CVE records: "
        f"{stage_count:,}"
    )

    print(
        "Replacing current Defender snapshot..."
    )

    conn.execute("""
        DELETE FROM defender_vulnerabilities
    """)

    conn.execute("""
        INSERT INTO defender_vulnerabilities (

            device_id,
            device_name,

            os_platform,
            os_version,

            software_vendor,
            software_name,
            software_version,

            cve_id,

            defender_severity,

            cvss_score,

            recommended_security_update,
            recommended_security_update_id,

            exploitability_level,

            security_update_available,

            first_seen_timestamp,
            last_seen_timestamp,

            imported_at

        )

        SELECT

            device_id,
            device_name,

            os_platform,
            os_version,

            software_vendor,
            software_name,
            software_version,

            cve_id,

            defender_severity,

            cvss_score,

            recommended_security_update,
            recommended_security_update_id,

            exploitability_level,

            security_update_available,

            first_seen_timestamp,
            last_seen_timestamp,

            imported_at

        FROM defender_vulnerabilities_stage
    """)

    conn.execute("""
        DROP TABLE defender_vulnerabilities_stage
    """)

    conn.commit()

    return stage_count


# =========================================================
# MAIN
# =========================================================

def main():

    print()
    print("=" * 70)
    print("VulnWatch AI - Defender Full Export")
    print("=" * 70)
    print()

    initialize_database()

    IMPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print(
        "Requesting Defender export..."
    )

    export = request_export(
        sas_valid_hours=6
    )

    print(
        f"Generated time: "
        f"{export['generated_time']}"
    )

    print(
        f"Files returned: "
        f"{len(export['export_files'])}"
    )

    print()

    conn = get_connection()

    create_stage_table(
        conn
    )

    imported_at = datetime.now(
        timezone.utc
    ).isoformat()

    total_records = 0

    try:

        total_files = len(
            export["export_files"]
        )

        for index, url in enumerate(
            export["export_files"],
            start=1
        ):

            filename = (
                IMPORT_DIR
                / f"part_{index:05d}.json.gz"
            )

            print(
                f"[{index}/{total_files}] "
                f"Downloading..."
            )

            download_export_file(
                url,
                filename
            )

            count = process_file(
                filename,
                conn,
                imported_at
            )

            total_records += count

            print(
                f"    Valid CVE records: "
                f"{count:,}"
            )

            print()

            filename.unlink(
                missing_ok=True
            )

        print(
            f"Total CVE records "
            f"in staging: {total_records:,}"
        )

        final_count = promote_stage(
            conn
        )

        print()
        print("=" * 70)
        print("Defender synchronization completed")
        print("=" * 70)
        print()

        print(
            f"Final Defender CVE records: "
            f"{final_count:,}"
        )

    except Exception:

        conn.rollback()

        print()
        print(
            "Synchronization failed."
        )

        print(
            "Existing Defender snapshot "
            "was NOT replaced."
        )

        raise

    finally:

        conn.close()


if __name__ == "__main__":
    main()
