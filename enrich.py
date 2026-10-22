import os
import time

from database import (
    get_connection,
    initialize_database,
    update_nvd_enrichment,
    update_nvd_status,
    set_sync_state
)


SYNC_KEY = "nvd_enrich"

from collectors.nvd import fetch_nvd_cve


# =========================================================
# CONFIGURATION
# =========================================================

MAX_CVES = int(
    os.getenv("VULNWATCH_MAX_CVES", "10")
)

DELAY = float(
    os.getenv("VULNWATCH_NVD_DELAY", "6")
)


# =========================================================
# SELECT CVEs
# =========================================================

def get_cves_to_enrich(limit):

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            cve_id,
            priority,
            risk_score,
            nvd_status,
            nvd_attempts
        FROM vulnerabilities
        WHERE COALESCE(nvd_enriched, 0) = 0
        ORDER BY
            CASE priority
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            risk_score DESC,
            date_added DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return rows


def get_status_counts():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            COALESCE(nvd_status, 'PENDING') AS status,
            COUNT(*) AS total
        FROM vulnerabilities
        GROUP BY COALESCE(nvd_status, 'PENDING')
        ORDER BY status
        """
    ).fetchall()

    conn.close()

    return {
        row["status"]: row["total"]
        for row in rows
    }


# =========================================================
# PROCESS
# =========================================================

def process_cve(row):

    cve_id = row["cve_id"]
    current_attempts = row["nvd_attempts"] or 0

    # ---------------------------------------------
    # Already enriched
    # ---------------------------------------------

    if row["nvd_status"] == "OK":

        print(
            f"[SKIP] {cve_id} - already enriched"
        )

        return "SKIP"


    # ---------------------------------------------
    # NVD lookup
    # ---------------------------------------------

    try:

        enrichment = fetch_nvd_cve(cve_id)

        # -----------------------------------------
        # Not found
        # -----------------------------------------

        if enrichment is None:

            update_nvd_status(
                cve_id,
                "NOT_FOUND",
                current_attempts + 1,
                "CVE not found in NVD"
            )

            print(
                f"[404] {cve_id} - absent from NVD"
            )

            return "404"


        # -----------------------------------------
        # Success
        # -----------------------------------------

        update_nvd_enrichment(
            cve_id,
            enrichment
        )

        update_nvd_status(
            cve_id,
            "OK",
            current_attempts + 1
        )

        print(
            f"[OK] {cve_id} "
            f"- CVSS={enrichment.get('cvss_v3_score')} "
            f"- {enrichment.get('cvss_v3_severity')}"
        )

        return "OK"


    except Exception as error:

        update_nvd_status(
            cve_id,
            "ERROR",
            current_attempts + 1,
            str(error)
        )

        print(
            f"[ERROR] {cve_id}: {error}"
        )

        return "ERROR"


# =========================================================
# MAIN
# =========================================================

def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - NVD Enrichment")
    print("=" * 60)
    print()

    initialize_database()

    rows = get_cves_to_enrich(
        MAX_CVES
    )

    if not rows:

        print(
            "No pending CVEs to enrich."
        )

        print()

        counts = get_status_counts()

        for status, total in counts.items():

            print(
                f"{status:12} : {total}"
            )

        set_sync_state(
            SYNC_KEY,
            "OK",
            "Aucune CVE en attente"
        )

        return


    print(
        f"CVEs selected: {len(rows)}"
    )

    print(
        f"NVD delay: {DELAY}s"
    )

    print()


    counters = {
        "OK": 0,
        "SKIP": 0,
        "404": 0,
        "ERROR": 0
    }


    # =====================================================
    # LOOP
    # =====================================================

    for index, row in enumerate(
        rows,
        start=1
    ):

        cve_id = row["cve_id"]

        print(
            f"[{index}/{len(rows)}] "
            f"{cve_id} "
            f"(priority={row['priority']}, "
            f"risk={row['risk_score']})"
        )


        result = process_cve(row)


        if result in counters:

            counters[result] += 1


        # ---------------------------------------------
        # Delay
        # ---------------------------------------------

        if index < len(rows):

            print(
                f"    Waiting {DELAY}s..."
            )

            time.sleep(DELAY)


    # =====================================================
    # SUMMARY
    # =====================================================

    print()
    print("=" * 60)
    print("NVD enrichment completed")
    print("=" * 60)
    print()

    print(
        f"[OK]       {counters['OK']}"
    )

    print(
        f"[SKIP]     {counters['SKIP']}"
    )

    print(
        f"[404]      {counters['404']}"
    )

    print(
        f"[ERROR]    {counters['ERROR']}"
    )

    print()

    counts = get_status_counts()

    print("Database status:")
    print()

    for status, total in counts.items():

        print(
            f"{status:12} : {total}"
        )

    print()

    set_sync_state(
        SYNC_KEY,
        "OK",
        f"OK={counters['OK']} SKIP={counters['SKIP']} "
        f"404={counters['404']} ERROR={counters['ERROR']}"
    )


if __name__ == "__main__":
    main()
