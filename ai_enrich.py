import os
import time
from services.jobs import report_progress

from database import (
    get_connection,
    initialize_database,
    get_exposure_context,
    update_ai_enrichment,
    update_ai_status
)

from services.ai_engine import (
    generate_ai_enrichment,
    is_ollama_available,
    AI_MODEL,
    OLLAMA_URL
)


# =========================================================
# CONFIGURATION
# =========================================================

MAX_CVES = int(
    os.getenv("VULNWATCH_AI_MAX_CVES", "10")
)

DELAY = float(
    os.getenv("VULNWATCH_AI_DELAY", "1")
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
            vendor,
            product,
            vulnerability_name,
            description,
            nvd_description,
            cvss_v3_score,
            cvss_v4_score,
            priority,
            risk_score,
            known_ransomware,
            ai_status,
            ai_attempts
        FROM vulnerabilities
        WHERE COALESCE(ai_status, 'PENDING') != 'OK'
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
            COALESCE(ai_status, 'PENDING') AS status,
            COUNT(*) AS total
        FROM vulnerabilities
        GROUP BY COALESCE(ai_status, 'PENDING')
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
    current_attempts = row["ai_attempts"] or 0

    # ---------------------------------------------
    # Already enriched
    # ---------------------------------------------

    if row["ai_status"] == "OK":

        print(
            f"[SKIP] {cve_id} - déjà analysée par l'IA"
        )

        return "SKIP"


    # ---------------------------------------------
    # Local LLM enrichment
    # ---------------------------------------------

    try:

        exposure = get_exposure_context(cve_id)

        enrichment = generate_ai_enrichment(
            dict(row),
            exposure
        )

        update_ai_enrichment(
            cve_id,
            enrichment
        )

        update_ai_status(
            cve_id,
            "OK",
            current_attempts + 1
        )

        print(
            f"[OK] {cve_id} - confiance={enrichment.get('ai_confidence')}"
        )

        return "OK"

    except Exception as error:

        update_ai_status(
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
    print("VulnWatch AI - Enrichissement par LLM local (Ollama)")
    print("=" * 60)
    print()

    initialize_database()

    if not is_ollama_available():

        print(
            f"[ERREUR] Impossible de joindre Ollama sur {OLLAMA_URL}."
        )

        print(
            "Vérifiez qu'Ollama est démarré "
            f"(`ollama serve`) et que le modèle '{AI_MODEL}' "
            f"est disponible (`ollama pull {AI_MODEL}`)."
        )

        print()

        return

    rows = get_cves_to_enrich(
        MAX_CVES
    )

    if not rows:

        print(
            "Aucune CVE en attente d'analyse IA."
        )

        print()

        counts = get_status_counts()

        for status, total in counts.items():

            print(
                f"{status:12} : {total}"
            )

        return


    print(
        f"Modèle : {AI_MODEL} ({OLLAMA_URL})"
    )

    print(
        f"CVEs sélectionnées : {len(rows)}"
    )

    print(
        f"Délai entre requêtes : {DELAY}s"
    )

    print()


    counters = {
        "OK": 0,
        "SKIP": 0,
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

        report_progress(index - 1, len(rows), f"Analyse de {cve_id}")

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

            time.sleep(DELAY)


    # =====================================================
    # SUMMARY
    # =====================================================

    print()
    print("=" * 60)
    print("Enrichissement IA terminé")
    print("=" * 60)
    print()

    print(
        f"[OK]       {counters['OK']}"
    )

    print(
        f"[SKIP]     {counters['SKIP']}"
    )

    print(
        f"[ERROR]    {counters['ERROR']}"
    )

    print()

    counts = get_status_counts()

    print("Statut de la base :")
    print()

    for status, total in counts.items():

        print(
            f"{status:12} : {total}"
        )

    print()


if __name__ == "__main__":
    main()
