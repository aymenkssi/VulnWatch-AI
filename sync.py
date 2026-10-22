import sys

from database import (
    initialize_database,
    save_vulnerability,
    set_sync_state,
    get_enrichment_integrity_snapshot,
    get_cvss_lookup
)
from collectors.cisa import fetch_cisa_kev
from services.risk_engine import calculate_risk


SYNC_KEY = "cisa_kev"


def main():

    print()
    print("=" * 50)
    print("VulnWatch AI - Vulnerability Synchronization")
    print("=" * 50)
    print()

    initialize_database()

    # ---------------------------------------------------------------
    # Garde-fou anti-écrasement : on prend une photo du nombre de CVE
    # déjà enrichies (NVD/IA) AVANT le sync. save_vulnerability() ne
    # doit toucher que les colonnes CISA (voir database.py) ; si ces
    # compteurs baissent après le sync, quelque chose a régressé et on
    # le signale au lieu de rapporter un succès silencieux.
    # ---------------------------------------------------------------

    before = get_enrichment_integrity_snapshot()

    try:
        vulnerabilities = fetch_cisa_kev()
    except Exception as e:
        print()
        print(f"[ERROR] Unable to download CISA KEV: {e}")

        set_sync_state(
            SYNC_KEY,
            "ERROR",
            str(e)
        )

        sys.exit(1)

    print(f"{len(vulnerabilities)} vulnerabilities found")
    print()

    print("Processing vulnerabilities...")

    counters = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    # Le flux CISA KEV brut n'a ni CVSS ni date de publication NVD :
    # sans ce lookup, calculate_risk() plafonnerait TOUJOURS à MEDIUM
    # pour toute CVE déjà enrichie, écrasant sa priorité CRITICAL/HIGH
    # à chaque resynchro périodique (voir get_cvss_lookup()).
    cvss_lookup = get_cvss_lookup()

    for vulnerability in vulnerabilities:

        enrichment = cvss_lookup.get(vulnerability.get("cveID"))

        if enrichment:

            vulnerability.setdefault(
                "cvss_v3_score", enrichment["cvss_v3_score"]
            )
            vulnerability.setdefault(
                "cvss_v4_score", enrichment["cvss_v4_score"]
            )
            vulnerability.setdefault(
                "nvd_published", enrichment["nvd_published"]
            )

        score, priority, reasons = calculate_risk(vulnerability)

        vulnerability["risk_score"] = score
        vulnerability["priority"] = priority

        save_vulnerability(vulnerability)

        counters[priority] += 1

    print()
    print("Synchronization completed successfully.")
    print()

    print("Risk distribution:")
    print(f"  CRITICAL : {counters['CRITICAL']}")
    print(f"  HIGH     : {counters['HIGH']}")
    print(f"  MEDIUM   : {counters['MEDIUM']}")
    print(f"  LOW      : {counters['LOW']}")

    print()

    # ---------------------------------------------------------------
    # Vérification post-sync : l'enrichissement NVD/IA ne doit jamais
    # baisser à cause d'une synchronisation CISA. On compare à la
    # photo prise avant le sync.
    # ---------------------------------------------------------------

    after = get_enrichment_integrity_snapshot()

    nvd_lost = before["nvd_ok"] - after["nvd_ok"]
    ai_lost = before["ai_ok"] - after["ai_ok"]

    if nvd_lost > 0 or ai_lost > 0:

        detail = (
            f"{len(vulnerabilities)} vulnérabilités traitées, mais "
            f"ALERTE : enrichissement perdu pendant le sync "
            f"(NVD: -{max(nvd_lost, 0)}, IA: -{max(ai_lost, 0)}). "
            f"save_vulnerability() a peut-être écrasé des colonnes "
            f"NVD/IA - vérifier database.py."
        )

        print("=" * 50)
        print("[ALERTE] Enrichissement NVD/IA perdu pendant le sync !")
        print(f"  NVD enrichies avant : {before['nvd_ok']}")
        print(f"  NVD enrichies après : {after['nvd_ok']}")
        print(f"  IA enrichies avant  : {before['ai_ok']}")
        print(f"  IA enrichies après  : {after['ai_ok']}")
        print("=" * 50)
        print()

        set_sync_state(
            SYNC_KEY,
            "WARNING",
            detail
        )

        return

    print(
        f"Intégrité enrichissement OK "
        f"(NVD enrichies : {after['nvd_ok']}, "
        f"IA enrichies : {after['ai_ok']})"
    )
    print()

    set_sync_state(
        SYNC_KEY,
        "OK",
        f"{len(vulnerabilities)} vulnérabilités traitées "
        f"(NVD={after['nvd_ok']}, IA={after['ai_ok']} préservées)"
    )


if __name__ == "__main__":
    main()
