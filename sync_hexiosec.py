import sys

from database import (
    initialize_database,
    get_hexiosec_config,
    is_hexiosec_configured,
    save_hexiosec_findings,
    save_hexiosec_assets,
    set_sync_state
)
from collectors.hexiosec import (
    fetch_hexiosec_risks,
    normalize_risk,
    fetch_hexiosec_assets,
    normalize_asset,
    ASSET_ENDPOINTS
)


SYNC_KEY = "hexiosec"


def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Synchronisation Hexiosec ASM (Attack Surface)")
    print("=" * 60)
    print()

    initialize_database()

    if not is_hexiosec_configured():

        print(
            "[SKIP] Hexiosec ASM non configuré "
            "(onglet Attack Surface)."
        )

        set_sync_state(
            SYNC_KEY,
            "ERROR",
            "Non configuré (base_url / clé API / endpoint manquants)"
        )

        sys.exit(1)

    config = get_hexiosec_config()

    try:

        raw_risks = fetch_hexiosec_risks(config)

    except Exception as error:

        print(f"[ERROR] Échec de récupération des risques : {error}")

        set_sync_state(
            SYNC_KEY,
            "ERROR",
            str(error)
        )

        sys.exit(1)

    print(f"{len(raw_risks)} risque(s) récupéré(s) depuis Hexiosec ASM")

    normalized = [normalize_risk(record) for record in raw_risks]

    # On ignore les entrées sans identifiant exploitable (impossible
    # de faire l'upsert / le suivi dans le temps sans clé stable).
    normalized = [
        finding for finding in normalized
        if finding.get("external_id")
    ]

    skipped = len(raw_risks) - len(normalized)

    if skipped:
        print(
            f"[WARN] {skipped} risque(s) ignoré(s) (pas d'identifiant "
            "exploitable dans la réponse API)"
        )

    saved = save_hexiosec_findings(normalized)

    print(f"{saved} risque(s) enregistré(s) en base")
    print()

    # =====================================================
    # INVENTAIRE DES ACTIFS (domaines, IP, services, composants)
    # =====================================================

    asset_totals = {}
    asset_errors = []

    for asset_type in ASSET_ENDPOINTS:

        try:

            raw_assets = fetch_hexiosec_assets(config, asset_type)

        except Exception as error:

            print(
                f"[ERROR] Échec de récupération des actifs "
                f"{asset_type} : {error}"
            )

            asset_errors.append(asset_type)

            continue

        normalized_assets = [
            normalize_asset(record, asset_type)
            for record in raw_assets
        ]

        saved_assets = save_hexiosec_assets(normalized_assets)

        asset_totals[asset_type] = saved_assets

        print(f"{asset_type} : {saved_assets} actif(s) enregistré(s)")

    print()

    assets_summary = ", ".join(
        f"{asset_type}={total}"
        for asset_type, total in asset_totals.items()
    )

    detail = (
        f"{saved} risque(s) synchronisé(s)"
        + (f", {skipped} ignoré(s)" if skipped else "")
        + (f" — Actifs : {assets_summary}" if assets_summary else "")
        + (
            f" — Échec récupération actifs : {', '.join(asset_errors)}"
            if asset_errors
            else ""
        )
    )

    set_sync_state(
        SYNC_KEY,
        "OK" if not asset_errors else "WARNING",
        detail
    )


if __name__ == "__main__":
    main()
