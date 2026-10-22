"""
Import de l'inventaire logiciel de chaque machine, puis calcul des
équipements touchés selon NVD (services/inventory_matcher.py).

Source :
  - par défaut, l'API Defender (export SoftwareInventoryExport, via
    Azure CLI connecté, permission Software.Read.All) ;
  - VULNWATCH_INVENTORY_CSV=<chemin> : un fichier CSV au format du
    portail Defender (DeviceId, DeviceName, OSPlatform, OSVersion,
    SoftwareVendor, SoftwareName, SoftwareVersion, ProductCodeCpe, ...).
"""

import csv
import gzip
import json
import os
import sys
from pathlib import Path

from database import initialize_database, set_sync_state
from collectors.defender import (
    request_export,
    download_export_file,
    SOFTWARE_INVENTORY_EXPORT_URL
)
from services.inventory_matcher import (
    replace_software_inventory,
    rebuild_all_matches
)
from services.jobs import report_progress


SYNC_KEY = "software_inventory"
EXPORT_DIR = Path("data/defender_exports")


def _read_csv(path):

    # Le portail Defender exporte en UTF-8 avec BOM.
    with open(path, encoding="utf-8-sig", newline="") as source:
        yield from csv.DictReader(source)


def _read_defender_export():

    print("Demande de l'export d'inventaire à Defender...")

    export = request_export(
        sas_valid_hours=6,
        url=SOFTWARE_INVENTORY_EXPORT_URL
    )

    files = export["export_files"]

    print(f"Export généré le {export['generated_time']} : {len(files)} fichier(s)")

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    for index, url in enumerate(files, start=1):

        report_progress(
            index - 1,
            len(files),
            f"Téléchargement du fichier d'inventaire {index}/{len(files)}",
            force=True
        )

        destination = EXPORT_DIR / f"inventory_part_{index:05d}.json.gz"
        download_export_file(url, destination)

        with gzip.open(destination, "rt", encoding="utf-8-sig") as source:

            for line in source:

                line = line.strip()

                if not line:
                    continue

                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

        destination.unlink(missing_ok=True)


def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Inventaire logiciel et équipements touchés (NVD)")
    print("=" * 60)
    print()

    initialize_database()

    csv_path = os.getenv("VULNWATCH_INVENTORY_CSV")

    try:

        records = _read_csv(csv_path) if csv_path else _read_defender_export()

        rows, devices = replace_software_inventory(
            records,
            progress=lambda count: report_progress(
                None, None, f"{count:,} logiciels importés".replace(",", " ")
            )
        )

        print(f"Inventaire : {rows} ligne(s), {devices} machine(s)")

        report_progress(
            None, None, "Comparaison avec les produits vulnérables NVD", force=True
        )

        matched_cves, affected = rebuild_all_matches(
            progress=lambda done, total: report_progress(
                done, total, "Comparaison avec les produits vulnérables NVD"
            )
        )

    except Exception as error:

        print(f"[ERROR] {error}")
        set_sync_state(SYNC_KEY, "ERROR", str(error))
        sys.exit(1)

    finally:

        if csv_path:
            Path(csv_path).unlink(missing_ok=True)

    detail = (
        ("CSV : " if csv_path else "Defender : ")
        + f"{devices} machine(s), {rows} logiciel(s) ; "
        f"{matched_cves} CVE touchent le parc selon NVD"
    )

    print(detail)
    set_sync_state(SYNC_KEY, "OK", detail)


if __name__ == "__main__":
    main()
