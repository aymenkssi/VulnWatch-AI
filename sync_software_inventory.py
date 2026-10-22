"""
Import de l'inventaire logiciel de chaque machine, puis calcul des
équipements touchés selon NVD (services/inventory_matcher.py).

Source :
  - par défaut, l'API Advanced Hunting de Defender (table
    DeviceTvmSoftwareInventory, par lots de machines sous la limite de
    100 000 lignes ; permission AdvancedQuery.Read.All). Si elle est
    refusée : export SoftwareInventoryExport (Software.Read.All) ;
  - VULNWATCH_INVENTORY_SOURCE=export : export SoftwareInventoryExport ;
  - VULNWATCH_INVENTORY_DEVICE=<DeviceId> : une seule machine (Advanced
    Hunting), les autres machines ne sont pas touchées ;
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
    SOFTWARE_INVENTORY_EXPORT_URL,
    iter_hunting_inventory,
    hunting_inventory_for_devices
)
from services.inventory_matcher import (
    replace_software_inventory,
    replace_device_inventory,
    rebuild_all_matches
)
from services.jobs import report_progress


SYNC_KEY = "software_inventory"

# Actualisation d'une seule machine : état séparé, pour ne pas remplacer
# celui de l'import complet (date, nombre de machines, source).
DEVICE_SYNC_KEY = "software_inventory_device"

# Les exports de résultats Advanced Hunting (table
# DeviceTvmSoftwareInventory, mêmes colonnes que ce CSV) sont plafonnés à
# 100 000 lignes : un fichier de cette taille est très probablement
# tronqué (machines avec une partie seulement de leurs logiciels).
CSV_EXPORT_LIMIT = 100_000

_read_rows = {"count": 0}
EXPORT_DIR = Path("data/defender_exports")


def _read_csv(path):

    # Le portail Defender exporte en UTF-8 avec BOM.
    with open(path, encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            _read_rows["count"] += 1
            yield row


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


_fallback = {"used": False}


def _read_hunting_or_export():
    """
    Advanced Hunting par lots ; si l'API est refusée (permission
    AdvancedQuery.Read.All absente), export par fichiers en secours.
    """

    try:

        first = True

        for row in iter_hunting_inventory(
            progress=lambda done, total, devices, rows: report_progress(
                done, total,
                f"Advanced Hunting : lot {done}/{total} "
                f"({devices} machines, {rows} logiciels)",
                force=True
            )
        ):
            first = False
            yield row

    except RuntimeError as error:

        if not first or "(403)" not in str(error) and "(401)" not in str(error):
            raise

        print(
            f"[AVERTISSEMENT] Advanced Hunting refusé ({error}). "
            "Ajoutez la permission AdvancedQuery.Read.All à l'application "
            "Azure. Import par l'export de fichiers à la place."
        )

        _fallback["used"] = True

        yield from _read_defender_export()


def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Inventaire logiciel et équipements touchés (NVD)")
    print("=" * 60)
    print()

    initialize_database()

    csv_path = os.getenv("VULNWATCH_INVENTORY_CSV")
    device_id = os.getenv("VULNWATCH_INVENTORY_DEVICE")
    source_label = "CSV"

    try:

        if device_id:

            # Une seule machine : Advanced Hunting, remplacement de ses
            # seules lignes d'inventaire.
            report_progress(None, None, "Inventaire de la machine (Advanced Hunting)", force=True)

            records = hunting_inventory_for_devices([device_id])
            rows = replace_device_inventory(device_id, records)
            devices = 1
            source_label = "Defender (machine)"

            print(f"Machine {device_id} : {rows} logiciel(s)")

        else:

            if csv_path:
                records = _read_csv(csv_path)
            elif os.getenv("VULNWATCH_INVENTORY_SOURCE") == "export":
                records = _read_defender_export()
                source_label = "Defender (export)"
            else:
                records = _read_hunting_or_export()
                source_label = "Defender (Advanced Hunting)"

            rows, devices = replace_software_inventory(
                records,
                progress=lambda count: report_progress(
                    None, None, f"{count:,} logiciels importés".replace(",", " ")
                )
            )

            if _fallback["used"]:
                source_label = "Defender (export, Advanced Hunting refusé)"

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
        set_sync_state(DEVICE_SYNC_KEY if device_id else SYNC_KEY, "ERROR", str(error))
        sys.exit(1)

    finally:

        if csv_path:
            Path(csv_path).unlink(missing_ok=True)

    detail = (
        f"{source_label} : "
        + f"{devices} machine(s), {rows} logiciel(s) ; "
        f"{matched_cves} CVE touchent le parc selon NVD"
    )

    status = "OK"

    if csv_path and _read_rows["count"] == CSV_EXPORT_LIMIT:

        status = "WARNING"
        limit = f"{CSV_EXPORT_LIMIT:,}".replace(",", " ")

        detail = (
            f"Fichier CSV de {limit} lignes exactement : très probablement "
            "tronqué (limite des exports Advanced Hunting), certaines "
            "machines n'ont qu'une partie de leurs logiciels. Préférez "
            "« Importer l'inventaire depuis Defender » (API, sans limite) "
            "ou découpez l'export. "
            + detail
        )

    print(detail)
    set_sync_state(DEVICE_SYNC_KEY if device_id else SYNC_KEY, status, detail)


if __name__ == "__main__":
    main()
