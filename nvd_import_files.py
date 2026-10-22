"""
Import de fichiers NVD téléchargés à la main (flux annuels
nvdcve-2.0-AAAA.json.gz, JSON de l'API...), envoyés depuis l'onglet
Veille. Les CVE et leurs produits vulnérables (CPE) sont enregistrés,
puis les équipements touchés selon NVD sont recalculés.

VULNWATCH_NVD_FILES : chemins des fichiers, séparés par os.pathsep.
Les fichiers sont supprimés après import.
"""

import os
import sys
from pathlib import Path

from database import initialize_database, bulk_save_nvd_discoveries
from collectors.nvd import parse_nvd_feed_bytes
from services.inventory_matcher import rebuild_all_matches
from services.jobs import report_progress


def main():

    initialize_database()

    paths = [
        Path(value)
        for value in os.getenv("VULNWATCH_NVD_FILES", "").split(os.pathsep)
        if value
    ]

    total = 0
    errors = []

    for index, path in enumerate(paths):

        report_progress(index, len(paths), f"Import de {path.name}", force=True)

        try:

            discoveries = parse_nvd_feed_bytes(path.read_bytes(), path.name)
            imported = bulk_save_nvd_discoveries(discoveries)
            total += imported

            print(f"{path.name} : {imported} CVE importée(s)/mise(s) à jour")

        except Exception as error:

            errors.append(f"{path.name} : {error}")
            print(f"[ERROR] {path.name} : {error}")

        finally:

            path.unlink(missing_ok=True)

    if total:

        report_progress(
            None, None, "Comparaison avec l'inventaire logiciel", force=True
        )

        matched_cves, _ = rebuild_all_matches()

        print(f"{matched_cves} CVE touchent le parc selon NVD")

    print(f"Total : {total} CVE")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
