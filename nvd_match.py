"""
Recalcule les équipements touchés selon NVD (inventaire logiciel x
produits vulnérables NVD), sans réimporter l'inventaire.
"""

import sys

from database import initialize_database
from services.inventory_matcher import rebuild_all_matches
from services.jobs import report_progress


def main():

    initialize_database()

    matched_cves, affected = rebuild_all_matches(
        progress=lambda done, total: report_progress(
            done, total, "Comparaison avec les produits vulnérables NVD"
        )
    )

    print(f"{matched_cves} CVE touchent le parc selon NVD")


if __name__ == "__main__":

    try:
        main()
    except Exception as error:
        print(f"[ERROR] {error}")
        sys.exit(1)
