"""
Télécharge depuis l'API NVD les fiches des CVE publiées depuis une date
(VULNWATCH_CPE_SINCE, AAAA-MM-JJ, défaut 2018-01-01) pour enregistrer
leurs produits vulnérables (configurations CPE) : les CVE importées
avant cette fonctionnalité n'en ont pas. Met aussi à jour les scores.

Reprend là où il s'était arrêté (curseur en base), sauf avec
VULNWATCH_CPE_RESTART=1. Termine par le recalcul des équipements
touchés selon NVD.
"""

import os
import sys
import time
from datetime import datetime, timezone, timedelta

from database import (
    initialize_database,
    bulk_save_nvd_discoveries,
    get_app_config,
    set_app_config
)
from collectors.nvd import fetch_recent_nvd_cves, PAGE_DELAY_SECONDS
from services.inventory_matcher import rebuild_all_matches
from services.jobs import report_progress


CURSOR_KEY = "nvd_cpe_sync_cursor"
MAX_WINDOW_DAYS = 119


def main():

    initialize_database()

    since = datetime.fromisoformat(
        os.getenv("VULNWATCH_CPE_SINCE", "2018-01-01")
    ).replace(tzinfo=timezone.utc)

    cursor = get_app_config(CURSOR_KEY)

    if cursor and os.getenv("VULNWATCH_CPE_RESTART") != "1":
        start = max(since, datetime.fromisoformat(cursor))
    else:
        start = since

    now = datetime.now(timezone.utc)
    windows = []

    while start < now:
        end = min(start + timedelta(days=MAX_WINDOW_DAYS), now)
        windows.append((start, end))
        start = end

    total = 0

    for index, (start, end) in enumerate(windows):

        report_progress(
            index,
            len(windows),
            f"CVE publiées du {start.date()} au {end.date()}",
            force=True
        )

        discoveries = fetch_recent_nvd_cves(start, end, "published")
        bulk_save_nvd_discoveries(discoveries)
        total += len(discoveries)

        set_app_config(CURSOR_KEY, end.isoformat())

        print(f"{start.date()} -> {end.date()} : {len(discoveries)} CVE")

        time.sleep(PAGE_DELAY_SECONDS)

    report_progress(
        len(windows), len(windows), "Comparaison avec l'inventaire logiciel",
        force=True
    )

    matched_cves, _ = rebuild_all_matches()

    print(f"Total : {total} CVE ; {matched_cves} CVE touchent le parc selon NVD")


if __name__ == "__main__":

    try:
        main()
    except Exception as error:
        print(f"[ERROR] {error}")
        sys.exit(1)
