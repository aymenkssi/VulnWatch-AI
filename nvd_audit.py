"""
État de la base NVD et rattrapage des CVE manquantes.

Pour chaque jour des N derniers jours (UTC), compare le nombre de CVE
publiées selon l'API NVD (count_nvd_cves : une requête légère par jour,
sans télécharger les CVE) avec le nombre de CVE de la base publiées ce
jour-là. Le rapport est enregistré en base et affiché dans l'onglet
Veille.

Pour chaque jour, le rapport indique aussi combien de CVE ont leurs
produits vulnérables NVD (CPE) et combien sont "à compléter" (importées
avant l'enregistrement des produits).

Avec VULNWATCH_AUDIT_FIX=1, TOUS les jours de la période sont
retéléchargés (CVE publiées ce jour-là) et enregistrés avec leurs
produits, puis recomptés : en plus des CVE manquantes ou à compléter,
cela met à jour les CVE dont NVD a déclaré ou corrigé les produits
vulnérables après leur enregistrement (ex. CVE publiée sans produits,
analysée par NVD une heure plus tard). Une page d'API par jour en
général : moins d'une minute pour 30 jours avec une clé API.
Le rattrapage n'envoie pas d'alerte e-mail (il peut ramener beaucoup de
CVE d'un coup) : les CVE rattrapées présentes sur le parc sont listées
dans le rapport et visibles dans l'onglet Veille.

Variables d'environnement :
  VULNWATCH_AUDIT_DAYS : nombre de jours à vérifier (défaut 30)
  VULNWATCH_AUDIT_FIX  : "1" pour rattraper les jours incomplets
"""

import os
import sys
import time
from datetime import datetime, timezone, timedelta

from database import (
    initialize_database,
    bulk_save_nvd_discoveries,
    count_cves_by_published_day,
    get_known_cve_ids,
    get_cve_ids_present_in_defender,
    set_nvd_audit_report
)
from collectors.nvd import (
    count_nvd_cves,
    fetch_recent_nvd_cves,
    PAGE_DELAY_SECONDS
)
from services.jobs import report_progress
from services.inventory_matcher import refresh_matches_for_cves
from database import get_inventory_matched_cve_ids


AUDIT_DAYS = int(os.getenv("VULNWATCH_AUDIT_DAYS", "30"))
FIX = os.getenv("VULNWATCH_AUDIT_FIX") == "1"


def _day_bounds(day):

    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1) - timedelta(milliseconds=1)

    return start, min(end, datetime.now(timezone.utc))


def _count_nvd_by_day(days, step, total_steps):

    counts = {}

    for day in days:

        report_progress(
            step,
            total_steps,
            f"Comptage NVD du {day.isoformat()}",
            force=True
        )

        start, end = _day_bounds(day)
        counts[day.isoformat()] = count_nvd_cves(start, end)

        step += 1
        time.sleep(PAGE_DELAY_SECONDS)

    return counts, step


def _build_rows(days, nvd_counts):

    local_counts = count_cves_by_published_day(days[0], days[-1])
    empty = {"total": 0, "with_cpe": 0, "unchecked": 0}

    rows = []

    for day in days:

        key = day.isoformat()
        nvd = nvd_counts[key]
        local = local_counts.get(key, empty)

        rows.append({
            "day": key,
            "nvd": nvd,
            "local": local["total"],
            "missing": max(nvd - local["total"], 0),
            "with_cpe": local["with_cpe"],
            "unchecked": local["unchecked"]
        })

    return rows


def main():

    print()
    print("=" * 60)
    print(
        "VulnWatch AI - État de la base NVD"
        + (" et rattrapage" if FIX else "")
    )
    print("=" * 60)
    print()

    initialize_database()

    today = datetime.now(timezone.utc).date()
    days = [
        today - timedelta(days=offset)
        for offset in range(AUDIT_DAYS - 1, -1, -1)
    ]

    total_steps = len(days) * 2 if FIX else len(days)
    step = 0

    print(f"Comptage NVD jour par jour ({days[0]} -> {days[-1]})...")

    nvd_counts, step = _count_nvd_by_day(days, step, total_steps)

    rows = _build_rows(days, nvd_counts)
    gaps = [row for row in rows if row["missing"] > 0 or row["unchecked"] > 0]

    print(
        f"{len(gaps)} jour(s) incomplet(s), "
        f"{sum(row['missing'] for row in rows)} CVE manquante(s), "
        f"{sum(row['unchecked'] for row in rows)} CVE à compléter (produits)"
    )

    recovered = 0
    completed = 0
    updated = 0
    recovered_on_parc = []

    if FIX:

        for row in rows:

            report_progress(
                step,
                total_steps,
                f"Rattrapage du {row['day']} ({row['missing']} manquante(s), "
                f"{row['unchecked']} à compléter)",
                force=True
            )

            day = datetime.fromisoformat(row["day"]).date()
            start, end = _day_bounds(day)

            discoveries = fetch_recent_nvd_cves(start, end, "published")
            ids = [cve_id for cve_id, _ in discoveries]

            known = get_known_cve_ids(ids)
            new_ids = [cve_id for cve_id in ids if cve_id not in known]
            matched_before = get_inventory_matched_cve_ids(ids)

            bulk_save_nvd_discoveries(discoveries)

            recovered += len(new_ids)
            completed += row["unchecked"]
            updated += len(ids) - len(new_ids)

            # Produits à jour pour toutes les CVE du jour : équipements
            # touchés selon NVD recalculés pour elles.
            matched_after = refresh_matches_for_cves(ids)

            # Nouvelles sur le parc : CVE rattrapées présentes chez
            # Defender, et toute CVE du jour qui touche maintenant une
            # machine selon NVD alors qu'elle n'en touchait aucune.
            on_parc = set(get_cve_ids_present_in_defender(new_ids))
            on_parc |= matched_after - matched_before
            recovered_on_parc.extend(on_parc)

            print(
                f"  {row['day']} : {len(new_ids)} CVE rattrapée(s), "
                f"{len(ids) - len(new_ids)} mise(s) à jour, "
                f"{len(on_parc)} nouvelle(s) sur le parc"
            )

            step += 1
            time.sleep(PAGE_DELAY_SECONDS)

        # Nouveau comptage local après rattrapage (les comptes NVD ne
        # changent pas, inutile de les redemander).
        rows = _build_rows(days, nvd_counts)

    report_progress(total_steps, total_steps, "Terminé", force=True)

    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "days": AUDIT_DAYS,
        "fixed": FIX,
        "recovered": recovered,
        "completed": completed,
        "updated": updated,
        "recovered_on_parc": sorted(recovered_on_parc),
        "rows": rows
    }

    set_nvd_audit_report(report)

    print()
    print("Résumé :")
    print(f"  CVE NVD sur la période  : {sum(r['nvd'] for r in rows)}")
    print(f"  CVE en base             : {sum(r['local'] for r in rows)}")
    print(f"  CVE manquantes          : {sum(r['missing'] for r in rows)}")

    print(f"  CVE à compléter         : {sum(r['unchecked'] for r in rows)}")

    if FIX:
        print(f"  CVE rattrapées          : {recovered}")
        print(f"  CVE complétées (produits): {completed}")
        print(f"  dont présentes sur le parc : {len(recovered_on_parc)}")

    print()


if __name__ == "__main__":

    try:
        main()
    except Exception as error:
        print(f"[ERROR] {error}")
        sys.exit(1)
