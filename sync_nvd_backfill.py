import sys
from datetime import datetime, timezone, timedelta

from database import (
    initialize_database,
    set_sync_state,
    bulk_save_nvd_discoveries,
    get_nvd_backfill_start,
    get_nvd_backfill_cursor,
    set_nvd_backfill_cursor,
    is_nvd_backfill_done,
    mark_nvd_backfill_done,
    get_nvd_total_count
)
from collectors.nvd import fetch_recent_nvd_cves


SYNC_KEY = "nvd_historical_backfill"

# Même contrainte que sync_nvd_feed.py : l'API NVD 2.0 n'accepte pas
# une fenêtre pubStartDate/pubEndDate de plus de 120 jours.
MAX_WINDOW_DAYS = 119


def _parse_iso(value):

    dt = datetime.fromisoformat(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Téléchargement historique NVD (premier lancement)")
    print("=" * 60)
    print()

    initialize_database()

    if is_nvd_backfill_done():

        print("Historique NVD déjà intégralement téléchargé. Rien à faire.")

        set_sync_state(
            SYNC_KEY,
            "OK",
            f"Historique complet ({get_nvd_total_count()} CVE NVD en base)."
        )

        return

    # -----------------------------------------------------------
    # Ordre DESCENDANT : on part des CVE les plus récentes et on
    # recule fenêtre par fenêtre jusqu'à floor_dt (2020-01-01 par
    # défaut) -- les vulnérabilités les plus susceptibles de
    # concerner l'environnement actuel (et le croisement XDR) sont
    # ainsi disponibles dès les premières minutes, sans attendre que
    # tout l'historique depuis 2020 soit téléchargé.
    # -----------------------------------------------------------

    floor_dt = _parse_iso(get_nvd_backfill_start())
    now = datetime.now(timezone.utc)

    # Le "curseur" représente ici la borne la plus ANCIENNE déjà
    # couverte (on avance vers le passé). Tant qu'il n'existe pas,
    # on part de "maintenant".
    cursor_raw = get_nvd_backfill_cursor()
    cursor_dt = _parse_iso(cursor_raw) if cursor_raw else now

    if cursor_dt <= floor_dt:

        mark_nvd_backfill_done()

        print("Curseur déjà remonté jusqu'à la date de départ. Terminé.")

        set_sync_state(
            SYNC_KEY,
            "OK",
            f"Historique complet ({get_nvd_total_count()} CVE NVD en base)."
        )

        return

    total_span_days = max((now - floor_dt).days, 1)

    total_windows = max(
        -(-total_span_days // MAX_WINDOW_DAYS),  # ceil
        1
    )

    windows_done = max(
        total_windows - int(-(-(cursor_dt - floor_dt).days // MAX_WINDOW_DAYS)),
        0
    )

    print(
        f"Reprise en reculant à partir du {cursor_dt.date()} "
        f"vers le {floor_dt.date()} "
        f"(fenêtre {windows_done + 1}/{total_windows})"
    )
    print()

    try:

        while cursor_dt > floor_dt:

            window_end = cursor_dt

            window_start = max(
                window_end - timedelta(days=MAX_WINDOW_DAYS),
                floor_dt
            )

            windows_done += 1

            print(
                f"[Fenêtre {windows_done}/{total_windows}] "
                f"{window_start.date()} -> {window_end.date()} ..."
            )

            discoveries = fetch_recent_nvd_cves(window_start, window_end)

            # bulk_save_nvd_discoveries() (UNE connexion/transaction,
            # commit par lot de 500) plutôt qu'un save_nvd_discovery()
            # par CVE (2 connexions + 2 commits CHACUNE) : avec des
            # fenêtres de plusieurs milliers de CVE, la version par
            # CVE créait une rafale continue de verrous d'écriture
            # SQLite qui pouvait faire paraître l'appli figée
            # (connexion/transaction pendant que ce script tourne en
            # arrière-plan), y compris sur l'écran de connexion.
            bulk_save_nvd_discoveries(discoveries)

            print(
                f"    {len(discoveries)} CVE récupérée(s) "
                f"({get_nvd_total_count()} au total en base)"
            )

            # Checkpoint IMMÉDIATEMENT après chaque fenêtre réussie :
            # si l'appli est redémarrée ou le process interrompu, on
            # reprend ici (en reculant toujours vers le passé), sans
            # retélécharger ce qui est déjà fait.
            cursor_dt = window_start
            set_nvd_backfill_cursor(cursor_dt.isoformat())

            set_sync_state(
                SYNC_KEY,
                "RUNNING",
                f"Fenêtre {windows_done}/{total_windows} terminée "
                f"(remonté jusqu'au {cursor_dt.date()}) -- "
                f"{get_nvd_total_count()} CVE NVD en base"
            )

    except Exception as error:

        print()
        print(f"[ERROR] Téléchargement historique NVD interrompu : {error}")

        set_sync_state(
            SYNC_KEY,
            "ERROR",
            f"Interrompu après la fenêtre {windows_done}/{total_windows} "
            f"({get_nvd_total_count()} CVE NVD en base) : {error}"
        )

        sys.exit(1)

    mark_nvd_backfill_done()

    print()
    print("Téléchargement historique NVD terminé.")
    print(f"Total CVE NVD en base : {get_nvd_total_count()}")
    print()

    set_sync_state(
        SYNC_KEY,
        "OK",
        f"Historique complet ({get_nvd_total_count()} CVE NVD en base)."
    )


if __name__ == "__main__":
    main()
