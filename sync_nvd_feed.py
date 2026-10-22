import sys
from datetime import datetime, timezone, timedelta

from database import (
    initialize_database,
    get_sync_state,
    set_sync_state,
    bulk_save_nvd_discoveries,
    get_cve_ids_present_in_defender,
    get_detection_context_for_cve,
    get_devices_for_cve,
    get_watch_recipients,
    record_watch_alert,
    is_smtp_configured,
    get_known_cve_ids,
    get_nvd_feed_cursor,
    set_nvd_feed_cursor
)
from collectors.nvd import fetch_recent_nvd_cves
from services.mailer import send_email
from services.ai_engine import generate_watch_alert_email
from services.jobs import report_progress


SYNC_KEY = "nvd_daily_feed"

# Fenêtre par défaut au tout premier lancement (pas encore de curseur ni
# de last_run_at à repartir).
DEFAULT_LOOKBACK_HOURS = 24

# Petit chevauchement avec la fenêtre précédente pour ne jamais rater
# une CVE publiée pile à la frontière entre deux exécutions.
OVERLAP_MINUTES = 60

# L'API NVD 2.0 n'accepte pas une fenêtre de plus de 120 jours : une
# période plus longue (synchro arrêtée plusieurs mois) est découpée en
# plusieurs fenêtres au lieu d'être tronquée.
MAX_WINDOW_DAYS = 119


def _parse_iso(value):

    dt = datetime.fromisoformat(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def _compute_start(now):
    """
    Début de la période à récupérer : le curseur (fin de la dernière
    fenêtre RÉUSSIE), moins un petit chevauchement. Avant l'ajout du
    curseur, on repartait de last_run_at, qui avançait aussi après un
    échec : les CVE de la fenêtre ratée n'étaient jamais récupérées.
    """

    cursor = get_nvd_feed_cursor()

    if cursor:

        try:
            return _parse_iso(cursor) - timedelta(minutes=OVERLAP_MINUTES)
        except ValueError:
            pass

    # Première exécution avec le curseur : on repart de la dernière
    # synchro connue (comportement précédent).
    state = get_sync_state(SYNC_KEY)

    if state and state.get("last_run_at"):

        try:
            return (
                _parse_iso(state["last_run_at"])
                - timedelta(minutes=OVERLAP_MINUTES)
            )
        except ValueError:
            pass

    return now - timedelta(hours=DEFAULT_LOOKBACK_HOURS)


def _split_windows(start, end):

    windows = []

    while start < end:

        window_end = min(start + timedelta(days=MAX_WINDOW_DAYS), end)
        windows.append((start, window_end))
        start = window_end

    return windows


def _send_match_alert(cve_id, recipient_emails):
    """
    Envoie l'alerte de correspondance NVD <-> XDR à la liste de
    diffusion "Veille", et l'enregistre dans l'historique (même
    historique que les alertes envoyées manuellement depuis l'onglet
    Veille). Retourne (ok, error_messages).
    """

    detection = get_detection_context_for_cve(cve_id)

    if detection is None:
        return False, [f"{cve_id} : aucune donnée d'exposition trouvée"]

    devices = get_devices_for_cve(cve_id)

    email = generate_watch_alert_email(detection, devices)

    sent_to = []
    errors = []

    for recipient_email in recipient_emails:

        try:

            send_email(
                recipient_email,
                email["sujet"],
                email["corps"]
            )

            sent_to.append(recipient_email)

        except Exception as error:

            errors.append(f"{cve_id} -> {recipient_email} : {error}")

    if sent_to:

        record_watch_alert(
            cve_id=cve_id,
            recipients=sent_to,
            subject=email["sujet"],
            body=email["corps"],
            affected_device_count=len(devices)
        )

    return bool(sent_to), errors


def _send_alerts(new_matches):
    """
    Alerte la liste de diffusion "Veille" pour les CVE NOUVELLES en base
    présentes dans l'inventaire XDR. Retourne (alertes envoyées, erreurs).
    """

    if not new_matches:
        return 0, []

    if not is_smtp_configured():

        print(
            "[INFO] Correspondance(s) trouvée(s) mais SMTP non "
            "configuré : pas d'alerte envoyée."
        )

        return 0, []

    recipient_emails = [
        recipient["email"]
        for recipient in get_watch_recipients(active_only=True)
    ]

    if not recipient_emails:

        print(
            "[INFO] Correspondance(s) trouvée(s) mais aucune "
            "liste de diffusion active (onglet Veille)."
        )

        return 0, []

    alerts_sent = 0
    alert_errors = []

    for index, cve_id in enumerate(new_matches):

        report_progress(
            index,
            len(new_matches),
            f"Alerte {cve_id} (rédaction IA + envoi)",
            force=True
        )

        ok, errors = _send_match_alert(cve_id, recipient_emails)

        if ok:

            print(f"[ALERTE] {cve_id} -> liste de diffusion")

            alerts_sent += 1

        alert_errors.extend(errors)

    return alerts_sent, alert_errors


def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Synchronisation NVD (source principale)")
    print("=" * 60)
    print()

    initialize_database()

    now = datetime.now(timezone.utc)
    windows = _split_windows(_compute_start(now), now)

    published_total = 0
    new_total = 0
    modified_total = 0
    matches_total = 0
    alerts_sent = 0
    alert_errors = []

    try:

        for number, (start, end) in enumerate(windows, start=1):

            print(
                f"[Fenêtre {number}/{len(windows)}] "
                f"{start.isoformat()} -> {end.isoformat()}"
            )

            # -------------------------------------------------
            # 1. CVE PUBLIÉES sur la fenêtre
            # -------------------------------------------------

            published = fetch_recent_nvd_cves(start, end, "published")
            published_ids = [cve_id for cve_id, _ in published]

            # Seules les CVE absentes de la base avant cet
            # enregistrement déclenchent une alerte : le chevauchement
            # entre deux fenêtres (ou une fenêtre rejouée après un
            # échec) ne renvoie pas deux fois la même alerte.
            known_before = get_known_cve_ids(published_ids)
            new_ids = [
                cve_id for cve_id in published_ids
                if cve_id not in known_before
            ]

            report_progress(
                None,
                None,
                f"Enregistrement de {len(published)} CVE publiées",
                force=True
            )

            bulk_save_nvd_discoveries(published)

            published_total += len(published)
            new_total += len(new_ids)

            print(
                f"    {len(published)} CVE publiée(s), "
                f"dont {len(new_ids)} nouvelle(s) en base"
            )

            # -------------------------------------------------
            # 2. Croisement XDR + alertes (CVE nouvelles)
            # -------------------------------------------------

            report_progress(
                None,
                None,
                "Croisement avec l'inventaire Defender XDR",
                force=True
            )

            new_matches = get_cve_ids_present_in_defender(new_ids)
            matches_total += len(new_matches)

            print(
                f"    {len(new_matches)} nouvelle(s) correspondance(s) "
                "dans l'inventaire XDR"
            )

            sent, errors = _send_alerts(new_matches)
            alerts_sent += sent
            alert_errors.extend(errors)

            # -------------------------------------------------
            # 3. CVE MODIFIÉES sur la fenêtre (score CVSS ajouté
            #    après coup, analyse NVD terminée...). Mise à jour en
            #    base uniquement, sans alerte.
            # -------------------------------------------------

            modified = fetch_recent_nvd_cves(start, end, "modified")

            report_progress(
                None,
                None,
                f"Mise à jour de {len(modified)} CVE modifiées",
                force=True
            )

            bulk_save_nvd_discoveries(modified)

            modified_total += len(modified)

            print(f"    {len(modified)} CVE modifiée(s) mise(s) à jour")

            # Fenêtre entièrement traitée : le curseur avance.
            set_nvd_feed_cursor(end.isoformat())

    except Exception as error:

        print(f"[ERROR] Échec de récupération NVD : {error}")
        print(
            "Le curseur n'a pas avancé : la prochaine synchro reprendra "
            "à partir de la dernière fenêtre réussie."
        )

        set_sync_state(SYNC_KEY, "ERROR", str(error))

        sys.exit(1)

    print()
    print("Résumé :")
    print(f"  CVE NVD publiées          : {published_total}")
    print(f"  Nouvelles en base         : {new_total}")
    print(f"  CVE modifiées mises à jour: {modified_total}")
    print(f"  Correspondances XDR       : {matches_total}")
    print(f"  Alertes envoyées          : {alerts_sent}")
    print(f"  Erreurs d'envoi           : {len(alert_errors)}")
    print()

    detail = (
        f"{published_total} CVE NVD ({new_total} nouvelles, "
        f"{modified_total} modifiées) / {matches_total} correspondance(s) "
        f"XDR / {alerts_sent} alerte(s) envoyée(s)"
        + (f" / {len(alert_errors)} erreur(s)" if alert_errors else "")
    )

    set_sync_state(
        SYNC_KEY,
        "OK" if not alert_errors else "WARNING",
        detail
    )


if __name__ == "__main__":
    main()
