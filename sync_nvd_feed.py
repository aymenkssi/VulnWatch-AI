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
    is_smtp_configured
)
from collectors.nvd import fetch_recent_nvd_cves
from services.mailer import send_email
from services.ai_engine import generate_watch_alert_email
from services.jobs import report_progress


SYNC_KEY = "nvd_daily_feed"

# Fenêtre par défaut au tout premier lancement (pas encore de
# last_run_at à repartir).
DEFAULT_LOOKBACK_HOURS = 24

# Petit chevauchement avec la fenêtre précédente pour ne jamais rater
# une CVE publiée pile à la frontière entre deux exécutions.
OVERLAP_MINUTES = 60

# L'API NVD 2.0 n'accepte pas une fenêtre pubStartDate/pubEndDate de
# plus de 120 jours.
MAX_WINDOW_DAYS = 119


def _compute_window():

    state = get_sync_state(SYNC_KEY)

    now = datetime.now(timezone.utc)

    start = now - timedelta(hours=DEFAULT_LOOKBACK_HOURS)

    if state and state.get("last_run_at"):

        try:

            last_run = datetime.fromisoformat(state["last_run_at"])

            if last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=timezone.utc)

            start = last_run - timedelta(minutes=OVERLAP_MINUTES)

        except ValueError:

            pass

    max_start = now - timedelta(days=MAX_WINDOW_DAYS)

    if start < max_start:
        start = max_start

    return start, now


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


def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Synchronisation NVD (source principale)")
    print("=" * 60)
    print()

    initialize_database()

    start, end = _compute_window()

    print(f"Fenêtre de publication NVD : {start.isoformat()} -> {end.isoformat()}")

    try:

        discoveries = fetch_recent_nvd_cves(start, end)

    except Exception as error:

        print(f"[ERROR] Échec de récupération NVD : {error}")

        set_sync_state(SYNC_KEY, "ERROR", str(error))

        sys.exit(1)

    print(f"{len(discoveries)} CVE publiée(s) par NVD sur la fenêtre")

    report_progress(
        None,
        None,
        f"Enregistrement de {len(discoveries)} CVE en base",
        force=True
    )

    bulk_save_nvd_discoveries(discoveries)

    print(f"{len(discoveries)} CVE enregistrée(s) / mise(s) à jour en base")

    report_progress(
        None,
        None,
        "Croisement avec l'inventaire Defender XDR",
        force=True
    )

    # =====================================================
    # CROISEMENT AVEC L'INVENTAIRE XDR
    # =====================================================

    pulled_ids = [cve_id for cve_id, _ in discoveries]

    matches = get_cve_ids_present_in_defender(pulled_ids)

    print(f"{len(matches)} correspondance(s) trouvée(s) dans l'inventaire XDR")

    alerts_sent = 0
    alert_errors = []

    if matches:

        if not is_smtp_configured():

            print(
                "[INFO] Correspondance(s) trouvée(s) mais SMTP non "
                "configuré : pas d'alerte envoyée."
            )

        else:

            recipient_emails = [
                recipient["email"]
                for recipient in get_watch_recipients(active_only=True)
            ]

            if not recipient_emails:

                print(
                    "[INFO] Correspondance(s) trouvée(s) mais aucune "
                    "liste de diffusion active (onglet Veille)."
                )

            else:

                for index, cve_id in enumerate(matches):

                    report_progress(
                        index,
                        len(matches),
                        f"Alerte {cve_id} (rédaction IA + envoi)",
                        force=True
                    )

                    ok, errors = _send_match_alert(cve_id, recipient_emails)

                    if ok:

                        print(f"[ALERTE] {cve_id} -> liste de diffusion")

                        alerts_sent += 1

                    alert_errors.extend(errors)

    print()
    print("Résumé :")
    print(f"  CVE NVD récupérées        : {len(discoveries)}")
    print(f"  Correspondances XDR       : {len(matches)}")
    print(f"  Alertes envoyées          : {alerts_sent}")
    print(f"  Erreurs d'envoi           : {len(alert_errors)}")
    print()

    detail = (
        f"{len(discoveries)} CVE NVD / {len(matches)} correspondance(s) XDR / "
        f"{alerts_sent} alerte(s) envoyée(s)"
        + (f" / {len(alert_errors)} erreur(s)" if alert_errors else "")
    )

    set_sync_state(
        SYNC_KEY,
        "OK" if not alert_errors else "WARNING",
        detail
    )


if __name__ == "__main__":
    main()
