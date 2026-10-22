from database import (
    initialize_database,
    get_connection,
    get_notification_candidates,
    create_device_notification,
    get_due_notifications,
    get_notification_cves,
    is_cve_still_on_device,
    mark_notification_cve_resolved,
    mark_notification_reminder_sent,
    mark_notification_resolved,
    mark_notification_error,
    get_exposure_context,
    set_sync_state,
    is_smtp_configured
)
from services.mailer import send_email, SmtpNotConfigured
from services.ai_engine import generate_notification_email


SYNC_KEY = "email_notify"


# =========================================================
# HELPERS
# =========================================================

def _get_vulnerability(cve_id):

    conn = get_connection()

    row = conn.execute(
        "SELECT * FROM vulnerabilities WHERE cve_id = ?",
        (cve_id,)
    ).fetchone()

    conn.close()

    return dict(row) if row else None


def _build_vulnerability_items(cve_ids):
    """
    Construit la liste {"vulnerability", "exposure"} attendue par
    generate_notification_email() pour un groupe de CVE, en ignorant
    silencieusement celles qui auraient disparu de la table
    `vulnerabilities` entre-temps.
    """

    items = []

    for cve_id in cve_ids:

        vulnerability = _get_vulnerability(cve_id)

        if vulnerability is None:
            continue

        items.append({
            "vulnerability": vulnerability,
            "exposure": get_exposure_context(cve_id)
        })

    return items


# =========================================================
# PHASE 1 : NOUVELLES NOTIFICATIONS (regroupées par serveur)
# =========================================================

def send_new_notifications():
    """
    Un e-mail par serveur qualifiant (voir get_notification_candidates :
    seuil de criticité + regroupement de toutes les CVE présentes sur
    ce serveur dans le même envoi).
    """

    candidates = get_notification_candidates()

    sent = 0
    errors = 0

    for candidate in candidates:

        device_name = candidate["device_name"]
        owner_email = candidate["owner_email"]
        cves = candidate["cves"]

        items = _build_vulnerability_items(
            [cve["cve_id"] for cve in cves]
        )

        if not items:
            continue

        email = generate_notification_email(
            items,
            device_name,
            is_reminder=False,
            reminder_count=0
        )

        try:

            send_email(
                owner_email,
                email["sujet"],
                email["corps"]
            )

            create_device_notification(
                device_name=device_name,
                device_id=candidate.get("device_id"),
                owner_email=owner_email,
                cves=cves,
                subject=email["sujet"],
                body=email["corps"]
            )

            print(
                f"[OK] Notification envoyée : {device_name} "
                f"({len(cves)} CVE) -> {owner_email}"
            )

            sent += 1

        except SmtpNotConfigured as error:

            print(f"[SKIP] SMTP non configuré : {error}")

            return sent, errors, "SMTP_NOT_CONFIGURED"

        except Exception as error:

            print(f"[ERROR] {device_name} : {error}")

            errors += 1

    return sent, errors, None


# =========================================================
# PHASE 2 : VÉRIFICATION + RELANCES (par groupe de CVE/serveur)
# =========================================================

def process_due_reminders():
    """
    Pour chaque notification groupée arrivée à échéance : vérifie
    chaque CVE du groupe. Celles qui ont disparu sont marquées
    résolues individuellement ; s'il n'en reste plus aucune, la
    notification du serveur passe à RESOLVED. S'il en reste, une
    relance est envoyée pour les CVE encore présentes (regroupées
    dans le même e-mail).
    """

    due = get_due_notifications()

    reminders_sent = 0
    resolved = 0
    errors = 0

    for notification in due:

        notification_id = notification["id"]
        device_name = notification["device_name"]
        owner_email = notification["owner_email"]

        tracked_cves = get_notification_cves(
            notification_id,
            only_unresolved=True
        )

        remaining_cves = []

        for tracked in tracked_cves:

            if is_cve_still_on_device(tracked["cve_id"], device_name):

                remaining_cves.append(tracked)

            else:

                mark_notification_cve_resolved(
                    notification_id,
                    tracked["cve_id"]
                )

                print(
                    f"[RESOLVED] {tracked['cve_id']} n'est plus présente "
                    f"sur {device_name}"
                )

        if not remaining_cves:

            mark_notification_resolved(notification_id)

            print(f"[RESOLVED] {device_name} : plus aucune CVE en attente")

            resolved += 1

            continue

        items = _build_vulnerability_items(
            [cve["cve_id"] for cve in remaining_cves]
        )

        if not items:
            continue

        reminder_count = (notification["reminder_count"] or 0) + 1

        email = generate_notification_email(
            items,
            device_name,
            is_reminder=True,
            reminder_count=reminder_count
        )

        try:

            send_email(
                owner_email,
                email["sujet"],
                email["corps"]
            )

            mark_notification_reminder_sent(
                notification_id,
                email["sujet"],
                email["corps"],
                remaining_cves
            )

            print(
                f"[RELANCE] {device_name} : {len(remaining_cves)} CVE "
                "toujours présente(s), relance envoyée"
            )

            reminders_sent += 1

        except SmtpNotConfigured as error:

            print(f"[SKIP] SMTP non configuré : {error}")

            return reminders_sent, resolved, errors, "SMTP_NOT_CONFIGURED"

        except Exception as error:

            mark_notification_error(notification_id, str(error))

            print(f"[ERROR] Relance {device_name} : {error}")

            errors += 1

    return reminders_sent, resolved, errors, None


# =========================================================
# MAIN
# =========================================================

def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Notifications e-mail (propriétaires serveur)")
    print("=" * 60)
    print()

    initialize_database()

    if not is_smtp_configured():

        print("[SKIP] SMTP non configuré (onglet Notifications).")

        set_sync_state(
            SYNC_KEY,
            "ERROR",
            "SMTP non configuré"
        )

        return

    sent, new_errors, blocker = send_new_notifications()

    if blocker == "SMTP_NOT_CONFIGURED":

        set_sync_state(SYNC_KEY, "ERROR", "SMTP non configuré")

        return

    reminders_sent, resolved, reminder_errors, blocker = process_due_reminders()

    if blocker == "SMTP_NOT_CONFIGURED":

        set_sync_state(SYNC_KEY, "ERROR", "SMTP non configuré")

        return

    total_errors = new_errors + reminder_errors

    print()
    print("Résumé :")
    print(f"  Nouvelles notifications envoyées (serveurs) : {sent}")
    print(f"  Relances envoyées (serveurs)                : {reminders_sent}")
    print(f"  Résolues (serveurs)                         : {resolved}")
    print(f"  Erreurs                                     : {total_errors}")
    print()

    set_sync_state(
        SYNC_KEY,
        "OK" if total_errors == 0 else "WARNING",
        f"Envoyées={sent} Relances={reminders_sent} "
        f"Résolues={resolved} Erreurs={total_errors}"
    )


if __name__ == "__main__":
    main()
