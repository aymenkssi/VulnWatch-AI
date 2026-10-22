import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr

from database import get_smtp_config, is_smtp_configured


class SmtpNotConfigured(RuntimeError):
    """SMTP settings are missing (host / from address)."""


def send_email(to_addr, subject, body):
    """
    Send a plain-text email using the SMTP settings stored in the
    database (Notifications tab). Raises SmtpNotConfigured if nothing
    has been configured yet, or smtplib exceptions on any send
    failure (caller records the error via
    database.mark_notification_error()).
    """

    if not is_smtp_configured():
        raise SmtpNotConfigured(
            "Paramètres SMTP non configurés (onglet Notifications)."
        )

    config = get_smtp_config()

    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = subject
    message["From"] = formataddr(("VulnWatch AI", config["from_addr"]))
    message["To"] = to_addr

    if config["use_tls"]:

        server = smtplib.SMTP(config["host"], config["port"], timeout=20)
        server.starttls()

    else:

        server = smtplib.SMTP(config["host"], config["port"], timeout=20)

    try:

        if config["username"]:

            server.login(
                config["username"],
                config["password"]
            )

        server.sendmail(
            config["from_addr"],
            [to_addr],
            message.as_string()
        )

    finally:

        # IMPORTANT : si login()/sendmail() a échoué parce que le
        # serveur a coupé la connexion (relais qui referme le socket
        # après un STARTTLS refusé, une auth refusée, etc.), le socket
        # est déjà mort. Appeler server.quit() sur un socket mort lève
        # une NOUVELLE exception ("please run connect() first") qui,
        # dans un bloc finally, remplace silencieusement l'erreur
        # d'origine — masquant la vraie cause. On avale donc cette
        # erreur de fermeture pour laisser remonter l'erreur réelle.
        try:
            server.quit()
        except Exception:
            try:
                server.close()
            except Exception:
                pass


def send_test_email(to_addr):

    send_email(
        to_addr,
        "VulnWatch AI - Test de configuration SMTP",
        "Ceci est un e-mail de test envoyé depuis VulnWatch AI. "
        "Si vous le recevez, la configuration SMTP est correcte."
    )
