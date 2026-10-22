import subprocess
import sys
import os
from pathlib import Path
from datetime import date, datetime, timezone, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components

from services.azure_auth import (
    get_azure_app_config,
    set_azure_app_config,
    clear_azure_app_config,
    is_azure_app_configured,
    test_azure_app,
    REQUIRED_ROLES,
    API_LABELS
)
from services.inventory_matcher import (
    get_inventory_matched_at,
    refresh_matches_for_cves
)
from services.jobs import (
    start_job,
    get_job,
    is_job_running,
    read_job_log,
    last_log_line,
    request_stop
)

from database import (
    get_connection,
    initialize_database,
    import_manual_server_owners,
    get_sync_state,
    get_pending_nvd_count,
    ensure_admin_seeded,
    verify_user_credentials,
    get_user,
    list_users,
    create_user,
    update_user,
    delete_user,
    set_user_password,
    password_policy_checks,
    password_is_valid,
    ROLES,
    create_auth_session,
    get_auth_session_user,
    delete_auth_session,
    AUTH_SESSION_DAYS,
    get_notification_delays,
    set_notification_delay,
    get_notification_min_priority,
    set_notification_min_priority,
    get_smtp_config,
    set_smtp_config,
    is_smtp_configured,
    get_notification_history,
    get_hexiosec_config,
    set_hexiosec_config,
    is_hexiosec_configured,
    get_hexiosec_findings,
    get_hexiosec_severity_counts,
    get_hexiosec_assets,
    get_hexiosec_asset_type_counts,
    get_recent_defender_detections,
    get_devices_for_cve,
    add_watch_recipient,
    get_watch_recipients,
    set_watch_recipient_active,
    delete_watch_recipient,
    record_watch_alert,
    get_watch_alert_history,
    get_nvd_api_key,
    get_nvd_audit_report,
    get_inventory_status,
    get_inventory_machines,
    get_inventory_products,
    get_machine_software,
    get_machine_nvd_cves,
    get_machine_defender_cves,
    get_product_versions,
    get_product_machines,
    get_product_nvd_cves,
    count_cves_without_cpe_check,
    get_inventory_matched_cves,
    get_inventory_devices_for_cve,
    get_inventory_device_count,
    search_nvd_cves,
    get_cve_details,
    get_app_config,
    set_app_config,
    set_nvd_api_key,
    get_nvd_backfill_start,
    set_nvd_backfill_start,
    is_nvd_backfill_done,
    reset_nvd_backfill,
    get_nvd_total_count,
    bulk_save_nvd_discoveries,
    get_nvd_defender_exposure
)
from services.mailer import send_test_email, send_email, SmtpNotConfigured
from services.ai_engine import generate_watch_alert_email
from collectors.hexiosec import test_connection as hexiosec_test_connection
import collectors.nvd as nvd_collector


# =========================================================
# CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="VulnWatch AI - Connexion",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# DATABASE INIT + COMPTE ADMIN
# =========================================================
#
# Les identifiants admin sont stockés en base (hash PBKDF2 + sel,
# jamais en clair, jamais codés en dur dans ce fichier). À la toute
# première exécution, un compte est créé automatiquement : reprise
# de VULNWATCH_ADMIN_USER / VULNWATCH_ADMIN_PASSWORD si définies,
# sinon génération d'un mot de passe aléatoire révélé une seule fois
# (console + fichier local). Il peut ensuite être changé depuis la
# section "Compte" de la barre latérale.

initialize_database()

_seeded_admin = ensure_admin_seeded()

if _seeded_admin:

    print()
    print("=" * 60)
    print("VulnWatch AI - Compte admin initial généré")
    print(f"Utilisateur : {_seeded_admin['username']}")
    print(f"Mot de passe : {_seeded_admin['password']}")
    print(
        "Changez ce mot de passe depuis l'application "
        "(section \"Compte\" dans la barre latérale) après connexion."
    )
    print("=" * 60)
    print()

    try:

        Path("data").mkdir(parents=True, exist_ok=True)

        with open(
            "data/INITIAL_ADMIN_PASSWORD.txt",
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                f"Utilisateur : {_seeded_admin['username']}\n"
                f"Mot de passe : {_seeded_admin['password']}\n"
                "Supprimez ce fichier une fois le mot de passe changé "
                "(section \"Compte\" dans l'application).\n"
            )

    except OSError:

        pass


# =========================================================
# AUTHENTIFICATION
# =========================================================

# Connexion conservée après un rafraîchissement de la page : jeton de
# session dans un cookie (voir create_auth_session dans database.py).
SESSION_COOKIE = "vulnwatch_session"


def _write_session_cookie(token, max_age_seconds):
    """
    Pose (ou efface, max_age_seconds=0) le cookie de session dans le
    navigateur. Streamlit ne sait que LIRE les cookies
    (st.context.cookies) : l'écriture passe par un petit script dans un
    composant invisible, qui écrit sur la page parente (même origine).
    """

    components.html(
        "<script>"
        f"window.parent.document.cookie = '{SESSION_COOKIE}={token}; "
        f"path=/; max-age={int(max_age_seconds)}; SameSite=Strict';"
        "</script>",
        height=0
    )


def logout():

    delete_auth_session(st.session_state.get("session_token"))

    for key in ("authenticated", "authenticated_username", "session_token", "user"):
        st.session_state.pop(key, None)

    # Le cookie est effacé à l'affichage de la page de connexion.
    st.session_state["clear_session_cookie"] = True


def authenticate():

    if st.session_state.get("authenticated", False):

        # Compte relu à chaque chargement : un utilisateur désactivé ou
        # supprimé par un administrateur est déconnecté aussitôt, un
        # changement de rôle s'applique tout de suite.
        user = get_user(st.session_state.get("authenticated_username"))

        if not user or not user["active"]:
            logout()
            st.rerun()

        st.session_state["user"] = user

        # Cookie à poser juste après la connexion (le st.rerun() qui suit
        # le formulaire ne laisse pas le temps au navigateur de le faire).
        pending_token = st.session_state.pop("pending_session_cookie", None)

        if pending_token:
            _write_session_cookie(pending_token, AUTH_SESSION_DAYS * 86400)

        return True

    if st.session_state.pop("clear_session_cookie", False):

        _write_session_cookie("", 0)

    else:

        # Page rafraîchie / nouvel onglet : on reprend la session du
        # cookie si elle est toujours valide.
        token = st.context.cookies.get(SESSION_COOKIE)
        user = get_auth_session_user(token)

        if user:
            st.session_state["authenticated"] = True
            st.session_state["authenticated_username"] = user["username"]
            st.session_state["user"] = user
            st.session_state["session_token"] = token
            return True

    st.title("🛡️ VulnWatch AI")
    st.subheader("Connexion")
    st.caption("Authentifiez-vous pour accéder à la plateforme de sécurité.")

    # Formulaire (st.form) plutôt que des widgets + un bouton libres :
    # avec un bouton libre, quand le navigateur (ou un gestionnaire de
    # mots de passe) auto-remplit les champs, Streamlit ne voit
    # parfois pas encore la valeur au moment du premier clic (elle
    # n'a pas encore déclenché d'événement "change" côté navigateur),
    # d'où le besoin de cliquer "Se connecter" deux fois. Un vrai
    # <form> HTML force le navigateur à valider les champs auto-remplis
    # avant la soumission, et Streamlit lit alors la valeur à jour dès
    # le premier clic.
    with st.form("login_form"):

        username = st.text_input("Nom d'utilisateur", key="login_username")
        password = st.text_input(
            "Mot de passe", type="password", key="login_password"
        )

        submitted = st.form_submit_button(
            "Se connecter", use_container_width=True, type="primary"
        )

    if submitted:

        user = verify_user_credentials(username, password)

        if user:
            token = create_auth_session(user["username"])
            st.session_state["authenticated"] = True
            st.session_state["authenticated_username"] = user["username"]
            st.session_state["user"] = user
            st.session_state["session_token"] = token
            st.session_state["pending_session_cookie"] = token
            st.session_state.pop("login_username", None)
            st.session_state.pop("login_password", None)
            st.rerun()

        st.error("Nom d'utilisateur ou mot de passe incorrect.")

    return False


def render_password_policy(password):
    """
    Exigences de la politique de mot de passe, avec ce qui est déjà
    respecté (✅) et ce qui ne l'est pas encore (❌). Mis à jour quand
    on quitte le champ ou qu'on appuie sur Entrée.
    """

    lines = [
        f"{'✅' if ok else '❌'} {label}"
        for label, ok in password_policy_checks(password)
    ]

    st.caption("**Politique de mot de passe**  \n" + "  \n".join(lines))


def password_change_form(username, key_prefix, require_current=True):
    """
    Formulaire de changement de mot de passe (première connexion ou
    « Mon compte »). Retourne True une fois le mot de passe changé.
    """

    current = None

    if require_current:
        current = st.text_input(
            "Mot de passe actuel", type="password",
            key=f"{key_prefix}_current"
        )

    new = st.text_input(
        "Nouveau mot de passe", type="password", key=f"{key_prefix}_new"
    )

    render_password_policy(new)

    confirm = st.text_input(
        "Confirmer le nouveau mot de passe", type="password",
        key=f"{key_prefix}_confirm"
    )

    if confirm:
        st.caption(
            "✅ Les deux saisies correspondent" if confirm == new
            else "❌ Les deux saisies ne correspondent pas"
        )

    if not st.button(
        "Changer le mot de passe",
        type="primary",
        use_container_width=True,
        key=f"{key_prefix}_submit"
    ):
        return False

    if require_current and not verify_user_credentials(username, current):
        st.error("Mot de passe actuel incorrect.")
    elif not password_is_valid(new):
        st.error("Le nouveau mot de passe ne respecte pas toutes les exigences.")
    elif new != confirm:
        st.error("Les deux saisies ne correspondent pas.")
    elif verify_user_credentials(username, new):
        st.error("Le nouveau mot de passe doit être différent de l'actuel.")
    else:
        # set_user_password ferme toutes les sessions de l'utilisateur :
        # on en rouvre une pour ce navigateur.
        set_user_password(username, new, must_change_password=False)

        token = create_auth_session(username)
        st.session_state["session_token"] = token
        st.session_state["pending_session_cookie"] = token

        for suffix in ("current", "new", "confirm"):
            st.session_state.pop(f"{key_prefix}_{suffix}", None)

        return True

    return False


if not authenticate():
    st.stop()


CURRENT_USER = st.session_state["user"]

# Lecteur : consultation et rafraîchissement seulement. Tous les boutons
# qui configurent, importent, lancent une synchro ou envoient un e-mail
# sont désactivés (disabled=... or not IS_ADMIN).
IS_ADMIN = CURRENT_USER["role"] == "admin"


# =========================================================
# CHANGEMENT DE MOT DE PASSE OBLIGATOIRE (première connexion)
# =========================================================

if CURRENT_USER["must_change_password"]:

    st.title("🛡️ VulnWatch AI")
    st.subheader("Changement de mot de passe obligatoire")
    st.info(
        f"Bonjour {CURRENT_USER['username']}, choisissez votre mot de passe "
        "personnel avant d'accéder à l'application."
    )

    if password_change_form(
        CURRENT_USER["username"], "first_login", require_current=False
    ):
        st.success("Mot de passe changé.")
        st.rerun()

    if st.button("Se déconnecter", key="first_login_logout"):
        logout()
        st.rerun()

    st.stop()


# =========================================================
# AUTOMATIC CISA SYNC (every 12h)
# =========================================================

AUTO_SYNC_INTERVAL_HOURS = 12


def format_sync_timestamp(iso_value):

    if not iso_value:
        return "jamais"

    try:

        dt = datetime.fromisoformat(iso_value)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone().strftime("%d/%m/%Y %H:%M")

    except ValueError:

        return iso_value


def launch_background_sync(script, min_interval, env=None):
    """
    Lance un script de synchro en sous-processus DÉTACHÉ (Popen) au
    lieu de subprocess.run : l'interface s'affiche tout de suite au
    lieu de rester figée (formulaire de connexion grisé) pendant que
    CISA / NVD / Ollama / SMTP répondent — le flux NVD et les e-mails
    générés par l'IA pouvaient prendre plusieurs minutes.

    Streamlit relance tout le script à chaque interaction : on note
    l'heure du lancement en base pour ne pas relancer le même script
    tant qu'il tourne (ou, s'il a planté, avant min_interval).
    Les tableaux se mettent à jour d'eux-mêmes (cache de 60 s).
    """

    key = f"autosync_launched_at:{script}"
    now = datetime.now(timezone.utc)
    launched_at = get_app_config(key)

    if launched_at:

        try:

            last_launch = datetime.fromisoformat(launched_at)

            if last_launch.tzinfo is None:
                last_launch = last_launch.replace(tzinfo=timezone.utc)

            if now - last_launch < min_interval:
                return

        except ValueError:

            pass

    if is_job_running(Path(script).stem):
        return

    set_app_config(key, now.isoformat())

    # Même clé que le bouton manuel correspondant : la synchro auto
    # apparaît avec sa barre de progression, et un clic pendant qu'elle
    # tourne ne la lance pas une seconde fois.
    start_job(
        Path(script).stem,
        script,
        JOB_LABELS.get(script, script),
        env=env
    )


# =========================================================
# SYNCHROS EN ARRIÈRE-PLAN : BARRE DE PROGRESSION
# =========================================================
#
# Les boutons "Synchroniser ..." lancent le script via start_job()
# (services/jobs.py) au lieu d'attendre sa fin : l'application reste
# utilisable pendant la synchro. render_job() affiche sous le bouton
# une barre de progression rafraîchie toutes les 2 s par un fragment
# Streamlit (seul ce bloc est réexécuté, pas toute la page), puis le
# résultat une fois le script terminé.

# Durée de vie du cache des requêtes lourdes. Chaque clic relance toute
# la page : au-delà de ce délai, elle relit la base (plusieurs secondes
# sur un gros parc). Le cache est vidé dès qu'une synchro lancée depuis
# l'interface se termine (render_job), donc 10 min suffisent.
CACHE_TTL_SECONDS = 600


JOB_LABELS = {
    "sync.py": "Synchronisation CISA KEV",
    "enrich.py": "Enrichissement NVD",
    "ai_enrich.py": "Analyse IA (Ollama)",
    "notify.py": "Notifications e-mail",
    "sync_hexiosec.py": "Synchronisation Hexiosec ASM",
    "sync_nvd_feed.py": "Synchronisation NVD",
    "nvd_audit.py": "Vérification de la base NVD",
    "sync_software_inventory.py": "Import de l'inventaire logiciel",
    "nvd_match.py": "Calcul des équipements touchés (NVD)",
    "nvd_import_files.py": "Import de fichiers NVD",
    "nvd_cpe_sync.py": "Téléchargement des produits vulnérables NVD"
}


def launch_job(script, env=None):

    # Pas de st.rerun() ici : le clic vient déjà de relancer la page, et
    # render_job(), appelé juste sous le bouton, affiche la progression.
    start_job(
        Path(script).stem,
        script,
        JOB_LABELS.get(script, script),
        env=env
    )


def format_duration(seconds):

    if seconds is None:
        return ""

    seconds = int(seconds)

    if seconds < 60:
        return f"{seconds} s"

    return f"{seconds // 60} min {seconds % 60:02d} s"


@st.fragment(run_every=2)
def _job_progress_fragment(key):

    job = get_job(key)

    if not job or not job["running"]:
        # Terminé : on relance toute la page pour afficher le résultat
        # et les données à jour.
        st.rerun()

    progress = job.get("progress") or {}
    current = progress.get("current")
    total = progress.get("total")
    elapsed = format_duration(job.get("elapsed_seconds"))

    if total:

        ratio = min(max(current or 0, 0) / total, 1.0)

        st.progress(
            ratio,
            text=(
                f"⏳ {job['label']} — {current}/{total} "
                f"({ratio:.0%}) · {elapsed}"
            )
        )

    else:

        # Étape sans total connu (téléchargement, écriture en base...) :
        # barre animée pour montrer que la synchro avance toujours.
        st.progress(
            (int(job.get("elapsed_seconds") or 0) % 20) / 20,
            text=f"⏳ {job['label']} en cours · {elapsed}"
        )

    detail = progress.get("message") or last_log_line(key)

    if detail:
        st.caption(detail)

    # Le clic ne relance que ce fragment : l'arrêt est pris en compte par
    # le lanceur en moins d'une seconde, la barre disparaît au passage
    # suivant.
    if job.get("stop_requested"):

        st.button(
            "Arrêt en cours...",
            key=f"job_stop_{key}",
            disabled=True
        )

    elif st.button("Arrêter", key=f"job_stop_{key}", disabled=not IS_ADMIN):

        request_stop(key)


def render_job(key, warning_state_key=None):
    """
    Sous le bouton d'une synchro : barre de progression tant qu'elle
    tourne, puis résultat (succès / échec + journal) dans la session
    qui l'a vue tourner.
    """

    job = get_job(key)

    if not job:
        return

    watched_key = f"job_watched_{key}"

    if job["running"]:

        st.session_state[watched_key] = True
        _job_progress_fragment(key)
        return

    if not st.session_state.get(watched_key):
        return

    # Une seule fois par exécution terminée : les tableaux relisent la
    # base au lieu d'afficher le cache d'avant la synchro.
    done_key = f"job_done_{key}"

    if st.session_state.get(done_key) != job.get("finished_at"):
        st.session_state[done_key] = job.get("finished_at")
        st.cache_data.clear()

    duration = format_duration(job.get("elapsed_seconds"))

    if job["status"] == "DONE":

        state = get_sync_state(warning_state_key) if warning_state_key else None

        if state and state.get("status") == "WARNING":
            st.warning(
                f"{job['label']} terminée en {duration}, avec un "
                f"avertissement :\n\n{state.get('detail')}"
            )
        else:
            st.success(f"{job['label']} terminée en {duration}.")

    elif job["status"] == "STOPPED":

        st.info(
            f"{job['label']} arrêtée à votre demande après {duration}. "
            "Les données déjà enregistrées sont conservées."
        )

    elif job["status"] == "INTERRUPTED":

        st.warning(
            f"{job['label']} interrompue (redémarrage du serveur ?). "
            "Vous pouvez la relancer."
        )

    else:

        st.error(
            f"Échec : {job['label']} (code {job.get('returncode')})."
        )

    with st.expander("Journal de la synchronisation"):
        st.code(read_job_log(key) or "(vide)", language="text")

    if st.button("Masquer", key=f"job_hide_{key}"):
        st.session_state[watched_key] = False
        st.rerun()


def auto_sync_cisa_if_needed():

    state = get_sync_state("cisa_kev")

    now = datetime.now(timezone.utc)
    needs_sync = True

    if state and state.get("last_run_at"):

        try:

            last_run = datetime.fromisoformat(
                state["last_run_at"]
            )

            if last_run.tzinfo is None:
                last_run = last_run.replace(
                    tzinfo=timezone.utc
                )

            needs_sync = (
                (now - last_run)
                >= timedelta(hours=AUTO_SYNC_INTERVAL_HOURS)
            )

        except ValueError:

            needs_sync = True

    if needs_sync:

        launch_background_sync(
            "sync.py",
            timedelta(hours=AUTO_SYNC_INTERVAL_HOURS)
        )


auto_sync_cisa_if_needed()


# =========================================================
# AUTOMATIC NVD ENRICHMENT (small batch on each load)
# =========================================================
#
# L'API NVD publique est limitée en débit (délai de plusieurs
# secondes entre chaque requête), donc on ne peut pas tout enrichir
# d'un coup à chaque ouverture de l'appli. On grignote le retard par
# petits lots, régulièrement, jusqu'à ce que "CVSS 3.1" / "Sévérité
# NVD" soient renseignés pour toutes les CVE.

AUTO_NVD_INTERVAL_MINUTES = 30
AUTO_NVD_BATCH_SIZE = 5


def auto_enrich_nvd_if_needed():

    if get_pending_nvd_count() == 0:
        return

    state = get_sync_state("nvd_enrich")

    now = datetime.now(timezone.utc)
    needs_run = True

    if state and state.get("last_run_at"):

        try:

            last_run = datetime.fromisoformat(
                state["last_run_at"]
            )

            if last_run.tzinfo is None:
                last_run = last_run.replace(
                    tzinfo=timezone.utc
                )

            needs_run = (
                (now - last_run)
                >= timedelta(minutes=AUTO_NVD_INTERVAL_MINUTES)
            )

        except ValueError:

            needs_run = True

    if needs_run:

        env = os.environ.copy()
        env["VULNWATCH_MAX_CVES"] = str(AUTO_NVD_BATCH_SIZE)

        nvd_api_key_for_enrich = get_nvd_api_key()

        if nvd_api_key_for_enrich:
            env["VULNWATCH_NVD_API_KEY"] = nvd_api_key_for_enrich

        launch_background_sync(
            "enrich.py",
            timedelta(minutes=AUTO_NVD_INTERVAL_MINUTES),
            env=env
        )


auto_enrich_nvd_if_needed()


# =========================================================
# AUTOMATIC EMAIL NOTIFICATIONS (nouvelles + relances)
# =========================================================
#
# Vérifie régulièrement s'il y a de nouvelles CVE à notifier aux
# propriétaires de serveur (notification activée) ou des relances
# arrivées à échéance (CVE toujours présente après le délai configuré
# selon sa criticité). Ne fait rien si le SMTP n'est pas configuré.

AUTO_NOTIFY_INTERVAL_MINUTES = 60


def auto_notify_if_needed():

    if not is_smtp_configured():
        return

    state = get_sync_state("email_notify")

    now = datetime.now(timezone.utc)
    needs_run = True

    if state and state.get("last_run_at"):

        try:

            last_run = datetime.fromisoformat(
                state["last_run_at"]
            )

            if last_run.tzinfo is None:
                last_run = last_run.replace(
                    tzinfo=timezone.utc
                )

            needs_run = (
                (now - last_run)
                >= timedelta(minutes=AUTO_NOTIFY_INTERVAL_MINUTES)
            )

        except ValueError:

            needs_run = True

    if needs_run:

        launch_background_sync(
            "notify.py",
            timedelta(minutes=AUTO_NOTIFY_INTERVAL_MINUTES)
        )


auto_notify_if_needed()


# =========================================================
# AUTOMATIC NVD DAILY FEED (source principale + croisement XDR)
# =========================================================
#
# Chaque jour, récupère les CVE nouvellement publiées par NVD (toutes
# sources confondues, pas seulement CISA KEV) et les croise avec
# l'inventaire XDR (defender_vulnerabilities). Toute correspondance
# déclenche automatiquement une alerte vers la liste de diffusion de
# l'onglet "Veille" (voir sync_nvd_feed.py). CISA KEV continue d'être
# synchronisée séparément et sert toujours à notifier les propriétaires
# de serveur (auto_notify_if_needed ci-dessus) : rien n'y change.

# Toutes les 2 h : NVD déclare souvent les produits vulnérables quelques
# heures après la publication ; la synchro récupère aussi ces
# modifications (et alerte si une CVE récente devient applicable au parc).
AUTO_NVD_FEED_INTERVAL_MINUTES = 2 * 60
AUTO_NVD_FEED_ERROR_RETRY_MINUTES = 60


def auto_sync_nvd_feed_if_needed():

    state = get_sync_state("nvd_daily_feed")

    now = datetime.now(timezone.utc)
    needs_run = True

    if state and state.get("last_run_at"):

        try:

            last_run = datetime.fromisoformat(
                state["last_run_at"]
            )

            if last_run.tzinfo is None:
                last_run = last_run.replace(
                    tzinfo=timezone.utc
                )

            # Après un échec, on retente au bout d'une heure au lieu
            # d'attendre le passage quotidien suivant.
            interval = (
                AUTO_NVD_FEED_ERROR_RETRY_MINUTES
                if state.get("status") == "ERROR"
                else AUTO_NVD_FEED_INTERVAL_MINUTES
            )

            needs_run = (now - last_run) >= timedelta(minutes=interval)

        except ValueError:

            needs_run = True

    if needs_run:

        env = os.environ.copy()

        api_key = get_nvd_api_key()

        if api_key:
            env["VULNWATCH_NVD_API_KEY"] = api_key

        # Garde-fou anti-relance d'une heure (et non 24 h) : sinon il
        # bloquerait la nouvelle tentative prévue une heure après un échec.
        launch_background_sync(
            "sync_nvd_feed.py",
            timedelta(minutes=AUTO_NVD_FEED_ERROR_RETRY_MINUTES),
            env=env
        )


auto_sync_nvd_feed_if_needed()


# =========================================================
# AUTOMATIC SOFTWARE INVENTORY (Defender, chaque jour)
# =========================================================
#
# Réimporte chaque jour l'inventaire logiciel depuis Defender puis
# recalcule les équipements touchés selon NVD — uniquement si le dernier
# import réussi venait de l'API Defender (pas pour un inventaire chargé
# par fichier CSV, qui serait sinon remplacé ou ferait échouer la
# synchro chaque jour faute d'accès à l'API).

AUTO_INVENTORY_INTERVAL_HOURS = 24


def auto_sync_software_inventory_if_needed():

    state = get_sync_state("software_inventory")

    if not state or not str(state.get("detail") or "").startswith("Defender"):
        return

    try:
        last_run = datetime.fromisoformat(state["last_run_at"])
    except (TypeError, ValueError):
        return

    if last_run.tzinfo is None:
        last_run = last_run.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) - last_run >= timedelta(
        hours=AUTO_INVENTORY_INTERVAL_HOURS
    ):
        launch_background_sync(
            "sync_software_inventory.py",
            timedelta(hours=AUTO_INVENTORY_INTERVAL_HOURS)
        )


auto_sync_software_inventory_if_needed()


# =========================================================
# NVD HISTORICAL BACKFILL (téléchargement initial depuis 2020)
# =========================================================
#
# Au tout premier lancement de l'appli, en plus de la synchro
# quotidienne (nouvelles publications uniquement), on rapatrie en
# arrière-plan tout l'historique NVD depuis get_nvd_backfill_start()
# (par défaut le 1er janvier 2020). Potentiellement des dizaines de
# milliers de CVE : on lance ça en sous-processus DÉTACHÉ (Popen, pas
# subprocess.run) pour ne jamais bloquer l'interface, avec reprise sur
# redémarrage (curseur persistant en base, voir sync_nvd_backfill.py).
# Un "heartbeat" (sync_state mis à jour après chaque fenêtre) permet
# de distinguer une synchro toujours active d'une synchro plantée, et
# de ne relancer un sous-processus que dans ce dernier cas.

NVD_BACKFILL_STALE_MINUTES = 15
NVD_BACKFILL_ERROR_RETRY_MINUTES = 30


def auto_launch_nvd_backfill_if_needed():

    if is_nvd_backfill_done():
        return

    state = get_sync_state("nvd_historical_backfill")

    now = datetime.now(timezone.utc)
    should_launch = True

    if state and state.get("last_run_at"):

        try:

            last_run = datetime.fromisoformat(state["last_run_at"])

            if last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=timezone.utc)

            age = now - last_run

            if state.get("status") == "RUNNING":

                # Un process actif met à jour ce champ après CHAQUE
                # fenêtre (quelques secondes à quelques minutes) : si
                # ça n'a pas bougé depuis un moment, il est probable
                # que le process ait été interrompu (redémarrage de
                # l'appli, par exemple).
                should_launch = age >= timedelta(
                    minutes=NVD_BACKFILL_STALE_MINUTES
                )

            elif state.get("status") == "ERROR":

                should_launch = age >= timedelta(
                    minutes=NVD_BACKFILL_ERROR_RETRY_MINUTES
                )

            else:

                should_launch = False

        except ValueError:

            should_launch = True

    if should_launch:

        env = os.environ.copy()

        api_key = get_nvd_api_key()

        if api_key:
            env["VULNWATCH_NVD_API_KEY"] = api_key

        subprocess.Popen(
            [
                sys.executable,
                "sync_nvd_backfill.py"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env
        )


auto_launch_nvd_backfill_if_needed()


# =========================================================
# DISPLAY HELPERS
# =========================================================

def fill_nvd_placeholders(frame):
    """
    Remplace les valeurs NULL de cvss_v3_score / cvss_v3_severity
    par "N/A" pour l'affichage, au lieu du "None" par défaut de
    pandas/Streamlit. Ces colonnes restent vides jusqu'à ce que
    l'enrichissement NVD ait traité la CVE (ou si NVD ne la connaît
    pas du tout).
    """

    frame = frame.copy()

    if "cvss_v3_score" in frame.columns:

        frame["cvss_v3_score"] = frame["cvss_v3_score"].apply(
            lambda v: f"{v:.1f}" if pd.notna(v) else "N/A"
        )

    if "cvss_v3_severity" in frame.columns:

        frame["cvss_v3_severity"] = (
            frame["cvss_v3_severity"].fillna("N/A")
        )

    return frame


PRIORITY_BADGES = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "INFO": "⚪ INFO"
}

# Palette partagée par les graphiques (mêmes couleurs que les badges).
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
    "INFO": "#a1a1aa",
    "N/A": "#9ca3af",
    "UNKNOWN": "#9ca3af",
    "NONE": "#9ca3af"
}


def plot_severity_bar(counts, x_title, y_title):
    """
    Construit un bar chart Plotly coloré par sévérité (mêmes
    couleurs que les badges CRITICAL/HIGH/MEDIUM/LOW), avec les
    valeurs affichées sur chaque barre.
    """

    chart_df = counts.reset_index()
    chart_df.columns = ["severity", "count"]

    fig = px.bar(
        chart_df,
        x="severity",
        y="count",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        text="count"
    )

    fig.update_traces(
        textposition="outside",
        marker_line_width=0
    )

    fig.update_layout(
        showlegend=False,
        xaxis_title=x_title,
        yaxis_title=y_title,
        margin=dict(l=10, r=10, t=10, b=10),
        height=320
    )

    return fig


def badge_priority(value):
    """
    Préfixe la priorité CISA d'un indicateur coloré (émoji), lisible
    d'un coup d'œil façon SOC/SIEM. st.dataframe n'interprète pas le
    HTML dans les cellules, donc on reste sur de l'émoji + texte,
    qui s'affiche correctement partout.
    """

    if pd.isna(value):
        return "⚪ UNKNOWN"

    text = str(value).strip().upper()

    return PRIORITY_BADGES.get(text, f"⚪ {text}")


def fill_priority_badges(frame, column="priority"):

    frame = frame.copy()

    if column in frame.columns:
        frame[column] = frame[column].apply(badge_priority)

    return frame


# =========================================================
# STYLE
# =========================================================

st.markdown("""
<style>

    .main {
        padding-top: 1rem;
    }

    .block-container {
        max-width: 1500px;
        padding-top: 1.5rem;
    }

    .app-header {
        padding: 0.5rem 0 1rem 0;
    }

    .app-title {
        font-size: 2.3rem;
        font-weight: 700;
        margin-bottom: 0.1rem;
    }

    .app-subtitle {
        color: #7f8c8d;
        font-size: 1rem;
        margin-bottom: 1rem;
    }

    .section-title {
        font-size: 1.35rem;
        font-weight: 600;
        margin-top: 1rem;
    }

    .status-card {
        padding: 1rem;
        border-radius: 0.6rem;
        border: 1px solid rgba(128,128,128,0.25);
        background: rgba(128,128,128,0.05);
    }

    .server-card {
        padding: 1.2rem;
        border-radius: 0.6rem;
        border: 1px solid rgba(128,128,128,0.25);
        margin-bottom: 0.8rem;
    }

    div[data-testid="stMetric"] {
        padding: 0.5rem;
    }

</style>
""", unsafe_allow_html=True)


# =========================================================
# DATA LOADERS
# =========================================================

@st.cache_data(ttl=CACHE_TTL_SECONDS)
def load_vulnerabilities():

    conn = get_connection()

    df = pd.read_sql_query(
        """
        SELECT
            cve_id,
            vendor,
            product,
            vulnerability_name,
            description,
            date_added,
            due_date,
            known_ransomware,
            source,
            risk_score,
            priority,
            cvss_v3_score,
            cvss_v3_severity,
            cvss_v3_vector,
            cvss_v4_score,
            cvss_v4_severity,
            cvss_v4_vector,
            cwe,
            nvd_description,
            nvd_published,
            nvd_last_modified,
            nvd_enriched,
            nvd_status,
            ai_summary,
            ai_impact,
            ai_recommendation,
            ai_confidence,
            ai_model,
            ai_generated_at,
            ai_status
        FROM vulnerabilities
        """,
        conn
    )

    conn.close()

    return df


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def load_exposure():

    conn = get_connection()

    df = pd.read_sql_query(
        """
        SELECT
            cve_id,
            affected_devices,
            affected_products,
            defender_severity,
            exploitability_level,
            security_update_available,
            recommended_security_updates,
            recommended_security_update_ids,
            ransomware,
            generated_at
        FROM cisa_defender_exposure
        """,
        conn
    )

    conn.close()

    return df


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def get_top_vulnerable_devices(limit=15):

    conn = get_connection()

    df = pd.read_sql_query(
        """
        SELECT
            d.device_id,
            MAX(d.device_name) AS device_name,
            COALESCE(MAX(ao.owner_name), 'Non attribué') AS owner_name,
            COALESCE(MAX(ao.owner_email), 'N/A') AS owner_email,
            COUNT(DISTINCT d.cve_id) AS cisa_cve_count
        FROM defender_vulnerabilities d
        INNER JOIN vulnerabilities v
            ON d.cve_id = v.cve_id
        LEFT JOIN asset_owners ao
            ON ao.device_id = d.device_id
        WHERE
            v.source = 'CISA KEV'
            AND d.device_name IS NOT NULL
            AND TRIM(d.device_name) <> ''
        GROUP BY
            d.device_id
        ORDER BY
            cisa_cve_count DESC,
            device_name ASC
        LIMIT ?
        """,
        conn,
        params=(limit,)
    )

    conn.close()
    return df


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def get_server_metrics():

    conn = get_connection()

    total_servers = conn.execute(
        """
        SELECT COUNT(DISTINCT d.device_id)
        FROM defender_vulnerabilities d
        WHERE LOWER(COALESCE(d.os_platform, ''))
                LIKE '%windowsserver%'
            OR
            LOWER(COALESCE(d.os_platform, ''))
                LIKE '%windows server%'
        """
    ).fetchone()[0]

    vulnerable_servers = conn.execute(
        """
        SELECT COUNT(DISTINCT d.device_id)

        FROM defender_vulnerabilities d

        INNER JOIN vulnerabilities v
            ON d.cve_id = v.cve_id


        WHERE
            (
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windowsserver%'
                OR
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windows server%'
            )

            AND v.source = 'CISA KEV'
        """
    ).fetchone()[0]

    critical_servers = conn.execute(
        """
        SELECT COUNT(DISTINCT d.device_id)

        FROM defender_vulnerabilities d

        INNER JOIN vulnerabilities v
            ON d.cve_id = v.cve_id


        WHERE
            (
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windowsserver%'
                OR
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windows server%'
            )

            AND v.source = 'CISA KEV'
            AND v.priority = 'CRITICAL'
        """
    ).fetchone()[0]

    server_cves = conn.execute(
        """
        SELECT COUNT(DISTINCT d.cve_id)

        FROM defender_vulnerabilities d

        INNER JOIN vulnerabilities v
            ON d.cve_id = v.cve_id


        WHERE
            (
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windowsserver%'
                OR
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windows server%'
            )

            AND v.source = 'CISA KEV'
        """
    ).fetchone()[0]

    conn.close()

    return {
        "total_servers": total_servers,
        "vulnerable_servers": vulnerable_servers,
        "critical_servers": critical_servers,
        "server_cves": server_cves
    }


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def get_server_cves():

    conn = get_connection()

    df = pd.read_sql_query(
        """
        SELECT
            d.cve_id,
            v.vendor,
            v.product,
            v.priority,
            v.cvss_v3_score,
            v.cvss_v3_severity,
            v.known_ransomware,

            COUNT(DISTINCT d.device_id)
                AS affected_servers,

            COUNT(DISTINCT
                COALESCE(d.software_vendor, '')
                || '|'
                || COALESCE(d.software_name, '')
                || '|'
                || COALESCE(d.software_version, '')
            ) AS affected_products,

            MAX(d.defender_severity)
                AS defender_severity,

            MAX(d.exploitability_level)
                AS exploitability_level,

            MAX(d.security_update_available)
                AS security_update_available,

            GROUP_CONCAT(
                DISTINCT d.recommended_security_update
            ) AS recommended_updates

        FROM defender_vulnerabilities d

        INNER JOIN vulnerabilities v
            ON d.cve_id = v.cve_id


        WHERE
            (
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windowsserver%'
                OR
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windows server%'
            )

            AND v.source = 'CISA KEV'

        GROUP BY
            d.cve_id,
            v.vendor,
            v.product,
            v.priority,
            v.cvss_v3_score,
            v.cvss_v3_severity,
            v.known_ransomware

        ORDER BY
            CASE v.priority
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            affected_servers DESC
        """,
        conn
    )

    conn.close()

    return df


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def get_server_inventory():

    conn = get_connection()

    df = pd.read_sql_query(
        """
        SELECT
            d.device_id,
            d.device_name,
            d.os_platform,
            d.os_version,

            m.owner AS owner,
            COALESCE(m.notification, 0) AS notification,

            COUNT(
                DISTINCT
                CASE
                    WHEN v.source = 'CISA KEV'
                    THEN d.cve_id
                END
            ) AS cve_count,

            COUNT(
                DISTINCT
                CASE
                    WHEN v.source = 'CISA KEV'
                        AND v.priority = 'CRITICAL'
                    THEN d.cve_id
                END
            ) AS critical_cve_count,

            COUNT(
                DISTINCT
                CASE
                    WHEN v.source = 'CISA KEV'
                        AND v.priority = 'MEDIUM'
                    THEN d.cve_id
                END
            ) AS medium_cve_count

        FROM defender_vulnerabilities d


        LEFT JOIN vulnerabilities v
            ON d.cve_id = v.cve_id
            AND v.source = 'CISA KEV'

        LEFT JOIN manual_server_owners m
            ON m.device_name = d.device_name

        WHERE
            (
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windowsserver%'
                OR
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windows server%'
            )

        GROUP BY
            d.device_id,
            d.device_name,
            d.os_platform,
            d.os_version,
            m.owner,
            m.notification

        ORDER BY
            critical_cve_count DESC,
            cve_count DESC,
            d.device_name ASC
        """,
        conn
    )

    conn.close()

    return df


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def get_server_cve_devices(cve_id):

    conn = get_connection()

    df = pd.read_sql_query(
        """
        SELECT DISTINCT
            d.device_id,
            d.device_name,
            d.os_platform,
            d.os_version,
            d.software_vendor,
            d.software_name,
            d.software_version,
            d.defender_severity,
            d.exploitability_level,
            d.security_update_available,
            d.recommended_security_update,
            d.recommended_security_update_id,
            d.first_seen_timestamp,
            d.last_seen_timestamp

        FROM defender_vulnerabilities d


        WHERE
            d.cve_id = ?

            AND (
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windowsserver%'
                OR
                LOWER(COALESCE(d.os_platform, ''))
                    LIKE '%windows server%'
            )

        ORDER BY
            d.device_name ASC
        """,
        conn,
        params=(cve_id,)
    )

    conn.close()

    return df


# =========================================================
# LOAD DATA
# =========================================================

# =========================================================
# PREPARATION
# =========================================================
#
# Toute la préparation (fusion avec l'exposition, colonnes calculées,
# découpage CISA / NVD) porte sur l'ensemble de la table
# vulnerabilities (plusieurs centaines de milliers de CVE avec
# l'historique NVD) : la refaire à chaque clic coûtait plusieurs
# secondes. Elle est mise en cache avec les requêtes qu'elle utilise.


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def load_nvd_exposure():
    return get_nvd_defender_exposure()


# Agrège TOUT defender_vulnerabilities (plusieurs millions de lignes) :
# Streamlit exécute le code de tous les onglets à chaque clic, donc
# sans cache l'onglet Veille ralentissait toute l'application.
@st.cache_data(ttl=CACHE_TTL_SECONDS)
def load_recent_defender_detections(limit=200, search=None):
    return get_recent_defender_detections(limit=limit, search=search)


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def prepare_vulnerability_frames():
    """
    Retourne (df_cisa, df_nvd), ou (None, None) si la base est vide.
    """

    df = load_vulnerabilities()
    exposure_df = load_exposure()

    if df.empty:
        return None, None

    df["due_date_dt"] = pd.to_datetime(
        df["due_date"],
        errors="coerce"
    )

    today = pd.Timestamp(date.today())

    df["overdue"] = (
        df["due_date_dt"].notna()
        &
        (df["due_date_dt"] < today)
    )

    df["ransomware_known"] = (
        df["known_ransomware"]
        .fillna("")
        .str.lower()
        .eq("known")
    )

    df = df.merge(
        exposure_df,
        on="cve_id",
        how="left",
        suffixes=("", "_exposure")
    )

    df["affected_devices"] = (
        df["affected_devices"]
        .fillna(0)
        .astype(int)
    )

    df["affected_products"] = (
        df["affected_products"]
        .fillna(0)
        .astype(int)
    )

    df["environment_status"] = (
        df["affected_devices"]
        .gt(0)
        .map(
            {
                True: "PRESENT",
                False: "NOT PRESENT"
            }
        )
    )

    # `df` ramène TOUTES les sources (CISA KEV + NVD, depuis que
    # sync_nvd_feed.py alimente aussi `vulnerabilities`). Le tableau
    # de bord, l'onglet "CISA KEV" et "Investigation CVE" sont, par
    # leur nom même, scopés CISA KEV : ils utilisent `df_cisa`.
    # `df_nvd` sert aux métriques NVD dédiées (voir tableau de bord
    # ci-dessous) — pour le détail et les alertes de correspondance
    # XDR, voir l'onglet "Veille", qui n'est volontairement pas limité
    # à une seule source.
    df_cisa = df[df["source"] == "CISA KEV"].copy()

    # Seules ces colonnes servent aux métriques NVD : on évite de
    # garder (et de recopier à chaque lecture du cache) toute la table.
    df_nvd = df.loc[
        df["source"] == "NVD",
        ["cve_id", "priority"]
    ].copy()

    # `cisa_defender_exposure` (fusionné dans `df` plus haut) est
    # volontairement limité aux CVE CISA KEV avec un propriétaire
    # résolu -- il ne contient donc JAMAIS de ligne pour une CVE
    # source='NVD', et `affected_devices`/`affected_products` valaient
    # 0 pour TOUTE CVE NVD, quel que soit son nombre réel de
    # correspondances dans l'inventaire XDR. On recalcule ici la vraie
    # présence NVD <-> XDR (voir get_nvd_defender_exposure() pour la
    # différence de portée).
    nvd_exposure = load_nvd_exposure()

    df_nvd["affected_devices"] = df_nvd["cve_id"].map(
        lambda cve_id: nvd_exposure.get(cve_id, {}).get("affected_devices", 0)
    )

    df_nvd["affected_products"] = df_nvd["cve_id"].map(
        lambda cve_id: nvd_exposure.get(cve_id, {}).get("affected_products", 0)
    )

    return df_cisa, df_nvd


df_cisa, df_nvd = prepare_vulnerability_frames()

if df_cisa is None:

    st.warning(
        "Aucune vulnérabilité trouvée dans la base de données."
    )

    st.stop()


# =========================================================
# HEADER
# =========================================================

st.markdown("""
<div class="app-header">
    <div class="app-title">VulnWatch AI</div>
    <div class="app-subtitle">
        CISA KEV &nbsp;•&nbsp;
        NVD &nbsp;•&nbsp;
        Microsoft Defender
    </div>
</div>
""", unsafe_allow_html=True)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.header("VulnWatch AI")

    current_username = st.session_state.get(
        "authenticated_username",
        "admin"
    )

    st.success(
        f"Connecté en tant que {current_username} "
        f"({ROLES.get(CURRENT_USER['role'], CURRENT_USER['role'])})"
    )

    if not IS_ADMIN:
        st.caption(
            "🔒 Accès en consultation : configuration, imports et "
            "synchronisations réservés aux administrateurs."
        )

    if st.button("🔄 Rafraîchir les données", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    if st.button("Se déconnecter", use_container_width=True):
        logout()
        st.rerun()

    st.write("Plateforme de renseignement sécurité")

    st.divider()

    with st.expander("🔐 Mon compte"):

        st.caption("Changer mon mot de passe.")

        if password_change_form(current_username, "account_password"):
            st.success("Mot de passe changé.")

    if IS_ADMIN:

        with st.expander("👥 Utilisateurs"):

            users = list_users()

            st.dataframe(
                pd.DataFrame([
                    {
                        "Utilisateur": u["username"],
                        "Rôle": ROLES.get(u["role"], u["role"]),
                        "Actif": "Oui" if u["active"] else "Non",
                        "Mot de passe à changer": (
                            "Oui" if u["must_change_password"] else ""
                        ),
                        "Dernière connexion": format_sync_timestamp(
                            u["last_login_at"]
                        ) if u["last_login_at"] else ""
                    }
                    for u in users
                ]),
                use_container_width=True,
                hide_index=True
            )

            st.markdown("**Créer un compte**")

            new_user_name = st.text_input(
                "Nom d'utilisateur", key="new_user_name"
            )

            new_user_role = st.selectbox(
                "Rôle",
                list(ROLES),
                index=list(ROLES).index("viewer"),
                format_func=ROLES.get,
                key="new_user_role",
                help="Lecteur : consultation et rafraîchissement seulement "
                     "(aucune configuration, aucun import, aucune "
                     "synchronisation)."
            )

            new_user_password = st.text_input(
                "Mot de passe provisoire",
                type="password",
                key="new_user_password"
            )

            render_password_policy(new_user_password)

            new_user_must_change = st.checkbox(
                "Changer le mot de passe à la première connexion",
                value=True,
                key="new_user_must_change"
            )

            if st.button(
                "Créer le compte", use_container_width=True,
                type="primary", key="new_user_create"
            ):
                try:
                    create_user(
                        new_user_name,
                        new_user_password,
                        role=new_user_role,
                        must_change_password=new_user_must_change,
                        created_by=current_username
                    )
                except ValueError as error:
                    st.error(str(error))
                else:
                    for key in ("new_user_name", "new_user_password"):
                        st.session_state.pop(key, None)
                    st.success(f"Compte « {new_user_name.strip()} » créé.")
                    st.rerun()

            others = [u["username"] for u in users if u["username"] != current_username]

            if others:

                st.markdown("**Gérer un compte**")

                managed_name = st.selectbox(
                    "Utilisateur", others, key="managed_user"
                )

                managed = get_user(managed_name)

                managed_role = st.selectbox(
                    "Rôle",
                    list(ROLES),
                    index=list(ROLES).index(managed["role"]),
                    format_func=ROLES.get,
                    key=f"managed_role_{managed_name}"
                )

                managed_active = st.checkbox(
                    "Compte actif",
                    value=managed["active"],
                    key=f"managed_active_{managed_name}"
                )

                if st.button(
                    "Enregistrer", use_container_width=True,
                    key=f"managed_save_{managed_name}"
                ):
                    try:
                        update_user(
                            managed_name,
                            role=managed_role if managed_role != managed["role"] else None,
                            active=managed_active if managed_active != managed["active"] else None
                        )
                    except ValueError as error:
                        st.error(str(error))
                    else:
                        st.success("Compte mis à jour.")
                        st.rerun()

                reset_password = st.text_input(
                    "Nouveau mot de passe provisoire",
                    type="password",
                    key=f"managed_reset_{managed_name}"
                )

                if reset_password:
                    render_password_policy(reset_password)

                if st.button(
                    "Réinitialiser le mot de passe",
                    use_container_width=True,
                    key=f"managed_reset_btn_{managed_name}",
                    help="L'utilisateur devra le changer à sa prochaine "
                         "connexion ; ses sessions ouvertes sont fermées."
                ):
                    try:
                        set_user_password(
                            managed_name, reset_password,
                            must_change_password=True
                        )
                    except ValueError as error:
                        st.error(str(error))
                    else:
                        st.session_state.pop(f"managed_reset_{managed_name}", None)
                        st.success(
                            "Mot de passe réinitialisé : à changer à la "
                            "prochaine connexion."
                        )

                if st.button(
                    f"Supprimer « {managed_name} »",
                    use_container_width=True,
                    key=f"managed_delete_{managed_name}"
                ):
                    try:
                        delete_user(managed_name)
                    except ValueError as error:
                        st.error(str(error))
                    else:
                        st.success("Compte supprimé.")
                        st.rerun()

    # Configuration réservée aux administrateurs.
    if IS_ADMIN:

        with st.expander("☁️ Application Azure (Defender / Graph)"):

            azure_config = get_azure_app_config()

            if is_azure_app_configured(azure_config):
                st.success("Synchros Defender via l'application Azure.")
            else:
                st.caption(
                    "Non configurée : les synchros Defender utilisent le "
                    "compte connecté à Azure CLI (az login)."
                )

            with st.popover("Comment créer l'application ?", use_container_width=True):

                st.markdown(
                    "1. **Portail Entra ID** > Inscriptions d'applications > "
                    "**Nouvelle inscription** (ex. *VulnWatch*), comptes de "
                    "cet annuaire uniquement, sans URI de redirection.\n"
                    "2. Noter l'**ID d'application (client)** et l'**ID de "
                    "l'annuaire (tenant)**.\n"
                    "3. **Certificats et secrets** > Nouveau secret client : "
                    "copier la **valeur** (affichée une seule fois). Notez la "
                    "date d'expiration.\n"
                    "4. **Autorisations d'API** > Ajouter une autorisation, "
                    "type **Autorisations d'application** :"
                )

                for resource, roles in REQUIRED_ROLES.items():
                    st.markdown(
                        f"**{API_LABELS[resource]}**"
                        + (" — onglet *API utilisées par mon organisation*, "
                           "rechercher *WindowsDefenderATP*"
                           if "Defender" in API_LABELS[resource] else "")
                    )
                    for role, usage in roles.items():
                        st.markdown(f"- `{role}` : {usage}")

                st.markdown(
                    "5. **Accorder un consentement d'administrateur** pour "
                    "l'organisation (bouton dans *Autorisations d'API*).\n"
                    "6. Renseigner les trois valeurs ci-dessous, enregistrer, "
                    "puis **Tester**."
                )

            azure_tenant = st.text_input(
                "ID de l'annuaire (tenant)",
                value=azure_config["tenant_id"],
                key="azure_tenant_id"
            )

            azure_client = st.text_input(
                "ID d'application (client)",
                value=azure_config["client_id"],
                key="azure_client_id"
            )

            azure_secret = st.text_input(
                "Secret client",
                type="password",
                value="",
                placeholder=(
                    "Défini (variable d'environnement)" if azure_config["secret_from_env"]
                    else "Enregistré — laisser vide pour le conserver"
                    if azure_config["client_secret"] else "Valeur du secret"
                ),
                key="azure_client_secret",
                help="Stocké dans la base VulnWatch (comme le mot de passe "
                     "SMTP). Pour ne pas le stocker : variable d'environnement "
                     "VULNWATCH_AZURE_CLIENT_SECRET."
            )

            azure_enabled = st.checkbox(
                "Utiliser cette application pour les synchros Defender",
                value=azure_config["enabled"] or not azure_config["client_id"],
                key="azure_enabled"
            )

            az1, az2, az3 = st.columns(3)

            with az1:
                azure_save = st.button("Enregistrer", use_container_width=True, key="azure_save")

            with az2:
                azure_test = st.button("Tester", use_container_width=True, key="azure_test")

            with az3:
                azure_clear = st.button("Supprimer", use_container_width=True, key="azure_clear")

            if azure_save:

                if not azure_tenant.strip() or not azure_client.strip():
                    st.error("ID de l'annuaire et ID d'application obligatoires.")
                elif not azure_secret and not azure_config["client_secret"]:
                    st.error("Secret client obligatoire.")
                else:
                    set_azure_app_config(
                        azure_tenant, azure_client, azure_secret, azure_enabled
                    )
                    st.success("Application Azure enregistrée.")
                    st.rerun()

            if azure_clear:
                clear_azure_app_config()
                st.success("Application Azure supprimée : retour à Azure CLI.")
                st.rerun()

            if azure_test:

                # Test avec les valeurs saisies (même non enregistrées).
                test_config = dict(
                    azure_config,
                    tenant_id=azure_tenant.strip(),
                    client_id=azure_client.strip(),
                    client_secret=azure_secret.strip() or azure_config["client_secret"]
                )

                if not (
                    test_config["tenant_id"] and test_config["client_id"]
                    and test_config["client_secret"]
                ):
                    st.error("Renseignez le tenant, l'ID d'application et le secret.")
                else:
                    with st.spinner("Test de connexion à Entra ID et aux API..."):
                        azure_results = test_azure_app(test_config)

                    failures = [r for r in azure_results if not r["ok"]]

                    if failures:
                        st.error(
                            f"{len(failures)} vérification(s) en échec sur "
                            f"{len(azure_results)}."
                        )
                    else:
                        st.success("Connexion et permissions OK.")

                    for result in azure_results:
                        st.markdown(
                            f"{'✅' if result['ok'] else '❌'} **{result['check']}** "
                            f"— {result['api']}"
                        )
                        # Texte brut : le détail peut contenir la réponse
                        # d'Entra ID ou de l'API.
                        st.text(result["detail"])

    st.divider()

    st.subheader("Sources de données")

    st.write("CISA KEV")
    st.write("NVD")
    st.write("Microsoft Defender")
    st.write("IA locale (Ollama)")

    st.divider()

    st.subheader("Actions")

    cisa_sync_state = get_sync_state("cisa_kev")

    if cisa_sync_state:

        cisa_status = cisa_sync_state.get("status")

        sync_status_icon = (
            "🟢"
            if cisa_status == "OK"
            else "🟠"
            if cisa_status == "WARNING"
            else "🔴"
        )

        st.caption(
            f"{sync_status_icon} Dernière synchro CISA : "
            f"{format_sync_timestamp(cisa_sync_state.get('last_run_at'))} "
            f"(auto. toutes les {AUTO_SYNC_INTERVAL_HOURS}h)"
        )

        if cisa_status == "WARNING":

            st.warning(
                "Un sync CISA précédent a détecté une perte "
                "d'enrichissement NVD/IA :\n\n"
                f"{cisa_sync_state.get('detail')}"
            )

    else:

        st.caption(
            "⚪ Aucune synchronisation CISA effectuée pour le moment "
            f"(auto. toutes les {AUTO_SYNC_INTERVAL_HOURS}h)"
        )

    if st.button(
        "Synchroniser CISA",
        use_container_width=True,
        disabled=(is_job_running("sync")) or not IS_ADMIN
    ):

        launch_job("sync.py")

    render_job("sync", warning_state_key="cisa_kev")


    nvd_pending = get_pending_nvd_count()

    nvd_sync_state = get_sync_state("nvd_enrich")

    if nvd_sync_state:

        st.caption(
            "🟢 Dernier enrichissement NVD : "
            f"{format_sync_timestamp(nvd_sync_state.get('last_run_at'))} "
            f"· {nvd_pending} CVE en attente "
            f"(auto. {AUTO_NVD_BATCH_SIZE} CVE / "
            f"{AUTO_NVD_INTERVAL_MINUTES} min)"
        )

    else:

        st.caption(
            f"⚪ Aucun enrichissement NVD effectué · "
            f"{nvd_pending} CVE en attente"
        )

    nvd_batch_size = st.number_input(
        "Nombre de CVE à enrichir (NVD)",
        min_value=1,
        value=20,
        step=1,
        key="nvd_batch_size"
    )

    if st.button(
        "Enrichir NVD maintenant",
        use_container_width=True,
        disabled=(is_job_running("enrich")) or not IS_ADMIN
    ):

        env = os.environ.copy()
        env["VULNWATCH_MAX_CVES"] = str(int(nvd_batch_size))

        nvd_api_key_for_manual_enrich = get_nvd_api_key()

        if nvd_api_key_for_manual_enrich:
            env["VULNWATCH_NVD_API_KEY"] = nvd_api_key_for_manual_enrich

        launch_job("enrich.py", env=env)

    render_job("enrich")


    st.divider()

    ai_batch_size = st.number_input(
        "Nombre de CVE à analyser",
        min_value=1,
        max_value=100,
        value=10,
        step=1,
        key="ai_batch_size"
    )

    if st.button(
        "Analyser avec l'IA locale",
        use_container_width=True,
        disabled=(is_job_running("ai_enrich")) or not IS_ADMIN
    ):

        env = os.environ.copy()
        env["VULNWATCH_AI_MAX_CVES"] = str(int(ai_batch_size))

        launch_job("ai_enrich.py", env=env)

    render_job("ai_enrich")


    st.divider()

    st.caption(
        "Priority values are preserved from "
        "the VulnWatch source classification."
    )


# =========================================================
# GLOBAL METRICS
# =========================================================
#
# Scopées CISA KEV (df_cisa), comme avant l'ajout de NVD comme source
# d'entrée — sinon les CVE NVD viendraient gonfler silencieusement un
# total étiqueté "CISA KEV". Les métriques NVD ont leur propre bloc
# juste en dessous.

total = len(df_cisa)

critical = int(
    (df_cisa["priority"] == "CRITICAL").sum()
)

high = int(
    (df_cisa["priority"] == "HIGH").sum()
)

medium = int(
    (df_cisa["priority"] == "MEDIUM").sum()
)

present = int(
    (df_cisa["affected_devices"] > 0).sum()
)

affected_devices = int(
    df_cisa.loc[
        df_cisa["affected_devices"] > 0,
        "affected_devices"
    ].sum()
)


# NVD (source principale, voir sync_nvd_feed.py) : total des CVE
# publiées récupérées, et combien d'entre elles ont une correspondance
# dans l'inventaire XDR (c'est ce sous-ensemble qui déclenche les
# alertes de l'onglet "Veille").

nvd_total = len(df_nvd)

nvd_present = int(
    (df_nvd["affected_devices"] > 0).sum()
)

nvd_critical = int(
    (df_nvd["priority"] == "CRITICAL").sum()
)


# =========================================================
# TABS
# =========================================================

tab_dashboard, tab_servers, tab_kev, tab_nvd, tab_inventory, tab_investigation, tab_notifications, tab_attack_surface, tab_watch = st.tabs(
    [
        "Tableau de bord",
        "Serveurs",
        "CISA KEV",
        "CVE NVD",
        "Inventaire",
        "Investigation CVE",
        "Notifications",
        "Attack Surface",
        "Veille"
    ]
)


# =========================================================
# DASHBOARD TAB
# =========================================================

with tab_dashboard:

    st.subheader("Vue d’ensemble de la sécurité")

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric(
        "CISA KEV",
        f"{total:,}"
    )

    c2.metric(
        "CRITICAL",
        f"{critical:,}"
    )

    c3.metric(
        "HIGH",
        f"{high:,}"
    )

    c4.metric(
        "Présentes dans l’environnement",
        f"{present:,}"
    )

    c5.metric(
        "Équipements affectés",
        f"{affected_devices:,}"
    )

    st.caption("CISA KEV (catalogue d'exploitation active confirmée)")

    n1, n2, n3 = st.columns(3)

    n1.metric(
        "NVD",
        f"{nvd_total:,}"
    )

    n2.metric(
        "NVD — CRITICAL",
        f"{nvd_critical:,}"
    )

    n3.metric(
        "NVD présentes dans l’environnement",
        f"{nvd_present:,}"
    )

    st.caption(
        "NVD (source principale, synchronisation quotidienne — voir "
        "l'onglet Veille) : total des CVE récemment publiées suivies, "
        "et combien ont une correspondance confirmée dans l'inventaire "
        "XDR."
    )

    st.divider()

    st.markdown(
        "### Top 15 Most Vulnerable Devices"
    )
    st.caption(
        "Classement selon le nombre de CVE CISA KEV distinctes détectées par Microsoft Defender."
    )

    top_devices = get_top_vulnerable_devices(15)

    if top_devices.empty:
        st.info(
            "Aucun équipement vulnérable trouvé dans les données CISA KEV actuelles."
        )
    else:
        top_devices["chart_label"] = (
            top_devices["device_name"].fillna("Unknown Device")
            + " — "
            + top_devices["owner_name"].fillna("Non attribué")
        )

        chart_data = top_devices.sort_values(
            "cisa_cve_count",
            ascending=True
        )

        devices_fig = px.bar(
            chart_data,
            x="cisa_cve_count",
            y="chart_label",
            orientation="h",
            color="cisa_cve_count",
            color_continuous_scale="Reds",
            text="cisa_cve_count",
            hover_data={
                "owner_email": True,
                "cisa_cve_count": True,
                "chart_label": False
            }
        )

        devices_fig.update_traces(
            textposition="outside"
        )

        devices_fig.update_layout(
            showlegend=False,
            coloraxis_showscale=False,
            xaxis_title="Nombre de CVE CISA KEV",
            yaxis_title="",
            margin=dict(l=10, r=10, t=10, b=10),
            height=max(320, 28 * len(chart_data))
        )

        st.plotly_chart(
            devices_fig,
            use_container_width=True
        )

        top_devices_display = top_devices[[
            "device_name",
            "owner_name",
            "owner_email",
            "cisa_cve_count"
        ]].rename(
            columns={
                "device_name": "Équipement",
                "owner_name": "Propriétaire",
                "owner_email": "E-mail propriétaire",
                "cisa_cve_count": "Nombre de CVE CISA KEV"
            }
        )

        st.dataframe(
            top_devices_display,
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    left, right = st.columns(2)

    with left:

        st.markdown(
            "### CISA Priority"
        )

        priority_counts = (
            df_cisa["priority"]
            .value_counts()
            .reindex(
                [
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW"
                ],
                fill_value=0
            )
        )

        st.plotly_chart(
            plot_severity_bar(
                priority_counts,
                x_title="Priorité CISA",
                y_title="Nombre de CVE"
            ),
            use_container_width=True
        )


    with right:

        st.markdown(
            "### NVD CVSS Severity"
        )

        nvd_counts = (
            df_cisa["cvss_v3_severity"]
            .fillna("N/A")
            .str.upper()
            .value_counts()
        )

        st.plotly_chart(
            plot_severity_bar(
                nvd_counts,
                x_title="Sévérité NVD",
                y_title="Nombre de CVE"
            ),
            use_container_width=True
        )


    st.divider()

    st.markdown(
        "### CISA KEV Present in Environment"
    )

    exposed = df_cisa[
        df_cisa["affected_devices"] > 0
    ].copy()

    if exposed.empty:

        st.info(
            "No CISA KEV currently matched "
            "in the Defender environment."
        )

    else:

        display = exposed[
            [
                "cve_id",
                "vendor",
                "product",
                "priority",
                "cvss_v3_score",
                "cvss_v3_severity",
                "affected_devices",
                "defender_severity",
                "exploitability_level"
            ]
        ].copy()

        display = fill_nvd_placeholders(display)
        display = fill_priority_badges(display)

        display = display.rename(
            columns={
                "cve_id": "CVE",
                "vendor": "Éditeur",
                "product": "Product",
                "priority": "Priorité CISA",
                "cvss_v3_score": "CVSS 3.1",
                "cvss_v3_severity": "Sévérité NVD",
                "affected_devices": "Devices",
                "defender_severity": "Sévérité Defender",
                "exploitability_level": "Exploitabilité"
            }
        )

        st.dataframe(
            display,
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# SERVERS TAB
# =========================================================

with tab_servers:

    st.subheader(
        "Sécurité des serveurs Windows"
    )

    st.caption(
        "Servers are identified from Defender "
        "devices running Windows Server."
    )

    metrics = get_server_metrics()

    s1, s2, s3, s4 = st.columns(4)

    s1.metric(
        "Serveurs Windows",
        f"{metrics['total_servers']:,}"
    )

    s2.metric(
        "Serveurs avec CISA KEV",
        f"{metrics['vulnerable_servers']:,}"
    )

    s3.metric(
        "Serveurs avec KEV CRITIQUE",
        f"{metrics['critical_servers']:,}"
    )

    s4.metric(
        "CVE CISA sur les serveurs",
        f"{metrics['server_cves']:,}"
    )

    st.divider()

    server_cves = get_server_cves()

    if server_cves.empty:

        st.success(
            "No CISA KEV vulnerability has "
            "been detected on Windows Servers."
        )

    else:

        st.markdown(
            "### Top CISA KEV Vulnerabilities on Servers"
        )

        server_display = fill_priority_badges(
            fill_nvd_placeholders(
                server_cves[
                    [
                        "cve_id",
                        "vendor",
                        "product",
                        "priority",
                        "cvss_v3_score",
                        "cvss_v3_severity",
                        "affected_servers",
                        "affected_products",
                        "defender_severity",
                        "exploitability_level",
                        "security_update_available",
                        "recommended_updates"
                    ]
                ]
            )
        ).rename(
            columns={
                "cve_id": "CVE",
                "vendor": "Éditeur",
                "product": "Product",
                "priority": "Priorité CISA",
                "cvss_v3_score": "CVSS 3.1",
                "cvss_v3_severity": "Sévérité NVD",
                "affected_servers": "Serveurs",
                "affected_products": "Produits",
                "defender_severity": "Sévérité Defender",
                "exploitability_level": "Exploitabilité",
                "security_update_available": "Mise à jour disponible",
                "recommended_updates": "Mise à jour recommandée"
            }
        )

        st.dataframe(
            server_display,
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    st.markdown(
        "### Windows Server Inventory"
    )

    with st.expander(
        "Importer propriétaires / notification (CSV)"
    ):

        st.caption(
            "Colonnes attendues : nom du serveur (device / device_name / "
            "server / serveur), owner, notification (1/0, TRUE/FALSE, "
            "oui/non ou x). Le nom du serveur doit correspondre à celui "
            "affiché dans la colonne \"Server\" ci-dessous. Le champ "
            "\"owner\" doit être une **adresse e-mail** : c'est elle qui "
            "reçoit les alertes / relances (onglet Notifications) si la "
            "notification est activée."
        )

        owners_csv = st.file_uploader(
            "Fichier CSV",
            type=["csv"],
            key="owners_csv_uploader",
            disabled=not IS_ADMIN
        )

        if owners_csv is not None:

            try:

                owners_df = pd.read_csv(owners_csv)

            except Exception as error:

                owners_df = None

                st.error(
                    f"Impossible de lire le CSV : {error}"
                )

            if owners_df is not None:

                normalized = {
                    col: str(col).strip().lower()
                    for col in owners_df.columns
                }

                device_col = next(
                    (
                        col for col, norm in normalized.items()
                        if norm in {
                            "divise", "device", "device_name",
                            "server", "serveur"
                        }
                    ),
                    None
                )

                owner_col = next(
                    (
                        col for col, norm in normalized.items()
                        if norm in {"owner", "proprietaire", "propriétaire"}
                    ),
                    None
                )

                notification_col = next(
                    (
                        col for col, norm in normalized.items()
                        if norm in {"notification", "notif", "notify"}
                    ),
                    None
                )

                if not device_col or not owner_col or not notification_col:

                    st.error(
                        "Le CSV doit contenir 3 colonnes : nom du serveur, "
                        "owner, notification. Colonnes détectées : "
                        + ", ".join(str(c) for c in owners_df.columns)
                    )

                else:

                    def _parse_notification(value):

                        if pd.isna(value):
                            return 0

                        text = str(value).strip().lower()

                        return (
                            1
                            if text in {
                                "1", "1.0", "true", "vrai",
                                "oui", "yes", "x"
                            }
                            else 0
                        )

                    owners_rows = [
                        {
                            "device_name": str(
                                row[device_col]
                            ).strip(),
                            "owner": (
                                str(row[owner_col]).strip()
                                if pd.notna(row[owner_col])
                                else None
                            ),
                            "notification": _parse_notification(
                                row[notification_col]
                            )
                        }
                        for _, row in owners_df.iterrows()
                        if pd.notna(row[device_col])
                        and str(row[device_col]).strip()
                    ]

                    st.write(
                        f"{len(owners_rows)} ligne(s) détectée(s)."
                    )

                    if st.button(
                        "Importer",
                        key="import_owners_btn",
                        disabled=not IS_ADMIN
                    ):

                        imported = import_manual_server_owners(
                            owners_rows
                        )

                        st.success(
                            f"{imported} propriétaire(s)/notification(s) "
                            "importé(s)."
                        )

                        st.cache_data.clear()

                        st.rerun()

    servers = get_server_inventory()

    if servers.empty:

        st.info(
            "Aucun serveur Windows trouvé."
        )

    else:

        server_count = len(servers)

        st.write(
            f"{server_count:,} Windows Server devices found"
        )

        st.caption(
            "Vous pouvez modifier directement le propriétaire (adresse "
            "e-mail) et la notification dans le tableau, puis cliquer sur "
            "\"Enregistrer les modifications\"."
        )

        servers_editable = servers.copy()

        servers_editable["owner"] = (
            servers_editable["owner"].fillna("")
        )

        servers_editable["notification"] = (
            servers_editable["notification"]
            .fillna(0)
            .astype(int)
            .astype(bool)
        )

        servers_editable = servers_editable.rename(
            columns={
                "device_id": "ID équipement",
                "device_name": "Server",
                "os_platform": "OS",
                "os_version": "Version OS",
                "owner": "Propriétaire",
                "notification": "Notification",
                "cve_count": "Nombre de CVE CISA",
                "critical_cve_count": "CVE critiques",
                "medium_cve_count": "CVE moyennes"
            }
        )

        edited_servers = st.data_editor(
            servers_editable,
            use_container_width=True,
            hide_index=True,
            disabled=([
                "ID équipement",
                "Server",
                "OS",
                "Version OS",
                "Nombre de CVE CISA",
                "CVE critiques",
                "CVE moyennes"
            ]) if IS_ADMIN else True,
            column_config={
                "Propriétaire": st.column_config.TextColumn(
                    "Propriétaire"
                ),
                "Notification": st.column_config.CheckboxColumn(
                    "Notification"
                )
            },
            key="server_inventory_editor"
        )

        if st.button(
            "Enregistrer les modifications",
            key="save_server_inventory_btn",
            disabled=not IS_ADMIN
        ):

            rows_to_save = [
                {
                    "device_name": row["Server"],
                    "owner": (
                        row["Propriétaire"].strip()
                        if isinstance(row["Propriétaire"], str)
                        and row["Propriétaire"].strip()
                        else None
                    ),
                    "notification": (
                        1 if row["Notification"] else 0
                    )
                }
                for _, row in edited_servers.iterrows()
            ]

            imported = import_manual_server_owners(
                rows_to_save
            )

            invalid_email_devices = [
                row["device_name"]
                for row in rows_to_save
                if row["notification"] == 1
                and (not row["owner"] or "@" not in row["owner"])
            ]

            st.session_state.pop(
                "server_inventory_editor",
                None
            )

            st.success(
                f"{imported} serveur(s) mis à jour."
            )

            if invalid_email_devices:

                st.warning(
                    "Notification activée mais propriétaire sans adresse "
                    "e-mail valide pour : "
                    + ", ".join(invalid_email_devices)
                    + ". Ces serveurs ne recevront aucune alerte tant que "
                    "le champ \"Propriétaire\" ne contient pas une adresse "
                    "e-mail."
                )

            st.cache_data.clear()

            st.rerun()

    st.divider()

    st.markdown(
        "### Server Investigation"
    )

    if not servers.empty:

        selected_server = st.selectbox(
            "Sélectionner un serveur",
            servers["device_name"].tolist()
        )

        server = servers[
            servers["device_name"]
            == selected_server
        ].iloc[0]


        a1, a2, a3 = st.columns(3)

        a1.metric(
            "CISA CVE",
            int(server["cve_count"])
        )

        a2.metric(
            "CRITICAL",
            int(server["critical_cve_count"])
        )

        a3.metric(
            "MEDIUM",
            int(server["medium_cve_count"])
        )

        st.write(
            f"**OS:** {server['os_platform']} "
            f"{server['os_version']}"
        )

        conn = get_connection()

        server_cve_df = pd.read_sql_query(
            """
            SELECT DISTINCT

                d.cve_id,
                v.priority,
                v.cvss_v3_score,
                v.cvss_v3_severity,
                d.software_vendor,
                d.software_name,
                d.software_version,
                d.defender_severity,
                d.exploitability_level,
                d.recommended_security_update

            FROM defender_vulnerabilities d

            INNER JOIN vulnerabilities v
                ON d.cve_id = v.cve_id

            WHERE
                d.device_name = ?

                AND v.source = 'CISA KEV'

            ORDER BY
                CASE v.priority
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                d.cve_id
            """,
            conn,
            params=(selected_server,)
        )

        conn.close()

        if not server_cve_df.empty:

            server_cve_df = fill_priority_badges(
                fill_nvd_placeholders(
                    server_cve_df
                )
            ).rename(
                columns={
                    "cve_id": "CVE",
                    "priority": "Priorité CISA",
                    "cvss_v3_score": "CVSS 3.1",
                    "cvss_v3_severity": "Sévérité NVD",
                    "software_vendor": "Éditeur",
                    "software_name": "Logiciel",
                    "software_version": "Version",
                    "defender_severity": "Sévérité Defender",
                    "exploitability_level": "Exploitabilité",
                    "recommended_security_update": "Mise à jour recommandée"
                }
            )

            st.dataframe(
                server_cve_df,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.success(
                "Aucune CISA KEV détectée sur ce serveur."
            )


# =========================================================
# CISA KEV TAB
# =========================================================

with tab_kev:

    st.subheader(
        "Vulnérabilités exploitées connues CISA"
    )

    st.caption(
        "CISA priority is preserved as the "
        "source classification."
    )

    exposed = df_cisa[
        df_cisa["affected_devices"] > 0
    ].copy()

    if exposed.empty:

        st.info(
            "Aucune CISA KEV correspondante dans Defender."
        )

    else:

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "KEV dans l’environnement",
            len(exposed)
        )

        col2.metric(
            "Équipements affectés",
            int(
                exposed["affected_devices"].sum()
            )
        )

        col3.metric(
            "Ransomware connu",
            int(
                exposed["ransomware_known"].sum()
            )
        )

        st.divider()

        priority_filter = st.selectbox(
            "Priorité CISA",
            [
                "ALL",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ]
        )

        search = st.text_input(
            "Rechercher CVE / éditeur / produit"
        )

        result = exposed.copy()

        if priority_filter != "ALL":

            result = result[
                result["priority"]
                == priority_filter
            ]

        if search:

            term = search.lower()

            mask = (
                result["cve_id"]
                .fillna("")
                .str.lower()
                .str.contains(
                    term,
                    na=False
                )
                |
                result["vendor"]
                .fillna("")
                .str.lower()
                .str.contains(
                    term,
                    na=False
                )
                |
                result["product"]
                .fillna("")
                .str.lower()
                .str.contains(
                    term,
                    na=False
                )
            )

            result = result[mask]


        table = fill_priority_badges(
            fill_nvd_placeholders(
                result[
                    [
                        "cve_id",
                        "vendor",
                        "product",
                        "priority",
                        "cvss_v3_score",
                        "cvss_v3_severity",
                        "affected_devices",
                        "affected_products",
                        "defender_severity",
                        "exploitability_level",
                        "security_update_available",
                        "due_date"
                    ]
                ]
            )
        ).rename(
            columns={
                "cve_id": "CVE",
                "vendor": "Éditeur",
                "product": "Product",
                "priority": "Priorité CISA",
                "cvss_v3_score": "CVSS 3.1",
                "cvss_v3_severity": "Sévérité NVD",
                "affected_devices": "Devices",
                "affected_products": "Produits",
                "defender_severity": "Sévérité Defender",
                "exploitability_level": "Exploitabilité",
                "security_update_available": "Mise à jour",
                "due_date": "Date d’échéance CISA"
            }
        )

        st.write(
            f"{len(table):,} CVE displayed"
        )

        st.dataframe(
            table,
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# CVE NVD TAB (toute la base, recherche + fiche détaillée)
# =========================================================

NVD_SEVERITY_LABELS = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "NONE": "⚪ Sans score"
}

NVD_SORT_LABELS = {
    "published_desc": "Publication la plus récente",
    "published_asc": "Publication la plus ancienne",
    "score_desc": "Score CVSS décroissant",
    "modified_desc": "Dernière modification NVD"
}


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_nvd_search(
    search, published_from, published_to, severities, min_score,
    on_parc_only, kev_only, sort, limit, offset
):
    return search_nvd_cves(
        search=search,
        published_from=published_from,
        published_to=published_to,
        severities=list(severities),
        min_score=min_score,
        on_parc_only=on_parc_only,
        kev_only=kev_only,
        sort=sort,
        limit=limit,
        offset=offset
    )


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_cve_details(cve_id):
    return get_cve_details(cve_id)


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_devices_for_cve(cve_id):
    return get_devices_for_cve(cve_id)


# Fiche NVD en ligne : une heure de cache, NVD ne change pas si vite et
# on ménage la limite de requêtes de l'API.
@st.cache_data(ttl=3600, show_spinner=False)
def load_nvd_record(cve_id, api_key):

    nvd_collector.NVD_API_KEY = api_key or None

    record = nvd_collector.fetch_nvd_cve_record(cve_id)

    if not record:
        return None

    # La fiche affichée est aussi enregistrée : si NVD a déclaré les
    # produits vulnérables depuis la dernière synchro, les équipements
    # touchés selon NVD sont recalculés tout de suite.
    bulk_save_nvd_discoveries([(cve_id, nvd_collector.parse_nvd_cve(record))])
    refresh_matches_for_cves([cve_id])

    return nvd_collector.describe_nvd_record(record)


INVENTORY_DEVICE_COLUMNS = {
    "device_name": "Équipement",
    "os_platform": "OS",
    "os_version": "Version OS",
    "software_vendor": "Éditeur",
    "software_name": "Logiciel",
    "software_version": "Version installée",
    "rule": "Versions vulnérables (NVD)",
    "end_of_support_status": "Fin de support",
    "distro_note": "À vérifier"
}


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_inventory_devices_for_cve(cve_id):
    return get_inventory_devices_for_cve(cve_id)


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_inventory_matched_cves(search):
    return get_inventory_matched_cves(search=search or None, limit=500)


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_inventory_status():
    return get_inventory_status()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_cpe_unchecked():
    return count_cves_without_cpe_check()


def format_nvd_date(value):

    if not value:
        return ""

    return str(value)[:16].replace("T", " ")


def render_nvd_cve_details(cve_id):

    details = load_cve_details(cve_id)

    if not details:
        st.warning(f"{cve_id} introuvable dans la base.")
        return

    st.markdown(f"### {cve_id}")

    st.markdown(
        f"[Fiche NVD](https://nvd.nist.gov/vuln/detail/{cve_id}) · "
        f"[CVE.org](https://www.cve.org/CVERecord?id={cve_id})"
    )

    severity = details.get("cvss_v3_severity") or details.get("cvss_v4_severity")

    inventory_devices = get_inventory_device_count(cve_id)

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric(
        "Sévérité",
        NVD_SEVERITY_LABELS.get(str(severity or "NONE").upper(), severity)
    )
    c2.metric(
        "CVSS 3.1",
        f"{details['cvss_v3_score']:.1f}"
        if details.get("cvss_v3_score") is not None else "N/A"
    )
    c3.metric(
        "CVSS 4.0",
        f"{details['cvss_v4_score']:.1f}"
        if details.get("cvss_v4_score") is not None else "N/A"
    )
    c4.metric(
        "Équipements (Defender)",
        details.get("parc_devices") or 0,
        help="Machines où Microsoft Defender a détecté cette CVE "
             "(catalogue Defender, dernier import Defender)."
    )
    c5.metric(
        "Équipements (NVD)",
        inventory_devices,
        help="Machines dont un logiciel installé correspond aux produits "
             "et versions vulnérables déclarés par NVD (inventaire "
             "logiciel x NVD, onglet Veille)."
    )
    c6.metric(
        "Catalogue CISA KEV",
        "Oui" if details.get("source") == "CISA KEV" else "Non"
    )

    d1, d2, d3 = st.columns(3)
    d1.caption(f"**Publiée (NVD)** : {format_nvd_date(details.get('nvd_published')) or 'N/A'}")
    d2.caption(f"**Dernière modification** : {format_nvd_date(details.get('nvd_last_modified')) or 'N/A'}")
    d3.caption(f"**CWE** : {details.get('cwe') or 'N/A'}")

    st.markdown("**Description**")
    st.write(
        details.get("nvd_description")
        or details.get("description")
        or "Pas de description."
    )

    vectors = []

    if details.get("cvss_v3_vector"):
        vectors.append(f"CVSS 3.1 : {details['cvss_v3_vector']}")

    if details.get("cvss_v4_vector"):
        vectors.append(f"CVSS 4.0 : {details['cvss_v4_vector']}")

    if vectors:
        st.code("\n".join(vectors), language="text")

    if details.get("source") == "CISA KEV":

        st.markdown("**CISA KEV**")

        st.write(
            f"{details.get('vulnerability_name') or ''} — "
            f"{details.get('vendor') or ''} {details.get('product') or ''}"
        )

        k1, k2, k3, k4 = st.columns(4)
        k1.caption(f"**Ajoutée au catalogue** : {details.get('date_added') or 'N/A'}")
        k2.caption(f"**Échéance de correction** : {details.get('due_date') or 'N/A'}")
        k3.caption(f"**Ransomware** : {details.get('known_ransomware') or 'N/A'}")
        k4.caption(
            f"**Priorité VulnWatch** : "
            f"{badge_priority(details.get('priority'))} "
            f"(score {details.get('risk_score') or 0})"
        )

    if details.get("ai_summary"):

        with st.expander("Analyse IA (Ollama)"):

            st.markdown(f"**Résumé** : {details.get('ai_summary')}")
            st.markdown(f"**Impact** : {details.get('ai_impact') or ''}")
            st.markdown(f"**Recommandation** : {details.get('ai_recommendation') or ''}")
            st.caption(
                f"Modèle {details.get('ai_model') or ''} — "
                f"{format_nvd_date(details.get('ai_generated_at'))}"
            )

    if inventory_devices:

        with st.expander(
            f"Équipements touchés selon NVD ({inventory_devices})"
        ):

            st.dataframe(
                pd.DataFrame(load_inventory_devices_for_cve(cve_id)).rename(
                    columns=INVENTORY_DEVICE_COLUMNS
                ),
                use_container_width=True,
                hide_index=True
            )

    if details.get("parc_devices"):

        with st.expander(
            f"Équipements touchés selon Defender ({details['parc_devices']})"
        ):

            devices = load_devices_for_cve(cve_id)

            if devices:
                st.dataframe(
                    pd.DataFrame(devices).rename(columns={
                        "device_name": "Équipement",
                        "os_platform": "OS",
                        "os_version": "Version OS",
                        "software_vendor": "Éditeur",
                        "software_name": "Logiciel",
                        "software_version": "Version",
                        "defender_severity": "Sévérité Defender",
                        "exploitability_level": "Exploitabilité",
                        "security_update_available": "Mise à jour",
                        "recommended_security_update": "Mise à jour recommandée",
                        "first_seen_timestamp": "Première détection",
                        "last_seen_timestamp": "Dernière détection"
                    }),
                    use_container_width=True,
                    hide_index=True
                )

    # Détail complet chargé à la demande depuis l'API NVD : références,
    # produits concernés, toutes les métriques (non conservés en base).
    if st.toggle(
        "Afficher le détail complet depuis NVD (références, produits "
        "concernés, toutes les métriques) et mettre à jour cette CVE "
        "dans VulnWatch",
        key=f"nvd_full_{cve_id}"
    ):

        try:

            with st.spinner("Chargement de la fiche NVD..."):
                record = load_nvd_record(cve_id, get_nvd_api_key())

        except Exception as error:

            st.error(f"Fiche NVD indisponible — {error}")
            return

        if not record:
            st.info("NVD ne connaît pas (ou plus) cette CVE.")
            return

        # La fiche NVD vient d'être enregistrée en base : si elle change
        # les machines touchées (produits déclarés depuis la dernière
        # synchro), on recharge une fois avec les chiffres à jour.
        refreshed_key = f"nvd_refreshed_{cve_id}"

        if (
            get_inventory_device_count(cve_id) != inventory_devices
            and not st.session_state.get(refreshed_key)
        ):
            st.session_state[refreshed_key] = True
            st.cache_data.clear()
            st.rerun()

        st.caption(
            f"Statut NVD : **{record['status'] or 'N/A'}** · "
            f"Source : {record['source_identifier'] or 'N/A'} · "
            f"CWE : {', '.join(record['weaknesses']) or 'N/A'}"
        )

        if record["metrics"]:
            st.markdown("**Métriques CVSS**")
            st.dataframe(
                pd.DataFrame(record["metrics"]).rename(columns={
                    "version": "Version",
                    "source": "Source",
                    "type": "Type",
                    "score": "Score",
                    "severity": "Sévérité",
                    "vector": "Vecteur"
                }),
                use_container_width=True,
                hide_index=True
            )

        if record["products"]:
            st.markdown(f"**Produits concernés ({len(record['products'])})**")
            st.dataframe(
                pd.DataFrame(record["products"]).rename(columns={
                    "type": "Type",
                    "vendor": "Éditeur",
                    "product": "Produit",
                    "version": "Version(s)",
                    "vulnerable": "Vulnérable"
                }),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.caption("Aucun produit (CPE) renseigné par NVD pour l'instant.")

        if record["references"]:
            st.markdown(f"**Références ({len(record['references'])})**")
            st.dataframe(
                pd.DataFrame(record["references"]).rename(columns={
                    "url": "Lien",
                    "source": "Source",
                    "tags": "Type"
                }),
                column_config={"Lien": st.column_config.LinkColumn("Lien")},
                use_container_width=True,
                hide_index=True
            )


with tab_nvd:

    st.subheader("CVE NVD — toute la base")

    st.caption(
        "Toutes les CVE connues de VulnWatch (flux NVD, historique, imports "
        "de fichiers NVD et catalogue CISA KEV), avec recherche et filtres. "
        "Sélectionnez une ligne pour afficher sa fiche détaillée."
    )

    f1, f2 = st.columns([3, 1])

    with f1:
        nvd_search = st.text_input(
            "Rechercher",
            placeholder="CVE-2026-12345, fortinet, remote code execution, CWE-79...",
            key="nvd_tab_search"
        )

    with f2:
        nvd_sort = st.selectbox(
            "Trier par",
            list(NVD_SORT_LABELS),
            format_func=NVD_SORT_LABELS.get,
            key="nvd_tab_sort"
        )

    g1, g2, g3, g4 = st.columns(4)

    with g1:
        nvd_from = st.date_input(
            "Publiée depuis le", value=None, key="nvd_tab_from",
            format="DD/MM/YYYY"
        )

    with g2:
        nvd_to = st.date_input(
            "Jusqu'au", value=None, key="nvd_tab_to",
            format="DD/MM/YYYY"
        )

    with g3:
        nvd_severities = st.multiselect(
            "Sévérité",
            list(NVD_SEVERITY_LABELS),
            format_func=NVD_SEVERITY_LABELS.get,
            key="nvd_tab_severities"
        )

    with g4:
        nvd_min_score = st.number_input(
            "Score CVSS minimal", min_value=0.0, max_value=10.0,
            value=0.0, step=0.5, key="nvd_tab_min_score"
        )

    h1, h2, h3 = st.columns([1, 1, 1])

    with h1:
        nvd_on_parc = st.checkbox(
            "Présentes sur le parc uniquement", key="nvd_tab_on_parc"
        )

    with h2:
        nvd_kev_only = st.checkbox(
            "Catalogue CISA KEV uniquement", key="nvd_tab_kev_only"
        )

    with h3:
        nvd_page_size = st.selectbox(
            "Lignes par page", [50, 100, 200], index=1,
            key="nvd_tab_page_size"
        )

    # Retour à la page 1 dès qu'un filtre change.
    nvd_filters = (
        nvd_search, nvd_from, nvd_to, tuple(nvd_severities),
        nvd_min_score, nvd_on_parc, nvd_kev_only, nvd_sort, nvd_page_size
    )

    if st.session_state.get("nvd_tab_filters") != nvd_filters:
        st.session_state["nvd_tab_filters"] = nvd_filters
        st.session_state["nvd_tab_page"] = 1

    nvd_page = int(st.session_state.get("nvd_tab_page", 1))

    nvd_total, nvd_rows = load_nvd_search(
        nvd_search.strip(),
        nvd_from,
        nvd_to,
        tuple(nvd_severities),
        nvd_min_score or None,
        nvd_on_parc,
        nvd_kev_only,
        nvd_sort,
        nvd_page_size,
        (nvd_page - 1) * nvd_page_size
    )

    nvd_pages = max(1, -(-nvd_total // nvd_page_size))

    # Le nombre de pages a pu diminuer (synchro, données modifiées) :
    # Streamlit refuse une valeur au-delà du maximum du champ "Page".
    if nvd_page > nvd_pages:
        st.session_state["nvd_tab_page"] = nvd_pages

    p1, p2 = st.columns([3, 1])

    with p1:
        st.markdown(
            f"**{nvd_total:,} CVE** trouvée(s) — page {nvd_page} / {nvd_pages:,}"
            .replace(",", " ")
        )

    with p2:
        st.number_input(
            "Page", min_value=1, max_value=nvd_pages, step=1,
            key="nvd_tab_page", label_visibility="collapsed"
        )

    if not nvd_rows:

        st.info("Aucune CVE ne correspond à ces critères.")

    else:

        nvd_df = pd.DataFrame(nvd_rows)

        nvd_df["severity"] = nvd_df["severity"].map(
            lambda value: NVD_SEVERITY_LABELS.get(
                str(value or "NONE").upper(), value
            )
        )
        nvd_df["nvd_published"] = nvd_df["nvd_published"].map(format_nvd_date)
        nvd_df["nvd_last_modified"] = nvd_df["nvd_last_modified"].map(format_nvd_date)
        nvd_df["source"] = nvd_df["source"].eq("CISA KEV").map(
            {True: "Oui", False: ""}
        )
        nvd_df["description"] = nvd_df["description"].fillna("").map(
            lambda text: text if len(text) <= 180 else text[:177] + "..."
        )

        nvd_event = st.dataframe(
            nvd_df[[
                "cve_id", "nvd_published", "severity", "cvss_v3_score",
                "cvss_v4_score", "cwe", "affected_devices", "source",
                "nvd_last_modified", "description"
            ]].rename(columns={
                "cve_id": "CVE",
                "nvd_published": "Publiée",
                "severity": "Sévérité",
                "cvss_v3_score": "CVSS 3.1",
                "cvss_v4_score": "CVSS 4.0",
                "cwe": "CWE",
                "affected_devices": "Équipements",
                "source": "CISA KEV",
                "nvd_last_modified": "Modifiée",
                "description": "Description"
            }),
            column_config={
                "CVSS 3.1": st.column_config.NumberColumn(format="%.1f"),
                "CVSS 4.0": st.column_config.NumberColumn(format="%.1f")
            },
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="nvd_tab_table"
        )

        selected_rows = nvd_event.selection.rows if nvd_event else []

        if selected_rows:

            st.divider()
            render_nvd_cve_details(nvd_rows[selected_rows[0]]["cve_id"])

        else:

            st.caption("Cliquez sur une ligne pour afficher la fiche de la CVE.")


# =========================================================
# INVENTAIRE TAB (logiciels par machine / par produit)
# =========================================================

@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_inventory_machines(search):
    return get_inventory_machines(search or None)


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_inventory_products(search):
    return get_inventory_products(search or None)


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_machine_details(device_id):
    return (
        get_machine_software(device_id),
        get_machine_nvd_cves(device_id),
        get_machine_defender_cves(device_id)
    )


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def load_product_details(cpe_vendor, cpe_product):
    return (
        get_product_versions(cpe_vendor, cpe_product),
        get_product_machines(cpe_vendor, cpe_product),
        get_product_nvd_cves(cpe_vendor, cpe_product)
    )


def nvd_cves_frame(rows):
    """Tableau de CVE (onglet Inventaire), colonnes en français."""

    frame = pd.DataFrame(rows)

    frame["severity"] = frame["severity"].map(
        lambda value: NVD_SEVERITY_LABELS.get(str(value or "NONE").upper(), value)
    )
    frame["nvd_published"] = frame["nvd_published"].map(format_nvd_date)
    frame["source"] = frame["source"].eq("CISA KEV").map({True: "Oui", False: ""})
    frame["description"] = frame["description"].fillna("").map(
        lambda text: text if len(text) <= 160 else text[:157] + "..."
    )

    return frame.rename(columns={
        "cve_id": "CVE",
        "nvd_published": "Publiée",
        "severity": "Sévérité",
        "cvss": "CVSS",
        "source": "CISA KEV",
        "software_name": "Logiciel",
        "software_version": "Version installée",
        "versions": "Versions installées touchées",
        "rule": "Versions vulnérables (NVD)",
        "distro_note": "À vérifier",
        "description": "Description"
    })


CVSS_COLUMN = {"CVSS": st.column_config.NumberColumn(format="%.1f")}


def render_machine_details(machine):

    software, nvd_cves, defender_cves = load_machine_details(machine["device_id"])

    st.markdown(f"### 🖥️ {machine['device_name'] or machine['device_id']}")
    st.caption(f"Identifiant Defender : {machine['device_id']}")

    # Inventaire de cette seule machine, relu dans Defender (Advanced
    # Hunting) : utile si l'import global était incomplet ou ancien.
    if st.button(
        "🔄 Actualiser l'inventaire de cette machine depuis Defender",
        key=f"refresh_device_{machine['device_id']}",
        disabled=is_job_running("sync_software_inventory") or not IS_ADMIN,
        help="Recharge tous les logiciels de cette machine (Advanced "
             "Hunting, permission AdvancedQuery.Read.All) puis recalcule "
             "les CVE selon NVD. Les autres machines ne changent pas."
    ):
        env = os.environ.copy()
        env["VULNWATCH_INVENTORY_DEVICE"] = machine["device_id"]
        launch_job("sync_software_inventory.py", env=env)

    render_job("sync_software_inventory", warning_state_key="software_inventory")

    a1, a2, a3, a4, a5 = st.columns(5)
    a1.metric("Système", machine["os_platform"] or "N/A")
    a2.metric("Version", machine["os_version"] or "N/A")
    a3.metric("Logiciels", len(software))
    a4.metric(
        "CVE (NVD)",
        len({row["cve_id"] for row in nvd_cves}),
        help="Logiciels installés comparés aux produits vulnérables NVD."
    )
    a5.metric(
        "CVE (Defender)",
        len({row["cve_id"] for row in defender_cves}),
        help="Dernier import Defender (sync_defender.py)."
    )

    if machine["os_architecture"]:
        st.caption(f"Architecture : {machine['os_architecture']}")

    tab_sw, tab_nvd_cves, tab_def_cves = st.tabs([
        f"Logiciels installés ({len(software)})",
        f"CVE selon NVD ({len({r['cve_id'] for r in nvd_cves})})",
        f"CVE selon Defender ({len({r['cve_id'] for r in defender_cves})})"
    ])

    with tab_sw:

        if software:
            st.dataframe(
                pd.DataFrame(software).rename(columns={
                    "software_vendor": "Éditeur",
                    "software_name": "Logiciel",
                    "software_version": "Version",
                    "cpe": "Identifiant CPE",
                    "end_of_support_status": "Fin de support",
                    "end_of_support_date": "Date de fin de support",
                    "nvd_cves": "CVE (NVD)",
                    "nvd_critical": "dont critiques",
                    "max_cvss": "CVSS max"
                }),
                column_config={"CVSS max": st.column_config.NumberColumn(format="%.1f")},
                use_container_width=True,
                hide_index=True
            )

    with tab_nvd_cves:

        if nvd_cves:
            st.dataframe(
                nvd_cves_frame(nvd_cves)[[
                    "CVE", "Sévérité", "CVSS", "Logiciel", "Version installée",
                    "Versions vulnérables (NVD)", "À vérifier", "Publiée",
                    "CISA KEV", "Description"
                ]],
                column_config=CVSS_COLUMN,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Aucune CVE ne touche cette machine selon NVD.")

    with tab_def_cves:

        if defender_cves:
            st.dataframe(
                pd.DataFrame(defender_cves).rename(columns={
                    "cve_id": "CVE",
                    "software_name": "Logiciel",
                    "software_version": "Version",
                    "defender_severity": "Sévérité Defender",
                    "cvss_score": "CVSS",
                    "exploitability_level": "Exploitabilité",
                    "recommended_security_update": "Mise à jour recommandée",
                    "first_seen_timestamp": "Première détection",
                    "kev": "CISA KEV"
                }),
                column_config=CVSS_COLUMN,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info(
                "Aucune CVE détectée par Defender sur cette machine "
                "(ou machine absente du dernier import Defender)."
            )


def render_product_details(product):

    versions, machines, nvd_cves = load_product_details(
        product["cpe_vendor"], product["cpe_product"]
    )

    st.markdown(
        f"### 📦 {product['software_vendor'] or product['cpe_vendor']} — "
        f"{product['software_name'] or product['cpe_product']}"
    )
    st.caption(
        f"Identifiant CPE : {product['cpe_vendor']}:{product['cpe_product']}"
    )

    b1, b2, b3, b4 = st.columns(4)
    b1.metric("Versions installées", len(versions))
    b2.metric("Machines", len({row["device_id"] for row in machines}))
    b3.metric("CVE (NVD)", len(nvd_cves))
    b4.metric(
        "Machines en fin de support",
        product["eos_installs"] or 0,
        help="Machines dont la version installée n'est plus (ou bientôt "
             "plus) maintenue par l'éditeur, selon Defender."
    )

    tab_versions, tab_machines, tab_cves = st.tabs([
        f"Versions ({len(versions)})",
        f"Machines ({len(machines)})",
        f"CVE selon NVD ({len(nvd_cves)})"
    ])

    with tab_versions:

        st.dataframe(
            pd.DataFrame(versions).rename(columns={
                "software_version": "Version",
                "device_count": "Machines",
                "end_of_support_status": "Fin de support",
                "end_of_support_date": "Date de fin de support",
                "nvd_cves": "CVE (NVD)",
                "max_cvss": "CVSS max"
            }),
            column_config={"CVSS max": st.column_config.NumberColumn(format="%.1f")},
            use_container_width=True,
            hide_index=True
        )

    with tab_machines:

        st.dataframe(
            pd.DataFrame(machines).rename(columns={
                "device_name": "Machine",
                "device_id": "Identifiant",
                "os_platform": "Système",
                "os_version": "Version OS",
                "software_version": "Version installée",
                "end_of_support_status": "Fin de support",
                "software_name": "Paquet / logiciel",
                "distro_note": "À vérifier"
            }),
            use_container_width=True,
            hide_index=True
        )

    with tab_cves:

        if nvd_cves:
            st.dataframe(
                nvd_cves_frame(nvd_cves)[[
                    "CVE", "Sévérité", "CVSS", "Versions installées touchées",
                    "Versions vulnérables (NVD)", "Publiée", "CISA KEV",
                    "Description"
                ]],
                column_config=CVSS_COLUMN,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Aucune CVE ne touche les versions installées selon NVD.")


with tab_inventory:

    st.subheader("Inventaire logiciel")

    st.caption(
        "Logiciels installés sur chaque machine (import Defender ou CSV, "
        "onglet Veille) et CVE qui les touchent selon NVD. Sélectionnez une "
        "ligne pour afficher la fiche complète."
    )

    inventory_overview = load_inventory_status()

    if not inventory_overview["inventory_rows"]:

        st.info(
            "Aucun inventaire importé. Onglet Veille > « Équipements touchés "
            "selon NVD » : « Importer l'inventaire depuis Defender » ou import CSV."
        )

    else:

        o1, o2, o3, o4 = st.columns(4)
        o1.metric("Machines", f"{inventory_overview['inventory_devices']:,}".replace(",", " "))
        o2.metric("Produits distincts", f"{inventory_overview['inventory_products']:,}".replace(",", " "))
        o3.metric("Logiciels installés", f"{inventory_overview['inventory_rows']:,}".replace(",", " "))
        o4.metric(
            "Machines touchées (NVD)",
            f"{inventory_overview['affected_devices']:,}".replace(",", " ")
        )

        st.caption(
            "Inventaire importé le "
            f"{format_sync_timestamp(inventory_overview['inventory_imported_at'])}"
        )

        v1, v2 = st.columns([1, 3])

        with v1:
            inventory_view = st.radio(
                "Afficher",
                ["Par machine", "Par produit"],
                horizontal=True,
                key="inventory_view"
            )

        with v2:
            inventory_tab_search = st.text_input(
                "Rechercher",
                placeholder=(
                    "Nom de machine, OS..." if inventory_view == "Par machine"
                    else "Éditeur ou produit (ex. microsoft, chrome, openssl)"
                ),
                key=f"inventory_tab_search_{inventory_view}"
            )

        if inventory_view == "Par machine":

            machines = load_inventory_machines(inventory_tab_search.strip())

            st.markdown(f"**{len(machines)} machine(s)**")

            if machines:

                machines_df = pd.DataFrame(machines)

                machine_event = st.dataframe(
                    machines_df[[
                        "device_name", "os_platform", "os_version",
                        "os_architecture", "software_count", "eos_count",
                        "nvd_cves", "nvd_critical"
                    ]].rename(columns={
                        "device_name": "Machine",
                        "os_platform": "Système",
                        "os_version": "Version OS",
                        "os_architecture": "Architecture",
                        "software_count": "Logiciels",
                        "eos_count": "En fin de support",
                        "nvd_cves": "CVE (NVD)",
                        "nvd_critical": "dont critiques"
                    }),
                    use_container_width=True,
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    key=f"inventory_machines_table_{inventory_tab_search}"
                )

                selection = machine_event.selection.rows if machine_event else []

                if selection:
                    st.divider()
                    render_machine_details(machines[selection[0]])

        else:

            products = load_inventory_products(inventory_tab_search.strip())

            st.markdown(f"**{len(products)} produit(s)**")

            if products:

                products_df = pd.DataFrame(products)
                products_df["versions"] = products_df["versions"].fillna("").map(
                    lambda text: text if len(text) <= 80 else text[:77] + "..."
                )

                product_event = st.dataframe(
                    products_df[[
                        "software_vendor", "software_name", "version_count",
                        "versions", "device_count", "eos_installs",
                        "nvd_cves", "nvd_critical"
                    ]].rename(columns={
                        "software_vendor": "Éditeur",
                        "software_name": "Produit",
                        "version_count": "Versions",
                        "versions": "Versions installées",
                        "device_count": "Machines",
                        "eos_installs": "Machines avec version en fin de support",
                        "nvd_cves": "CVE (NVD)",
                        "nvd_critical": "dont critiques"
                    }),
                    use_container_width=True,
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    key=f"inventory_products_table_{inventory_tab_search}"
                )

                selection = product_event.selection.rows if product_event else []

                if selection:
                    st.divider()
                    render_product_details(products[selection[0]])


# =========================================================
# CVE INVESTIGATION TAB
# =========================================================

with tab_investigation:

    st.subheader(
        "Investigation CVE"
    )

    exposed = df_cisa[
        df_cisa["affected_devices"] > 0
    ].copy()

    if exposed.empty:

        st.info(
            "No CISA KEV is currently "
            "present in the environment."
        )

    else:

        selected_cve = st.selectbox(
            "Sélectionner une CVE",
            exposed["cve_id"].tolist()
        )

        selected = exposed[
            exposed["cve_id"]
            == selected_cve
        ].iloc[0]


        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Priorité CISA",
            badge_priority(selected["priority"])
        )

        c2.metric(
            "CVSS 3.1",
            str(
                selected["cvss_v3_score"]
            )
            if pd.notna(
                selected["cvss_v3_score"]
            )
            else "N/A"
        )

        c3.metric(
            "Équipements affectés",
            int(
                selected["affected_devices"]
            )
        )

        c4.metric(
            "Produits affectés",
            int(
                selected["affected_products"]
            )
        )

        st.divider()

        left, right = st.columns(2)

        with left:

            st.markdown(
                "### Classification"
            )

            st.write(
                f"**CISA Priority:** "
                f"{badge_priority(selected['priority'])}"
            )

            nvd_severity_display = (
                selected["cvss_v3_severity"]
                if pd.notna(selected["cvss_v3_severity"])
                else "N/A"
            )

            st.write(
                f"**NVD Severity:** {nvd_severity_display}"
            )

            st.write(
                f"**Defender Severity:** "
                f"{selected['defender_severity']}"
            )

            st.write(
                f"**CWE:** "
                f"{selected['cwe']}"
            )

            st.write(
                f"**Ransomware:** "
                f"{selected['known_ransomware']}"
            )


        with right:

            st.markdown(
                "### Defender"
            )

            st.write(
                f"**Exploitability:** "
                f"{selected['exploitability_level']}"
            )

            update = (
                "YES"
                if selected[
                    "security_update_available"
                ] == 1
                else "NO"
            )

            st.write(
                f"**Security Update:** {update}"
            )

            st.write(
                f"**Recommended Update:** "
                f"{selected['recommended_security_updates']}"
            )

            st.write(
                f"**CISA Due Date:** "
                f"{selected['due_date']}"
            )


        st.divider()

        st.markdown(
            "### Affected Devices"
        )

        devices = get_server_cve_devices(
            selected_cve
        )

        if not devices.empty:

            devices = devices.rename(
                columns={
                    "device_id": "ID équipement",
                    "device_name": "Équipement",
                    "os_platform": "OS",
                    "os_version": "Version OS",
                    "software_vendor": "Éditeur",
                    "software_name": "Logiciel",
                    "software_version": "Version",
                    "defender_severity": "Sévérité Defender",
                    "exploitability_level": "Exploitabilité",
                    "security_update_available": "Mise à jour",
                    "recommended_security_update": "Mise à jour recommandée",
                    "recommended_security_update_id": "ID mise à jour",
                    "first_seen_timestamp": "Première détection",
                    "last_seen_timestamp": "Dernière détection"
                }
            )

            st.write(
                f"{len(devices):,} device/software records"
            )

            st.dataframe(
                devices,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "Aucun détail d’équipement disponible."
            )


        st.divider()

        st.markdown(
            "### Analyse IA locale"
        )

        ai_status = selected.get("ai_status")

        if ai_status == "OK" and pd.notna(selected.get("ai_summary")):

            st.write(
                f"**Résumé :** {selected['ai_summary']}"
            )

            st.write(
                f"**Impact estimé (contexte interne) :** "
                f"{selected['ai_impact']}"
            )

            st.write(
                f"**Recommandation :** "
                f"{selected['ai_recommendation']}"
            )

            st.caption(
                f"Confiance : {selected['ai_confidence']} · "
                f"Modèle : {selected['ai_model']} · "
                f"Généré le {selected['ai_generated_at']}"
            )

        else:

            st.info(
                "Aucune analyse IA disponible pour cette CVE."
            )

        if st.button(
            "Générer l'analyse IA pour cette CVE",
            key="ai_single_cve",
            disabled=not IS_ADMIN
        ):

            from services.ai_engine import (
                generate_ai_enrichment,
                is_ollama_available
            )

            from database import (
                get_exposure_context,
                update_ai_enrichment,
                update_ai_status
            )

            if not is_ollama_available():

                st.error(
                    "Ollama n'est pas joignable en local "
                    "(http://localhost:11434). "
                    "Démarrez-le avec `ollama serve`."
                )

            else:

                with st.spinner(
                    "Analyse en cours (LLM local)..."
                ):

                    try:

                        conn = get_connection()

                        vuln_row = conn.execute(
                            "SELECT * FROM vulnerabilities "
                            "WHERE cve_id = ?",
                            (selected_cve,)
                        ).fetchone()

                        conn.close()

                        exposure = get_exposure_context(
                            selected_cve
                        )

                        enrichment = generate_ai_enrichment(
                            dict(vuln_row),
                            exposure
                        )

                        update_ai_enrichment(
                            selected_cve,
                            enrichment
                        )

                        update_ai_status(
                            selected_cve,
                            "OK"
                        )

                        st.success(
                            "Analyse IA générée."
                        )

                        st.cache_data.clear()

                        st.rerun()

                    except Exception as error:

                        update_ai_status(
                            selected_cve,
                            "ERROR",
                            error=str(error)
                        )

                        st.error(
                            f"Échec de l'analyse IA : {error}"
                        )


# =========================================================
# NOTIFICATIONS TAB
# =========================================================

with tab_notifications:

    st.subheader("Notifications e-mail aux propriétaires de serveur")

    st.caption(
        "Un propriétaire dont la case \"Notification\" est activée "
        "(onglet Serveurs, champ \"Propriétaire\" = adresse e-mail) "
        "reçoit UN SEUL e-mail par serveur, généré par l'IA locale, "
        "regroupant toutes les CVE CISA KEV actuellement présentes sur "
        "ce serveur. L'envoi initial ne part que si au moins une de ces "
        "CVE atteint le seuil de criticité configuré ci-dessous — les "
        "CVE moins critiques ne déclenchent jamais un envoi à elles "
        "seules mais sont regroupées dans le même e-mail dès qu'une CVE "
        "plus grave le déclenche. Si des CVE du groupe sont toujours "
        "présentes après le délai configuré (selon leur criticité), une "
        "relance groupée est envoyée automatiquement ; le serveur est "
        "marqué résolu quand il n'en reste plus aucune."
    )

    notify_state = get_sync_state("email_notify")

    if notify_state:

        notify_icon = (
            "🟢"
            if notify_state.get("status") == "OK"
            else "🟠"
            if notify_state.get("status") == "WARNING"
            else "🔴"
        )

        st.caption(
            f"{notify_icon} Dernière vérification : "
            f"{format_sync_timestamp(notify_state.get('last_run_at'))} "
            f"(auto. toutes les {AUTO_NOTIFY_INTERVAL_MINUTES} min) "
            f"— {notify_state.get('detail') or ''}"
        )

    else:

        st.caption(
            "⚪ Aucune vérification effectuée pour le moment "
            f"(auto. toutes les {AUTO_NOTIFY_INTERVAL_MINUTES} min)"
        )

    st.divider()

    # -----------------------------------------------------
    # Configuration SMTP
    # -----------------------------------------------------

    st.markdown("#### Configuration SMTP")

    current_smtp = get_smtp_config()

    with st.form("smtp_config_form"):

        smtp_col1, smtp_col2 = st.columns(2)

        with smtp_col1:

            smtp_host = st.text_input(
                "Serveur SMTP",
                value=current_smtp["host"]
            )

            smtp_username = st.text_input(
                "Utilisateur SMTP",
                value=current_smtp["username"]
            )

            smtp_from = st.text_input(
                "Adresse d'expédition",
                value=current_smtp["from_addr"]
            )

        with smtp_col2:

            smtp_port = st.number_input(
                "Port",
                min_value=1,
                max_value=65535,
                value=current_smtp["port"]
            )

            smtp_password = st.text_input(
                "Mot de passe SMTP",
                type="password",
                value="",
                key="smtp_password_field",
                help=(
                    "Laisser vide pour conserver le mot de passe déjà "
                    "enregistré. Le champ se vide automatiquement "
                    "après enregistrement."
                )
            )

            smtp_use_tls = st.checkbox(
                "Utiliser STARTTLS",
                value=current_smtp["use_tls"]
            )

        smtp_submitted = st.form_submit_button(
            "Enregistrer la configuration SMTP",
            disabled=not IS_ADMIN
        )

        if smtp_submitted:

            set_smtp_config(
                host=smtp_host.strip(),
                port=smtp_port,
                username=smtp_username.strip(),
                password=smtp_password,
                from_addr=smtp_from.strip(),
                use_tls=smtp_use_tls
            )

            st.session_state.pop("smtp_password_field", None)

            st.success("Configuration SMTP enregistrée.")

            st.rerun()

    test_col1, test_col2 = st.columns([3, 1])

    with test_col1:

        test_email_addr = st.text_input(
            "Adresse pour l'e-mail de test",
            key="smtp_test_addr"
        )

    with test_col2:

        st.write("")
        st.write("")

        if st.button("Envoyer un test", use_container_width=True, disabled=not IS_ADMIN):

            if not test_email_addr.strip():

                st.warning("Renseignez une adresse e-mail.")

            else:

                try:

                    send_test_email(test_email_addr.strip())

                    st.success(f"E-mail de test envoyé à {test_email_addr}.")

                except SmtpNotConfigured:

                    st.error("Configurez d'abord le SMTP ci-dessus.")

                except Exception as error:

                    st.error(f"Échec de l'envoi : {error}")

    st.divider()

    # -----------------------------------------------------
    # Seuil de criticité déclenchant l'envoi
    # -----------------------------------------------------

    st.markdown("#### Seuil de déclenchement")

    st.caption(
        "Le premier e-mail pour un serveur ne part que si au moins une "
        "de ses CVE atteint ce niveau de criticité ou plus (les autres "
        "CVE, moins critiques, sont regroupées dans le même e-mail sans "
        "jamais déclencher un envoi à elles seules)."
    )

    priority_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    current_min_priority = get_notification_min_priority()

    selected_min_priority = st.selectbox(
        "Criticité minimale pour déclencher un envoi",
        priority_options,
        index=priority_options.index(current_min_priority)
        if current_min_priority in priority_options
        else 1
    )

    if st.button("Enregistrer le seuil de déclenchement", disabled=not IS_ADMIN):

        set_notification_min_priority(selected_min_priority)

        st.success("Seuil de déclenchement mis à jour.")

        st.rerun()

    st.divider()

    # -----------------------------------------------------
    # Délais de relance par criticité
    # -----------------------------------------------------

    st.markdown("#### Délai avant relance (par criticité)")

    st.caption(
        "Si la CVE est toujours présente sur le serveur après ce délai, "
        "un e-mail de relance est envoyé automatiquement, et le compteur "
        "redémarre pour la relance suivante."
    )

    current_delays = get_notification_delays()

    delay_cols = st.columns(4)

    delay_labels = {
        "CRITICAL": "CRITICAL (heures)",
        "HIGH": "HIGH (heures)",
        "MEDIUM": "MEDIUM (heures)",
        "LOW": "LOW (heures)"
    }

    new_delays = {}

    for col, priority in zip(delay_cols, delay_labels):

        with col:

            new_delays[priority] = col.number_input(
                delay_labels[priority],
                min_value=1.0,
                value=float(current_delays[priority]),
                step=1.0,
                key=f"delay_{priority}"
            )

    if st.button("Enregistrer les délais", disabled=not IS_ADMIN):

        for priority, hours in new_delays.items():
            set_notification_delay(priority, hours)

        st.success("Délais de relance mis à jour.")

        st.rerun()

    st.divider()

    # -----------------------------------------------------
    # Déclenchement manuel
    # -----------------------------------------------------

    if st.button(
        "Vérifier et envoyer les notifications maintenant",
        use_container_width=True,
        disabled=(is_job_running("notify")) or not IS_ADMIN
    ):

        if not is_smtp_configured():

            st.error(
                "Configurez d'abord le SMTP ci-dessus avant d'envoyer "
                "des notifications."
            )

        else:

            launch_job("notify.py")

    render_job("notify")


    st.divider()

    # -----------------------------------------------------
    # Historique
    # -----------------------------------------------------

    st.markdown("#### Historique des notifications")

    st.caption(
        "Une ligne par serveur. \"CVE\" liste toutes les CVE regroupées "
        "dans l'e-mail ; \"CVE en attente\" indique combien d'entre elles "
        "sont encore présentes (les autres ont été résolues et retirées "
        "du groupe au fil des relances)."
    )

    history = get_notification_history()

    if not history:

        st.info("Aucune notification envoyée pour le moment.")

    else:

        history_df = pd.DataFrame(history)

        status_labels = {
            "SENT": "🟦 Envoyée",
            "REMINDER_SENT": "🟠 Relancée",
            "RESOLVED": "🟢 Résolue",
            "ERROR": "🔴 Erreur"
        }

        history_df["status"] = history_df["status"].map(
            lambda value: status_labels.get(value, value)
        )

        history_df = history_df.rename(
            columns={
                "device_name": "Serveur",
                "owner_email": "Propriétaire",
                "cve_ids": "CVE",
                "cve_count": "Nb. CVE",
                "cve_open_count": "CVE en attente",
                "status": "Statut",
                "sent_at": "Envoyée le",
                "reminder_count": "Relances",
                "last_reminder_at": "Dernière relance",
                "next_check_at": "Prochaine vérification",
                "resolved_at": "Résolue le",
                "last_error": "Dernière erreur"
            }
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# ATTACK SURFACE TAB (Hexiosec ASM)
# =========================================================

with tab_attack_surface:

    st.subheader("Attack Surface Management (Hexiosec ASM)")

    st.caption(
        "Importe les risques détectés par Hexiosec ASM (découverte "
        "d'actifs exposés sur Internet — domaines, IP, certificats, "
        "services). Table séparée de CISA KEV : un risque ASM n'a pas "
        "toujours de CVE associée."
    )

    hexiosec_state = get_sync_state("hexiosec")

    if hexiosec_state:

        hexiosec_icon = (
            "🟢"
            if hexiosec_state.get("status") == "OK"
            else "🔴"
        )

        st.caption(
            f"{hexiosec_icon} Dernière synchro : "
            f"{format_sync_timestamp(hexiosec_state.get('last_run_at'))} "
            f"— {hexiosec_state.get('detail') or ''}"
        )

    else:

        st.caption("⚪ Aucune synchronisation Hexiosec effectuée pour le moment.")

    st.divider()

    # -----------------------------------------------------
    # Configuration de la connexion API
    # -----------------------------------------------------

    st.markdown("#### Configuration de la connexion")

    st.caption(
        "L'API publique Hexiosec ASM n'est pas disponible sur tous les "
        "paliers et son chemin exact dépend de votre organisation/scan "
        "(visible dans l'app Hexiosec sous \"Using the Public API\" / "
        "Swagger UI, en haut à droite de l'écran). Utilisez "
        "\"Tester la connexion\" ci-dessous pour valider/ajuster ces "
        "paramètres."
    )

    current_hexiosec = get_hexiosec_config()

    with st.form("hexiosec_config_form"):

        hx_col1, hx_col2 = st.columns(2)

        with hx_col1:

            hx_base_url = st.text_input(
                "URL de base de l'API",
                value=current_hexiosec["base_url"]
            )

            hx_endpoint_path = st.text_input(
                "Chemin de l'endpoint \"risques\"",
                value=current_hexiosec["endpoint_path"],
                help=(
                    "Endpoint officiel : /v1/scan_data/{scan_id}/risks "
                    "(d'après la spec OpenAPI Hexiosec). Le "
                    "\"{scan_id}\" est automatiquement remplacé par "
                    "l'ID de scan renseigné ci-dessous."
                )
            )

            hx_scan_id = st.text_input(
                "ID du scan (\"SCC France\")",
                value=current_hexiosec["scan_id"],
                help=(
                    "Visible dans l'URL de la page du scan dans l'app "
                    "Hexiosec ASM, ou récupérable via "
                    "GET /v1/scans/by-org."
                )
            )

            hx_label = st.text_input(
                "Nom du scope (affichage uniquement)",
                value=current_hexiosec["label"]
            )

        with hx_col2:

            hx_auth_header = st.text_input(
                "Nom du header d'authentification",
                value=current_hexiosec["auth_header"],
                help="Header officiel Hexiosec : X-Hexiosec-API-Key"
            )

            hx_auth_prefix = st.text_input(
                "Préfixe du header (laisser vide pour Hexiosec)",
                value=current_hexiosec["auth_prefix"]
            )

            hx_api_key = st.text_input(
                "Clé API",
                type="password",
                value="",
                key="hexiosec_api_key_field",
                help=(
                    "Laisser vide pour conserver la clé déjà "
                    "enregistrée. Le champ se vide automatiquement "
                    "après enregistrement, la clé n'est jamais "
                    "réaffichée."
                )
            )

        hx_submitted = st.form_submit_button(
            "Enregistrer la configuration",
            disabled=not IS_ADMIN
        )

        if hx_submitted:

            set_hexiosec_config(
                base_url=hx_base_url.strip(),
                api_key=hx_api_key,
                auth_header=hx_auth_header.strip(),
                auth_prefix=hx_auth_prefix,
                endpoint_path=hx_endpoint_path.strip(),
                scan_id=hx_scan_id.strip(),
                label=hx_label.strip()
            )

            # Vide explicitement le champ (masqué par type="password",
            # mais Streamlit garde sinon la saisie affichée en points
            # entre deux exécutions du script) : après enregistrement,
            # la clé n'est plus jamais présente à l'écran, même masquée.
            st.session_state.pop("hexiosec_api_key_field", None)

            st.success("Configuration Hexiosec enregistrée.")

            st.rerun()

    if st.button("Tester la connexion", disabled=not IS_ADMIN):

        if not is_hexiosec_configured():

            st.warning(
                "Renseignez au moins l'URL de base, l'endpoint et la "
                "clé API avant de tester."
            )

        else:

            ok, status_code, payload = hexiosec_test_connection(
                get_hexiosec_config()
            )

            if ok:

                st.success(f"Connexion réussie (HTTP {status_code}).")

            else:

                st.error(
                    f"Échec de connexion "
                    f"(HTTP {status_code if status_code else 'N/A'})."
                )

            st.caption(
                "Réponse brute (utile pour ajuster l'endpoint / le "
                "mapping des champs) :"
            )

            st.json(payload) if isinstance(payload, (dict, list)) else st.code(str(payload))

    st.divider()

    # -----------------------------------------------------
    # Déclenchement manuel
    # -----------------------------------------------------

    if st.button(
        "Synchroniser les risques Hexiosec",
        use_container_width=True,
        disabled=(is_job_running("sync_hexiosec")) or not IS_ADMIN
    ):

        if not is_hexiosec_configured():

            st.error(
                "Configurez d'abord la connexion Hexiosec ci-dessus."
            )

        else:

            launch_job("sync_hexiosec.py")

    render_job("sync_hexiosec")


    st.divider()

    # -----------------------------------------------------
    # Risques importés
    # -----------------------------------------------------

    st.markdown(
        f"#### Risques — {current_hexiosec['label'] or 'Attack Surface'}"
    )

    hexiosec_counts = get_hexiosec_severity_counts()

    if hexiosec_counts:

        hx_c1, hx_c2, hx_c3, hx_c4, hx_c5 = st.columns(5)

        hx_c1.metric("CRITICAL", hexiosec_counts.get("CRITICAL", 0))
        hx_c2.metric("HIGH", hexiosec_counts.get("HIGH", 0))
        hx_c3.metric("MEDIUM", hexiosec_counts.get("MEDIUM", 0))
        hx_c4.metric("LOW", hexiosec_counts.get("LOW", 0))
        hx_c5.metric("INFO", hexiosec_counts.get("INFO", 0))

        hx_counts_series = pd.Series(hexiosec_counts).reindex(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        ).fillna(0).astype(int)

        st.plotly_chart(
            plot_severity_bar(
                hx_counts_series,
                "Sévérité",
                "Nombre de risques"
            ),
            use_container_width=True
        )

    hexiosec_findings = get_hexiosec_findings()

    if not hexiosec_findings:

        st.info(
            "Aucun risque importé pour le moment. Configurez la "
            "connexion ci-dessus puis cliquez sur \"Synchroniser\"."
        )

    else:

        findings_df = pd.DataFrame(hexiosec_findings)

        hx_risk_filter_col1, hx_risk_filter_col2 = st.columns([2, 3])

        with hx_risk_filter_col1:

            hx_severity_filter = st.multiselect(
                "Filtrer par sévérité",
                options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                default=[],
                key="hx_risk_severity_filter"
            )

        with hx_risk_filter_col2:

            hx_risk_search = st.text_input(
                "Rechercher (actif, titre, CVE)",
                key="hx_risk_search"
            )

        filtered_findings_df = findings_df.copy()

        if hx_severity_filter:

            filtered_findings_df = filtered_findings_df[
                filtered_findings_df["severity"]
                .fillna("")
                .str.upper()
                .isin(hx_severity_filter)
            ]

        if hx_risk_search.strip():

            needle = hx_risk_search.strip().lower()

            haystack = (
                filtered_findings_df["asset"].fillna("")
                + " "
                + filtered_findings_df["title"].fillna("")
                + " "
                + filtered_findings_df["cve_id"].fillna("")
            ).str.lower()

            filtered_findings_df = filtered_findings_df[
                haystack.str.contains(needle, regex=False)
            ]

        st.caption(
            f"{len(filtered_findings_df)} / {len(findings_df)} risque(s) affiché(s)"
        )

        filtered_findings_df = fill_priority_badges(
            filtered_findings_df, column="severity"
        )

        filtered_findings_df = filtered_findings_df.rename(
            columns={
                "asset": "Actif",
                "category": "Catégorie",
                "title": "Titre",
                "severity": "Sévérité",
                "cve_id": "CVE",
                "status": "Statut",
                "first_seen": "Détecté le",
                "last_seen": "Vu le",
                "imported_at": "Importé le"
            }
        )

        st.dataframe(
            filtered_findings_df[
                [
                    "Actif", "Catégorie", "Titre", "Sévérité", "CVE",
                    "Statut", "Détecté le", "Vu le", "Importé le"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    # -----------------------------------------------------
    # Inventaire des actifs (domaines, IP, services, composants)
    # -----------------------------------------------------

    st.markdown("#### Actifs découverts")

    st.caption(
        "Inventaire complet remonté par Hexiosec ASM (les tuiles "
        "\"Discovery\" de l'app : domaines, IP, services, composants), "
        "avec le nombre de risques par sévérité associés à chaque "
        "actif."
    )

    hx_asset_counts = get_hexiosec_asset_type_counts()

    if hx_asset_counts:

        hx_ac1, hx_ac2, hx_ac3, hx_ac4 = st.columns(4)

        hx_ac1.metric("Domaines", hx_asset_counts.get("DOMAIN", 0))
        hx_ac2.metric("IP", hx_asset_counts.get("IP", 0))
        hx_ac3.metric("Services", hx_asset_counts.get("SERVICE", 0))
        hx_ac4.metric("Composants", hx_asset_counts.get("COMPONENT", 0))

    hx_asset_filter_col1, hx_asset_filter_col2, hx_asset_filter_col3 = st.columns(
        [2, 2, 3]
    )

    with hx_asset_filter_col1:

        hx_asset_type_filter = st.multiselect(
            "Type d'actif",
            options=["DOMAIN", "IP", "SERVICE", "COMPONENT"],
            default=[],
            format_func=lambda value: {
                "DOMAIN": "Domaine",
                "IP": "IP",
                "SERVICE": "Service",
                "COMPONENT": "Composant"
            }.get(value, value),
            key="hx_asset_type_filter"
        )

    with hx_asset_filter_col2:

        hx_asset_min_severity = st.selectbox(
            "Risque minimum associé",
            options=["Tous", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            key="hx_asset_min_severity"
        )

    with hx_asset_filter_col3:

        hx_asset_search = st.text_input(
            "Rechercher (nom, détail)",
            key="hx_asset_search"
        )

    hexiosec_assets_rows = get_hexiosec_assets(
        asset_types=hx_asset_type_filter or None,
        search=hx_asset_search.strip() or None,
        min_severity=(
            hx_asset_min_severity if hx_asset_min_severity != "Tous" else None
        )
    )

    if not hexiosec_assets_rows:

        st.info(
            "Aucun actif importé pour le moment (ou aucun ne "
            "correspond aux filtres). Cliquez sur \"Synchroniser\" "
            "ci-dessus pour importer l'inventaire complet."
        )

    else:

        assets_df = pd.DataFrame(hexiosec_assets_rows)

        assets_df["asset_type"] = assets_df["asset_type"].map(
            {
                "DOMAIN": "Domaine",
                "IP": "IP",
                "SERVICE": "Service",
                "COMPONENT": "Composant"
            }
        ).fillna(assets_df["asset_type"])

        assets_df = assets_df.rename(
            columns={
                "asset_type": "Type",
                "name": "Nom",
                "detail": "Détail",
                "risk_critical": "Critiques",
                "risk_high": "Hautes",
                "risk_medium": "Moyennes",
                "risk_low": "Basses",
                "risk_info": "Info",
                "created": "Découvert le",
                "last_seen": "Vu le",
                "imported_at": "Importé le"
            }
        )

        st.dataframe(
            assets_df[
                [
                    "Type", "Nom", "Détail", "Critiques", "Hautes",
                    "Moyennes", "Basses", "Info", "Découvert le",
                    "Vu le", "Importé le"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# VEILLE TAB (détections récentes Defender XDR + liste de diffusion)
# =========================================================
#
# Contrairement aux onglets "CISA KEV" / "Serveurs" / "Investigation
# CVE", ici defender_vulnerabilities N'EST PAS filtrée sur
# v.source = 'CISA KEV' : on voit TOUTE CVE que Defender XDR a
# détectée dans l'environnement, y compris une CVE toute fraîche pas
# encore référencée CISA KEV. L'alerte par e-mail part vers une liste
# de diffusion dédiée (pas les propriétaires de serveur).

with tab_watch:

    st.subheader("Veille — détections récentes (Microsoft Defender XDR)")

    st.caption(
        "Contrairement aux autres onglets, cette vue n'est PAS limitée "
        "aux CVE du catalogue CISA KEV : elle exploite directement "
        "toutes les détections déjà remontées par Microsoft Defender "
        "XDR (synchro existante), ce qui permet de réagir à une "
        "vulnérabilité fraîchement annoncée (ex: un 0-day fournisseur) "
        "avant même qu'elle soit éventuellement ajoutée au catalogue "
        "CISA KEV."
    )

    # -----------------------------------------------------
    # Synchro NVD quotidienne (source principale)
    # -----------------------------------------------------
    #
    # NVD est la source d'ENTRÉE : chaque jour, les nouvelles CVE
    # publiées par NVD sont récupérées et croisées avec l'inventaire
    # XDR ci-dessus. CISA KEV reste synchronisée séparément (onglet
    # CISA KEV) et continue à servir d'étiquette "exploitation active
    # connue" sur les CVE communes aux deux sources.

    st.markdown("#### Synchronisation NVD (source principale)")

    st.caption(
        "Chaque jour, VulnWatch récupère les CVE nouvellement publiées "
        "sur nvd.nist.gov et les croise automatiquement avec "
        "l'inventaire XDR : toute correspondance déclenche une alerte "
        "automatique vers la liste de diffusion ci-dessous (sans "
        "attendre un ajout éventuel au catalogue CISA KEV)."
    )

    nvd_feed_state = get_sync_state("nvd_daily_feed")

    if nvd_feed_state:

        nvd_feed_icon = (
            "🟢"
            if nvd_feed_state.get("status") == "OK"
            else "🟠"
            if nvd_feed_state.get("status") == "WARNING"
            else "🔴"
        )

        st.caption(
            f"{nvd_feed_icon} Dernière synchro : "
            f"{format_sync_timestamp(nvd_feed_state.get('last_run_at'))} "
            f"(auto. toutes les {AUTO_NVD_FEED_INTERVAL_MINUTES // 60} h) — "
            f"{nvd_feed_state.get('detail') or ''}"
        )

    else:

        st.caption(
            "⚪ Aucune synchronisation NVD effectuée pour le moment "
            f"(auto. toutes les {AUTO_NVD_FEED_INTERVAL_MINUTES // 60} h)"
        )

    if st.button(
        "Synchroniser NVD maintenant",
        use_container_width=True,
        key="watch_nvd_sync_button",
        disabled=(is_job_running("sync_nvd_feed")) or not IS_ADMIN
    ):

        env = os.environ.copy()

        nvd_key_for_run = get_nvd_api_key()

        if nvd_key_for_run:
            env["VULNWATCH_NVD_API_KEY"] = nvd_key_for_run

        launch_job("sync_nvd_feed.py", env=env)

    render_job("sync_nvd_feed")


    with st.expander("Clé API NVD (optionnel)"):

        st.caption(
            "Sans clé : limite publique de 5 requêtes / 30s (suffisant "
            "pour un volume quotidien normal). Avec une clé gratuite "
            "(nvd.nist.gov/developers/request-an-api-key), la limite "
            "passe à 50 requêtes / 30s — utile si la fenêtre de "
            "synchro contient beaucoup de CVE (ex: après un premier "
            "lancement, ou une longue interruption)."
        )

        current_nvd_key = get_nvd_api_key()

        new_nvd_key = st.text_input(
            "Clé API NVD",
            type="password",
            value="",
            key="nvd_api_key_field",
            help=(
                "Laisser vide pour conserver la clé déjà enregistrée "
                "(ou continuer sans clé). Le champ se vide "
                "automatiquement après enregistrement."
            )
        )

        nvd_key_status = "configurée" if current_nvd_key else "non configurée"

        st.caption(f"Clé actuelle : {nvd_key_status}")

        if st.button("Enregistrer la clé API NVD", disabled=not IS_ADMIN):

            if new_nvd_key:

                set_nvd_api_key(new_nvd_key.strip())

                st.session_state.pop("nvd_api_key_field", None)

                st.success("Clé API NVD enregistrée.")

                st.rerun()

            else:

                st.info("Champ vide : rien n'a été changé.")

    # -----------------------------------------------------
    # État de la base NVD (comparaison jour par jour + rattrapage)
    # -----------------------------------------------------

    st.markdown("#### État de la base NVD")

    st.caption(
        "Compare, jour par jour, le nombre de CVE publiées sur "
        "nvd.nist.gov avec celles présentes dans VulnWatch (une requête "
        "légère par jour, sans télécharger les CVE). « Rattraper » "
        "retélécharge tous les jours de la période : CVE manquantes, et "
        "mise à jour des CVE dont NVD a déclaré ou corrigé les produits "
        "vulnérables après coup. Sans alerte e-mail : les CVE devenues "
        "présentes sur le parc sont listées ci-dessous."
    )

    if get_nvd_api_key():
        st.caption("🔑 Clé API NVD configurée (50 requêtes / 30 s).")
    else:
        st.caption(
            "⚠️ Aucune clé API NVD : la vérification est plus lente "
            "(5 requêtes / 30 s). Renseignez-la dans « Clé API NVD » "
            "ci-dessus."
        )

    audit_days = st.number_input(
        "Période à vérifier (jours)",
        min_value=1,
        max_value=120,
        value=30,
        step=1,
        key="nvd_audit_days"
    )

    audit_running = is_job_running("nvd_audit")

    audit_col_check, audit_col_fix = st.columns(2)

    with audit_col_check:

        audit_check = st.button(
            "Vérifier l'état",
            use_container_width=True,
            disabled=(audit_running) or not IS_ADMIN,
            key="nvd_audit_check_button"
        )

    with audit_col_fix:

        audit_fix = st.button(
            "Rattraper les CVE manquantes",
            use_container_width=True,
            type="primary",
            disabled=(audit_running) or not IS_ADMIN,
            key="nvd_audit_fix_button"
        )

    if audit_check or audit_fix:

        env = os.environ.copy()
        env["VULNWATCH_AUDIT_DAYS"] = str(int(audit_days))

        if audit_fix:
            env["VULNWATCH_AUDIT_FIX"] = "1"

        audit_key = get_nvd_api_key()

        if audit_key:
            env["VULNWATCH_NVD_API_KEY"] = audit_key

        launch_job("nvd_audit.py", env=env)

    render_job("nvd_audit")

    audit_report = get_nvd_audit_report()

    if audit_report and audit_report.get("rows"):

        audit_rows = audit_report["rows"]

        total_nvd = sum(row["nvd"] for row in audit_rows)
        total_local = sum(row["local"] for row in audit_rows)
        total_missing = sum(row["missing"] for row in audit_rows)
        # Rapports antérieurs à l'ajout des colonnes produits : 0.
        total_unchecked = sum(row.get("unchecked", 0) for row in audit_rows)
        total_with_cpe = sum(row.get("with_cpe", 0) for row in audit_rows)
        incomplete_days = sum(
            1 for row in audit_rows
            if row["missing"] or row.get("unchecked", 0)
        )

        st.caption(
            f"Dernière vérification : "
            f"{format_sync_timestamp(audit_report.get('checked_at'))} "
            f"— {audit_report.get('days')} derniers jours"
        )

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("CVE publiées (NVD)", f"{total_nvd:,}")
        m2.metric("CVE dans VulnWatch", f"{total_local:,}")
        m3.metric("CVE manquantes", f"{total_missing:,}")
        m4.metric(
            "Produits NVD à compléter",
            f"{total_unchecked:,}",
            help="CVE présentes mais dont les produits vulnérables NVD "
                 "n'ont jamais été récupérés (importées avant cette "
                 "fonctionnalité). « Rattraper » les complète. "
                 f"{total_with_cpe:,} CVE de la période ont leurs produits ; "
                 "les autres ne sont pas encore analysées par NVD."
        )
        m5.metric("Jours incomplets", incomplete_days)

        if audit_report.get("fixed"):

            on_parc = audit_report.get("recovered_on_parc") or []

            st.info(
                f"Rattrapage : {audit_report.get('recovered', 0)} CVE "
                f"ajoutée(s), {audit_report.get('updated', 0)} mise(s) à jour "
                f"(produits et scores NVD), {audit_report.get('skipped', 0)} "
                f"jour(s) inchangé(s) sautés, dont {len(on_parc)} nouvelle(s) "
                f"présente(s) sur le parc"
                + (f" : {', '.join(on_parc[:20])}" if on_parc else "")
                + (" ..." if len(on_parc) > 20 else "")
            )

        if total_missing == 0 and total_unchecked == 0:
            st.success("✅ La base est à jour avec NVD sur cette période.")

        audit_df = pd.DataFrame(list(reversed(audit_rows)))

        for column in ("with_cpe", "unchecked"):
            if column not in audit_df:
                audit_df[column] = 0

        def audit_state(row):

            problems = []

            if row["missing"]:
                problems.append(f"⚠️ {row['missing']} manquante(s)")

            if row["unchecked"]:
                problems.append(f"🧩 {row['unchecked']} à compléter")

            return " · ".join(problems) or "✅ Complet"

        audit_df["state"] = audit_df.apply(audit_state, axis=1)

        st.dataframe(
            audit_df[[
                "day", "nvd", "local", "missing", "with_cpe", "unchecked",
                "state"
            ]].rename(
                columns={
                    "day": "Date de publication (UTC)",
                    "nvd": "NVD",
                    "local": "VulnWatch",
                    "missing": "Manquantes",
                    "with_cpe": "Avec produits NVD",
                    "unchecked": "Produits à compléter",
                    "state": "État"
                }
            ),
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    # -----------------------------------------------------
    # Équipements touchés selon NVD (inventaire logiciel x CPE NVD)
    # -----------------------------------------------------

    st.markdown("#### Équipements touchés selon NVD (inventaire logiciel)")

    st.caption(
        "VulnWatch compare lui-même les logiciels installés sur chaque "
        "machine aux produits et versions déclarés vulnérables par NVD "
        "(référence : la base NVD), sans attendre que Defender ait intégré "
        "la CVE. Calcul refait après chaque import d'inventaire, et pour "
        "chaque nouvelle CVE à la synchro NVD (alerte de veille incluse)."
    )

    inventory_status = load_inventory_status()

    i1, i2, i3, i4 = st.columns(4)
    i1.metric("Machines inventoriées", f"{inventory_status['inventory_devices']:,}".replace(",", " "))
    i2.metric("Logiciels installés", f"{inventory_status['inventory_rows']:,}".replace(",", " "))
    i3.metric(
        "CVE avec produits NVD",
        f"{inventory_status['cves_with_cpe']:,}".replace(",", " "),
        help="CVE pour lesquelles VulnWatch connaît les produits vulnérables "
             "(configurations CPE NVD). Les autres ne peuvent pas être "
             "reliées à l'inventaire."
    )
    i4.metric(
        "CVE touchant le parc",
        f"{inventory_status['matched_cves']:,}".replace(",", " "),
        help=f"{inventory_status['affected_devices']} machine(s) concernée(s)."
    )

    st.caption(
        f"Inventaire importé le "
        f"{format_sync_timestamp(inventory_status['inventory_imported_at'])} "
        f"· calcul du {format_sync_timestamp(get_inventory_matched_at())}"
    )

    cpe_unchecked, cpe_oldest = load_cpe_unchecked()

    inv_col1, inv_col2 = st.columns(2)

    with inv_col1:

        if st.button(
            "Importer l'inventaire depuis Defender",
            use_container_width=True,
            type="primary",
            disabled=(is_job_running("sync_software_inventory")) or not IS_ADMIN,
            key="inventory_defender_button",
            help="Inventaire complet par l'API Advanced Hunting de Defender "
                 "(par lots de machines, sans la limite de 100 000 lignes ; "
                 "permission AdvancedQuery.Read.All), à défaut export "
                 "SoftwareInventoryExport (Software.Read.All). Application "
                 "Azure (barre latérale) ou Azure CLI. Réimporté ensuite "
                 "automatiquement chaque jour."
        ):
            launch_job("sync_software_inventory.py")

    with inv_col2:

        if st.button(
            "Recalculer les équipements touchés",
            use_container_width=True,
            disabled=(is_job_running("nvd_match")) or not IS_ADMIN,
            key="inventory_match_button"
        ):
            launch_job("nvd_match.py")

    # Complément ponctuel de l'historique : les CVE importées avant
    # l'enregistrement des produits NVD n'en ont pas. « Rattraper » (état
    # de la base NVD) ne couvre que 120 jours ; au-delà, ce bouton (ou un
    # réimport des fichiers NVD). Masqué une fois l'historique complété :
    # la synchro quotidienne enregistre ensuite les produits elle-même.
    if cpe_unchecked or is_job_running("nvd_cpe_sync"):

        st.warning(
            f"{cpe_unchecked:,} CVE".replace(",", " ")
            + (f" (publiées depuis le {str(cpe_oldest)[:10]})" if cpe_oldest else "")
            + " n'ont pas encore leurs produits vulnérables NVD : elles ne "
            "peuvent pas être reliées à l'inventaire. Le plus rapide : "
            "réimporter vos fichiers NVD (« Import manuel d'un fichier NVD » "
            "ci-dessus). Sinon, téléchargement depuis l'API NVD ci-dessous "
            "(une seule fois, reprend là où il s'est arrêté)."
        )

        cpe_col1, cpe_col2 = st.columns([1, 2])

        with cpe_col1:

            default_since = date(2018, 1, 1)

            try:
                default_since = max(
                    date.fromisoformat(str(cpe_oldest)[:10]), default_since
                ) if cpe_oldest else default_since
            except ValueError:
                pass

            cpe_since = st.date_input(
                "CVE publiées depuis",
                value=default_since,
                format="DD/MM/YYYY",
                key="inventory_cpe_since"
            )

        with cpe_col2:

            st.write("")

            if st.button(
                "Télécharger les produits NVD",
                use_container_width=True,
                disabled=(is_job_running("nvd_cpe_sync")) or not IS_ADMIN,
                key="inventory_cpe_button"
            ):
                env = os.environ.copy()
                env["VULNWATCH_CPE_SINCE"] = cpe_since.isoformat()

                cpe_key = get_nvd_api_key()

                if cpe_key:
                    env["VULNWATCH_NVD_API_KEY"] = cpe_key

                launch_job("nvd_cpe_sync.py", env=env)

    else:

        st.caption(
            "✅ Produits vulnérables NVD récupérés pour toutes les CVE "
            "(la synchro quotidienne les tient à jour)."
        )

    render_job("sync_software_inventory", warning_state_key="software_inventory")

    inventory_state = get_sync_state("software_inventory")

    if inventory_state and inventory_state.get("status") == "WARNING":
        st.warning(f"⚠️ Dernier import d'inventaire : {inventory_state.get('detail')}")
    render_job("nvd_match")
    render_job("nvd_cpe_sync")

    with st.expander("Importer un inventaire CSV (export du portail Defender)"):

        st.caption(
            "Portail Microsoft Defender > Gestion des vulnérabilités > "
            "Inventaire logiciel > Exporter (colonnes DeviceId, DeviceName, "
            "OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, "
            "ProductCodeCpe...). Remplace l'inventaire actuel."
        )

        inventory_csv = st.file_uploader(
            "Fichier CSV d'inventaire",
            type=["csv"],
            key="inventory_csv_upload",
            disabled=not IS_ADMIN
        )

        if inventory_csv and st.button(
            "Importer le CSV",
            use_container_width=True,
            disabled=(is_job_running("sync_software_inventory")) or not IS_ADMIN,
            key="inventory_csv_button"
        ):
            upload_dir = Path("data/imports")
            upload_dir.mkdir(parents=True, exist_ok=True)

            csv_target = upload_dir / "software_inventory_upload.csv"
            csv_target.write_bytes(inventory_csv.getvalue())

            env = os.environ.copy()
            env["VULNWATCH_INVENTORY_CSV"] = str(csv_target.resolve())

            launch_job("sync_software_inventory.py", env=env)

    inventory_search = st.text_input(
        "Rechercher dans les CVE touchant le parc (selon NVD)",
        placeholder="CVE, mot-clé, éditeur ou produit (ex. chrome, fortinet)",
        key="inventory_search"
    )

    inventory_cves = load_inventory_matched_cves(inventory_search.strip())

    if not inventory_cves:

        st.info(
            "Aucune CVE ne touche le parc selon NVD pour le moment "
            "(inventaire non importé, produits NVD manquants, ou aucune "
            "correspondance)."
        )

    else:

        inventory_df = pd.DataFrame(inventory_cves)
        inventory_df["severity"] = inventory_df["severity"].map(
            lambda value: NVD_SEVERITY_LABELS.get(
                str(value or "NONE").upper(), value
            )
        )
        inventory_df["nvd_published"] = inventory_df["nvd_published"].map(
            format_nvd_date
        )
        inventory_df["source"] = inventory_df["source"].eq("CISA KEV").map(
            {True: "Oui", False: ""}
        )

        inventory_event = st.dataframe(
            inventory_df[[
                "cve_id", "nvd_published", "severity", "cvss",
                "affected_devices", "defender_devices", "source", "products"
            ]].rename(columns={
                "cve_id": "CVE",
                "nvd_published": "Publiée",
                "severity": "Sévérité",
                "cvss": "CVSS",
                "affected_devices": "Machines (NVD)",
                "defender_devices": "Machines (Defender)",
                "source": "CISA KEV",
                "products": "Produits concernés"
            }),
            column_config={
                "CVSS": st.column_config.NumberColumn(format="%.1f")
            },
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="inventory_cves_table"
        )

        inventory_selected = (
            inventory_event.selection.rows if inventory_event else []
        )

        if inventory_selected:

            selected_inventory_cve = inventory_cves[inventory_selected[0]]["cve_id"]

            st.markdown(
                f"**{selected_inventory_cve}** — machines touchées selon NVD "
                "(détail complet dans l'onglet CVE NVD)"
            )

            st.dataframe(
                pd.DataFrame(
                    load_inventory_devices_for_cve(selected_inventory_cve)
                ).rename(columns=INVENTORY_DEVICE_COLUMNS),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.caption(
                "Sélectionnez une ligne pour voir les machines et les "
                "versions concernées. « Machines (Defender) » à 0 : "
                "Defender n'a pas (encore) relié cette CVE au parc."
            )

    st.divider()

    # -----------------------------------------------------
    # Téléchargement historique NVD (premier lancement)
    # -----------------------------------------------------

    st.markdown("#### Historique NVD (téléchargement initial)")

    st.caption(
        "En plus de la synchro quotidienne ci-dessus (nouvelles "
        "publications), VulnWatch télécharge en arrière-plan tout "
        "l'historique NVD, en partant des CVE les PLUS RÉCENTES et en "
        "remontant progressivement jusqu'à la date de départ choisie "
        "— les vulnérabilités les plus susceptibles de concerner "
        "l'environnement actuel sont donc disponibles dès les "
        "premières minutes, sans attendre la fin du téléchargement. "
        "Le tout sans bloquer l'interface, par petits lots, avec "
        "reprise automatique en cas d'interruption."
    )

    backfill_state = get_sync_state("nvd_historical_backfill")
    backfill_done = is_nvd_backfill_done()

    if backfill_done:

        st.success(
            f"🟢 Historique NVD complet — {get_nvd_total_count()} CVE "
            f"NVD en base."
        )

    elif backfill_state:

        backfill_icon = (
            "🟠" if backfill_state.get("status") == "RUNNING"
            else "🔴" if backfill_state.get("status") == "ERROR"
            else "⚪"
        )

        st.info(
            f"{backfill_icon} Téléchargement en cours (arrière-plan) — "
            f"{format_sync_timestamp(backfill_state.get('last_run_at'))} : "
            f"{backfill_state.get('detail') or ''}"
        )

        st.caption(
            "Cette page peut être fermée et rouverte sans perdre la "
            "progression : la reprise se fait automatiquement depuis "
            "le dernier point atteint."
        )

    else:

        st.caption(
            "⚪ Pas encore démarré — sera lancé automatiquement au "
            "prochain chargement de l'appli."
        )

    with st.expander("Options de l'historique NVD"):

        current_backfill_start = get_nvd_backfill_start()

        st.caption(
            f"Le téléchargement remonte jusqu'au : "
            f"{current_backfill_start[:10]} (le plus ancien)"
        )

        if not backfill_state:

            new_backfill_start = st.date_input(
                "Remonter l'historique jusqu'au",
                value=date(2020, 1, 1),
                key="nvd_backfill_start_field",
                help=(
                    "Modifiable uniquement avant le premier lancement "
                    "du téléchargement."
                )
            )

            if st.button(
                "Enregistrer la date de départ",
                key="nvd_backfill_start_save_button",
                disabled=not IS_ADMIN
            ):

                set_nvd_backfill_start(
                    datetime(
                        new_backfill_start.year,
                        new_backfill_start.month,
                        new_backfill_start.day,
                        tzinfo=timezone.utc
                    ).isoformat()
                )

                st.success("Date de départ enregistrée.")

                st.rerun()

        else:

            st.caption(
                "Le téléchargement a déjà commencé : la date de "
                "départ ne peut plus être changée (utiliser "
                "\"Relancer depuis zéro\" ci-dessous pour en choisir "
                "une nouvelle)."
            )

        if st.button(
            "Relancer le téléchargement maintenant",
            use_container_width=True,
            key="watch_nvd_backfill_relaunch_button",
            help=(
                "Reprend depuis le dernier point atteint. Utile si le "
                "téléchargement semble bloqué sans attendre le délai "
                "de reprise automatique."
            ),
            disabled=not IS_ADMIN
        ):

            env = os.environ.copy()

            backfill_key_for_run = get_nvd_api_key()

            if backfill_key_for_run:
                env["VULNWATCH_NVD_API_KEY"] = backfill_key_for_run

            subprocess.Popen(
                [sys.executable, "sync_nvd_backfill.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env
            )

            st.success(
                "Téléchargement relancé en arrière-plan. Rafraîchir "
                "cette page dans quelques instants pour voir la "
                "progression."
            )

        if backfill_done or backfill_state:

            if st.button(
                "Tout retélécharger depuis zéro",
                key="watch_nvd_backfill_reset_button",
                disabled=not IS_ADMIN
            ):

                reset_nvd_backfill()

                st.success(
                    "Historique réinitialisé — sera retéléchargé "
                    "(aucune CVE déjà en base n'est supprimée)."
                )

                st.rerun()

    # -----------------------------------------------------
    # Import manuel d'un fichier NVD (si pas d'accès sortant depuis
    # le serveur vers services.nvd.nist.gov)
    # -----------------------------------------------------

    with st.expander("Import manuel d'un fichier NVD"):

        st.caption(
            "Si ce serveur n'a pas d'accès sortant vers "
            "services.nvd.nist.gov (proxy, pare-feu...), le "
            "téléchargement automatique ne peut pas fonctionner. "
            "Solution : télécharger le fichier depuis un poste qui a "
            "accès à Internet, puis l'envoyer ici."
        )

        st.markdown(
            "Où trouver le fichier : "
            "[nvd.nist.gov/vuln/data-feeds](https://nvd.nist.gov/vuln/data-feeds) "
            "(un fichier `nvdcve-2.0-AAAA.json.gz` par année, ex. "
            "2020 à aujourd'hui) — ou l'export JSON d'une requête "
            "sur l'API NVD 2.0 (`cves/2.0`). Formats acceptés : "
            "`.json`, `.json.gz`, `.json.zip`."
        )

        uploaded_nvd_files = st.file_uploader(
            "Fichier(s) NVD",
            type=["json", "gz", "zip"],
            accept_multiple_files=True,
            key="nvd_manual_upload_field",
            disabled=not IS_ADMIN
        )

        if uploaded_nvd_files and st.button(
            "Importer",
            use_container_width=True,
            key="nvd_manual_upload_button",
            disabled=(is_job_running("nvd_import_files")) or not IS_ADMIN
        ):

            # Import en arrière-plan (un flux annuel complet prend
            # plusieurs minutes) : les fichiers sont déposés dans
            # data/imports/nvd puis traités par nvd_import_files.py, qui
            # enregistre aussi les produits vulnérables (CPE) et recalcule
            # les équipements touchés selon NVD.
            upload_dir = Path("data/imports/nvd")
            upload_dir.mkdir(parents=True, exist_ok=True)

            saved_paths = []

            for uploaded_file in uploaded_nvd_files:

                target = upload_dir / Path(uploaded_file.name).name
                target.write_bytes(uploaded_file.getvalue())
                saved_paths.append(str(target.resolve()))

            env = os.environ.copy()
            env["VULNWATCH_NVD_FILES"] = os.pathsep.join(saved_paths)

            launch_job("nvd_import_files.py", env=env)

        render_job("nvd_import_files")

    st.divider()

    # -----------------------------------------------------
    # Recherche / détections récentes
    # -----------------------------------------------------

    watch_search = st.text_input(
        "Rechercher une CVE, un éditeur ou un produit",
        key="watch_search",
        placeholder="ex: CVE-2026-109618, Apache, PHP..."
    )

    detections = load_recent_defender_detections(
        limit=200,
        search=watch_search.strip() if watch_search else None
    )

    if not detections:

        st.info(
            "Aucune détection Defender trouvée"
            + (f" pour \"{watch_search}\"." if watch_search else ".")
        )

    else:

        detections_df = pd.DataFrame(detections)

        detections_df["criticité"] = detections_df.apply(
            lambda row: badge_priority(
                row["cisa_priority"] or row["defender_severity"]
            ),
            axis=1
        )

        detections_df["Au catalogue CISA KEV"] = detections_df[
            "cisa_source"
        ].apply(lambda value: "🟢 Oui" if value == "CISA KEV" else "⚪ Non")

        detections_df["nvd_published_display"] = detections_df[
            "nvd_published"
        ].apply(
            lambda value: str(value)[:10] if value else "N/A"
        )

        display_df = detections_df.rename(
            columns={
                "cve_id": "CVE",
                "vulnerability_name": "Nom",
                "software_vendor": "Éditeur",
                "software_name": "Produit",
                "defender_cvss_score": "CVSS (Defender)",
                "nvd_published_display": "Date de publication (NVD)",
                "affected_devices": "Équipements touchés",
                "devices_with_update_available": "Équip. avec MàJ dispo",
                "recommended_security_update": "Mise à jour recommandée",
                "first_seen": "Première détection",
                "last_seen": "Dernière détection"
            }
        )

        st.dataframe(
            display_df[
                [
                    "CVE", "Nom", "Éditeur", "Produit", "criticité",
                    "Au catalogue CISA KEV", "Date de publication (NVD)",
                    "CVSS (Defender)", "Équipements touchés",
                    "Équip. avec MàJ dispo", "Mise à jour recommandée",
                    "Première détection", "Dernière détection"
                ]
            ].rename(columns={"criticité": "Criticité"}),
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        # -------------------------------------------------
        # Détail d'une CVE + actifs touchés + envoi d'alerte
        # -------------------------------------------------

        st.markdown("#### Détail et envoi d'alerte")

        watch_cve_options = detections_df["cve_id"].tolist()

        selected_watch_cve = st.selectbox(
            "Sélectionner une CVE",
            watch_cve_options,
            key="watch_selected_cve"
        )

        selected_detection = detections_df[
            detections_df["cve_id"] == selected_watch_cve
        ].iloc[0].to_dict()

        affected_devices = get_devices_for_cve(selected_watch_cve)

        wc1, wc2, wc3, wc4, wc5 = st.columns(5)

        wc1.metric(
            "Criticité",
            badge_priority(
                selected_detection["cisa_priority"]
                or selected_detection["defender_severity"]
            )
        )

        wc2.metric(
            "CVSS",
            str(
                selected_detection["nvd_cvss_v3_score"]
                or selected_detection["defender_cvss_score"]
                or "N/A"
            )
        )

        wc3.metric(
            "Actifs touchés",
            len(affected_devices)
        )

        wc4.metric(
            "Au catalogue CISA KEV",
            "Oui" if selected_detection["cisa_source"] == "CISA KEV" else "Non"
        )

        wc5.metric(
            "Date de publication (NVD)",
            str(selected_detection.get("nvd_published") or "N/A")[:10]
        )

        if affected_devices:

            devices_df = pd.DataFrame(affected_devices).rename(
                columns={
                    "device_name": "Équipement",
                    "os_platform": "OS",
                    "os_version": "Version OS",
                    "software_vendor": "Éditeur",
                    "software_name": "Logiciel",
                    "software_version": "Version",
                    "defender_severity": "Sévérité Defender",
                    "exploitability_level": "Exploitabilité",
                    "security_update_available": "Mise à jour",
                    "recommended_security_update": "Mise à jour recommandée",
                    "first_seen_timestamp": "Première détection",
                    "last_seen_timestamp": "Dernière détection"
                }
            )

            st.dataframe(
                devices_df[
                    [
                        "Équipement", "OS", "Version OS", "Éditeur",
                        "Logiciel", "Version", "Sévérité Defender",
                        "Exploitabilité", "Mise à jour",
                        "Mise à jour recommandée", "Première détection",
                        "Dernière détection"
                    ]
                ],
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info("Aucun équipement listé pour cette CVE.")

        active_recipients = get_watch_recipients(active_only=True)

        if st.button(
            f"📧 Envoyer une alerte à la liste de diffusion "
            f"({len(active_recipients)} destinataire(s))",
            use_container_width=True,
            disabled=(not active_recipients) or not IS_ADMIN
        ):

            if not is_smtp_configured():

                st.error(
                    "Configurez d'abord le SMTP (onglet Notifications) "
                    "avant d'envoyer une alerte."
                )

            else:

                with st.spinner("Génération et envoi de l'alerte..."):

                    alert_email = generate_watch_alert_email(
                        selected_detection,
                        affected_devices
                    )

                    recipient_emails = [
                        recipient["email"]
                        for recipient in active_recipients
                    ]

                    send_errors = []

                    for recipient_email in recipient_emails:

                        try:

                            send_email(
                                recipient_email,
                                alert_email["sujet"],
                                alert_email["corps"]
                            )

                        except Exception as error:

                            send_errors.append(f"{recipient_email} : {error}")

                    sent_count = len(recipient_emails) - len(send_errors)

                    if sent_count > 0:

                        record_watch_alert(
                            cve_id=selected_watch_cve,
                            recipients=recipient_emails,
                            subject=alert_email["sujet"],
                            body=alert_email["corps"],
                            affected_device_count=len(affected_devices)
                        )

                if sent_count > 0:

                    st.success(
                        f"Alerte envoyée à {sent_count} destinataire(s) "
                        f"pour {selected_watch_cve}."
                    )

                if send_errors:

                    st.error(
                        "Échec pour : " + " ; ".join(send_errors)
                    )

        elif not active_recipients:

            st.caption(
                "Ajoutez au moins un destinataire actif ci-dessous pour "
                "pouvoir envoyer une alerte."
            )

    st.divider()

    # -----------------------------------------------------
    # Liste de diffusion
    # -----------------------------------------------------

    st.markdown("#### Liste de diffusion")

    st.caption(
        "Indépendante des propriétaires de serveur (onglet Serveurs) : "
        "ces destinataires reçoivent les alertes de veille envoyées "
        "manuellement ci-dessus, quel que soit le serveur concerné."
    )

    with st.form("watch_recipient_form", clear_on_submit=True):

        wr_col1, wr_col2, wr_col3 = st.columns([2, 2, 1])

        with wr_col1:
            new_recipient_email = st.text_input("Adresse e-mail")

        with wr_col2:
            new_recipient_label = st.text_input(
                "Nom / équipe (optionnel)"
            )

        with wr_col3:
            st.write("")
            st.write("")
            add_recipient_submitted = st.form_submit_button(
                "Ajouter",
                use_container_width=True,
                disabled=not IS_ADMIN
            )

        if add_recipient_submitted:

            if not new_recipient_email.strip() or "@" not in new_recipient_email:

                st.warning("Adresse e-mail invalide.")

            else:

                add_watch_recipient(
                    new_recipient_email.strip(),
                    new_recipient_label.strip()
                )

                st.success(f"{new_recipient_email} ajouté à la liste.")

                st.rerun()

    all_recipients = get_watch_recipients()

    if not all_recipients:

        st.info("Aucun destinataire dans la liste de diffusion.")

    else:

        for recipient in all_recipients:

            rc1, rc2, rc3, rc4 = st.columns([3, 2, 1, 1])

            rc1.write(recipient["email"])
            rc2.write(recipient["label"] or "—")

            with rc3:

                new_active = st.checkbox(
                    "Actif",
                    value=bool(recipient["active"]),
                    key=f"watch_recipient_active_{recipient['id']}",
                    disabled=not IS_ADMIN
                )

                if new_active != bool(recipient["active"]):

                    set_watch_recipient_active(recipient["id"], new_active)

                    st.rerun()

            with rc4:

                if st.button(
                    "🗑️",
                    key=f"watch_recipient_delete_{recipient['id']}",
                    disabled=not IS_ADMIN
                ):

                    delete_watch_recipient(recipient["id"])

                    st.rerun()

    st.divider()

    # -----------------------------------------------------
    # Historique des alertes envoyées
    # -----------------------------------------------------

    st.markdown("#### Historique des alertes de veille")

    watch_history = get_watch_alert_history()

    if not watch_history:

        st.info("Aucune alerte de veille envoyée pour le moment.")

    else:

        history_df = pd.DataFrame(watch_history).rename(
            columns={
                "cve_id": "CVE",
                "recipients": "Destinataires",
                "subject": "Objet",
                "affected_device_count": "Actifs touchés",
                "sent_at": "Envoyée le"
            }
        )

        st.dataframe(
            history_df[
                [
                    "CVE", "Objet", "Destinataires", "Actifs touchés",
                    "Envoyée le"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "VulnWatch AI | CISA KEV + NVD + Microsoft Defender + IA locale (Ollama)"
)