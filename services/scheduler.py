"""
Synchros automatiques : quelle synchro est due, et lancement en
arrière-plan (services/jobs.py).

Utilisé par l'interface (app.py, à chaque affichage de page) et par
scheduled_sync.py (Planificateur de tâches Windows, toutes les 15 min) :
les synchros tournent ainsi même quand personne n'a ouvert l'application.
Les deux peuvent tourner en même temps sans doublon : une synchro déjà en
cours n'est jamais relancée (is_job_running) et chaque lancement est noté
en base (autosync_launched_at:<script>).
"""

import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from database import (
    get_app_config,
    set_app_config,
    get_sync_state,
    get_pending_nvd_count,
    get_nvd_api_key,
    is_smtp_configured,
    is_nvd_backfill_done,
    get_inventory_schedule,
    INVENTORY_SOURCE_KEY
)
from services.jobs import is_job_running, start_job


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
    "nvd_cpe_sync.py": "Téléchargement des produits vulnérables NVD",
    "sync_nvd_backfill.py": "Téléchargement historique NVD"
}

# CISA KEV : toutes les 12 h.
AUTO_SYNC_INTERVAL_HOURS = 12

# Enrichissement NVD par petits lots (API NVD limitée en débit).
AUTO_NVD_INTERVAL_MINUTES = 30
AUTO_NVD_BATCH_SIZE = 5

# Notifications e-mail (nouvelles CVE + relances).
AUTO_NOTIFY_INTERVAL_MINUTES = 60

# Flux NVD toutes les 2 h : NVD déclare souvent les produits vulnérables
# quelques heures après la publication. Après un échec, nouvel essai au
# bout d'une heure.
AUTO_NVD_FEED_INTERVAL_MINUTES = 2 * 60
AUTO_NVD_FEED_ERROR_RETRY_MINUTES = 60

# Téléchargement historique NVD : relancé s'il ne donne plus signe de vie
# (heartbeat en base) ou après un échec.
NVD_BACKFILL_STALE_MINUTES = 15
NVD_BACKFILL_ERROR_RETRY_MINUTES = 30

INVENTORY_SCRIPT = "sync_software_inventory.py"


def _parse(iso_value):

    try:
        value = datetime.fromisoformat(iso_value)
    except (TypeError, ValueError):
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value


def _age(sync_key):
    """Temps écoulé depuis la dernière exécution, None si jamais lancée."""

    state = get_sync_state(sync_key)
    last_run = _parse((state or {}).get("last_run_at"))

    if last_run is None:
        return None

    return datetime.now(timezone.utc) - last_run


def _nvd_env():

    env = os.environ.copy()
    api_key = get_nvd_api_key()

    if api_key:
        env["VULNWATCH_NVD_API_KEY"] = api_key

    return env


def launch_background_sync(script, min_interval, env=None):
    """
    Lance un script de synchro en arrière-plan, sous la même clé que le
    bouton manuel correspondant : la synchro auto apparaît avec sa barre
    de progression, et un clic pendant qu'elle tourne ne la lance pas une
    seconde fois. L'heure du lancement est notée en base pour ne pas
    relancer le script avant min_interval (s'il a planté).
    Retourne la clé de la tâche lancée, ou None.
    """

    key = f"autosync_launched_at:{script}"
    now = datetime.now(timezone.utc)
    last_launch = _parse(get_app_config(key))

    if last_launch and now - last_launch < min_interval:
        return None

    job_key = Path(script).stem

    if is_job_running(job_key):
        return None

    set_app_config(key, now.isoformat())

    start_job(job_key, script, JOB_LABELS.get(script, script), env=env)

    return job_key


def auto_sync_cisa_if_needed():

    age = _age("cisa_kev")
    interval = timedelta(hours=AUTO_SYNC_INTERVAL_HOURS)

    if age is None or age >= interval:
        return launch_background_sync("sync.py", interval)


def auto_enrich_nvd_if_needed():

    if get_pending_nvd_count() == 0:
        return None

    age = _age("nvd_enrich")
    interval = timedelta(minutes=AUTO_NVD_INTERVAL_MINUTES)

    if age is None or age >= interval:

        env = _nvd_env()
        env["VULNWATCH_MAX_CVES"] = str(AUTO_NVD_BATCH_SIZE)

        return launch_background_sync("enrich.py", interval, env=env)


def auto_notify_if_needed():

    if not is_smtp_configured():
        return None

    age = _age("email_notify")
    interval = timedelta(minutes=AUTO_NOTIFY_INTERVAL_MINUTES)

    if age is None or age >= interval:
        return launch_background_sync("notify.py", interval)


def auto_sync_nvd_feed_if_needed():

    state = get_sync_state("nvd_daily_feed") or {}
    age = _age("nvd_daily_feed")

    interval = (
        AUTO_NVD_FEED_ERROR_RETRY_MINUTES
        if state.get("status") == "ERROR"
        else AUTO_NVD_FEED_INTERVAL_MINUTES
    )

    if age is None or age >= timedelta(minutes=interval):

        # Garde-fou anti-relance d'une heure : sinon il bloquerait la
        # nouvelle tentative prévue une heure après un échec.
        return launch_background_sync(
            "sync_nvd_feed.py",
            timedelta(minutes=AUTO_NVD_FEED_ERROR_RETRY_MINUTES),
            env=_nvd_env()
        )


def inventory_due_mode():
    """
    "full", "delta" ou None : synchro d'inventaire due selon la fréquence
    réglée dans l'onglet Veille. Uniquement si le dernier import venait
    de l'API Defender (un inventaire chargé par CSV n'est pas remplacé).
    """

    # Source du dernier import réussi (notée par sync_software_inventory.py) ;
    # à défaut (import antérieur), déduite du détail de l'état. Un échec
    # passager n'arrête donc pas les synchros automatiques.
    source = get_app_config(INVENTORY_SOURCE_KEY)

    if not source:
        state = get_sync_state("software_inventory") or {}
        source = "defender" if str(state.get("detail") or "").startswith("Defender") else ""

    if source != "defender":
        return None

    schedule = get_inventory_schedule()
    now = datetime.now(timezone.utc)

    last_full = _parse(schedule["last_full_at"])

    if last_full is None or now - last_full >= timedelta(days=schedule["full_days"]):
        return "full"

    age = _age("software_inventory")

    if age is None or age >= timedelta(hours=schedule["delta_hours"]):
        return "delta"

    return None


def auto_sync_software_inventory_if_needed():

    mode = inventory_due_mode()

    if not mode:
        return None

    env = os.environ.copy()
    env["VULNWATCH_INVENTORY_MODE"] = mode

    return launch_background_sync(
        INVENTORY_SCRIPT,
        timedelta(hours=min(get_inventory_schedule()["delta_hours"], 1)),
        env=env
    )


def auto_launch_nvd_backfill_if_needed():
    """
    Téléchargement historique NVD au tout premier lancement, avec reprise
    (curseur en base, voir sync_nvd_backfill.py) s'il a été interrompu.
    """

    if is_nvd_backfill_done():
        return None

    state = get_sync_state("nvd_historical_backfill") or {}
    age = _age("nvd_historical_backfill")

    if age is not None:

        if state.get("status") == "RUNNING":
            # Le script met à jour son état après chaque fenêtre : s'il
            # n'a pas bougé depuis un moment, il a été interrompu.
            if age < timedelta(minutes=NVD_BACKFILL_STALE_MINUTES):
                return None
        elif state.get("status") == "ERROR":
            if age < timedelta(minutes=NVD_BACKFILL_ERROR_RETRY_MINUTES):
                return None
        else:
            return None

    return launch_background_sync(
        "sync_nvd_backfill.py",
        timedelta(minutes=NVD_BACKFILL_STALE_MINUTES),
        env=_nvd_env()
    )


def run_due_syncs():
    """Lance toutes les synchros dues. Retourne les clés des tâches lancées."""

    launched = []

    for check in (
        auto_sync_cisa_if_needed,
        auto_enrich_nvd_if_needed,
        auto_notify_if_needed,
        auto_sync_nvd_feed_if_needed,
        auto_sync_software_inventory_if_needed,
        auto_launch_nvd_backfill_if_needed
    ):

        try:
            key = check()
        except Exception as error:
            print(f"[ERROR] {check.__name__} : {error}")
            continue

        if key:
            launched.append(key)

    return launched
