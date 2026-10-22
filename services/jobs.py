"""
Tâches de synchronisation en arrière-plan, avec suivi de progression.

Les boutons "Synchroniser ..." de l'interface lançaient les scripts avec
subprocess.run : Streamlit attendait la fin du script et toute la page
restait figée (grisée) pendant plusieurs minutes. Ici :

  - start_job() lance le script dans un sous-processus détaché, via ce
    même fichier utilisé comme "lanceur" (voir _run_job plus bas) ;
  - le lanceur écrit l'état de la tâche dans data/jobs/<clé>.status.json
    (RUNNING puis DONE / ERROR, code retour, battement de cœur) et la
    sortie du script dans data/jobs/<clé>.log ;
  - le script appelle report_progress() dans ses boucles, ce qui écrit
    data/jobs/<clé>.progress.json ; l'interface lit ces fichiers pour
    afficher une barre de progression sans bloquer.

Des fichiers plutôt que la base SQLite : l'interface les relit toutes
les 2 secondes pendant une synchro, ça n'ajoute aucune écriture
concurrente sur la base.

Ce module n'utilise que la bibliothèque standard : il est importé par
les scripts de synchro et exécuté directement comme lanceur.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
JOBS_DIR = BASE_DIR / "data" / "jobs"

JOB_KEY_ENV = "VULNWATCH_JOB_KEY"

# Le lanceur met à jour son battement de cœur toutes les
# HEARTBEAT_SECONDS. Une tâche "RUNNING" dont le battement est plus vieux
# que STALE_SECONDS a été interrompue (redémarrage du serveur, process
# tué...) : on la considère terminée pour pouvoir la relancer.
HEARTBEAT_SECONDS = 5
STALE_SECONDS = 60


def _now():

    return datetime.now(timezone.utc)


def _path(key, suffix):

    return JOBS_DIR / f"{key}.{suffix}"


def _write_json(path, data):

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")

    # Sous Windows, os.replace échoue si l'interface est justement en
    # train de lire le fichier : on réessaie un court instant.
    for _ in range(20):

        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.05)

    tmp.unlink(missing_ok=True)


def _read_json(path):

    for _ in range(3):

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            time.sleep(0.05)

    return None


def _age_seconds(iso_value):

    try:
        return (_now() - datetime.fromisoformat(iso_value)).total_seconds()
    except (TypeError, ValueError):
        return None


# =========================================================
# CÔTÉ INTERFACE
# =========================================================

def get_job(key):
    """
    État de la dernière exécution de la tâche `key`, ou None si elle
    n'a jamais été lancée. Champs ajoutés :
      - running : True tant que le script tourne ;
      - progress : dernier report_progress() du script (ou None) ;
      - elapsed_seconds : durée depuis le lancement (ou durée totale).
    """

    status = _read_json(_path(key, "status.json"))

    if not status:
        return None

    if status.get("status") == "RUNNING":

        age = _age_seconds(status.get("heartbeat_at"))

        if age is None or age > STALE_SECONDS:
            status["status"] = "INTERRUPTED"

    status["running"] = status.get("status") == "RUNNING"
    status["stop_requested"] = (
        status["running"] and _path(key, "stop").exists()
    )
    status["progress"] = _read_json(_path(key, "progress.json"))

    end = status.get("finished_at") if not status["running"] else None
    started = _age_seconds(status.get("started_at"))
    finished = _age_seconds(end) if end else 0

    if started is not None and finished is not None:
        status["elapsed_seconds"] = max(started - finished, 0)
    else:
        status["elapsed_seconds"] = None

    return status


def is_job_running(key):

    job = get_job(key)

    return bool(job and job["running"])


def start_job(key, script, label, env=None):
    """
    Lance `script` en arrière-plan sous la clé `key`. Ne fait rien et
    retourne False si la même tâche tourne déjà (un clic de plus, ou la
    synchro automatique, ne la lance pas une seconde fois).
    """

    if is_job_running(key):
        return False

    JOBS_DIR.mkdir(parents=True, exist_ok=True)

    _path(key, "progress.json").unlink(missing_ok=True)
    _path(key, "stop").unlink(missing_ok=True)

    now = _now().isoformat()

    _write_json(
        _path(key, "status.json"),
        {
            "key": key,
            "script": script,
            "label": label,
            "status": "RUNNING",
            "started_at": now,
            "heartbeat_at": now,
            "finished_at": None,
            "returncode": None
        }
    )

    kwargs = {}

    if os.name == "nt":
        # Pas de fenêtre console qui s'ouvre sur le serveur.
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), key, script],
        cwd=BASE_DIR,
        env=env if env is not None else os.environ.copy(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **kwargs
    )

    return True


def request_stop(key):
    """
    Demande l'arrêt d'une tâche en cours : le lanceur voit cette demande
    dans la seconde et arrête le script (et ses sous-processus).
    """

    if is_job_running(key):
        _path(key, "stop").touch()
        return True

    return False


def read_job_log(key, max_chars=6000):
    """Fin du journal (stdout + stderr) de la dernière exécution."""

    try:
        text = _path(key, "log").read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""

    return text[-max_chars:]


def last_log_line(key):

    for line in reversed(read_job_log(key, 2000).splitlines()):

        line = line.strip(" =-\t")

        if line:
            return line

    return ""


# =========================================================
# CÔTÉ SCRIPTS DE SYNCHRO
# =========================================================

_last_report = 0.0


def report_progress(current, total=None, message=None, force=False):
    """
    À appeler depuis les boucles des scripts de synchro. Ne fait rien si
    le script n'a pas été lancé par start_job() (exécution à la main en
    ligne de commande, synchro historique NVD...). Limité à une écriture
    toutes les 0,5 s, sauf force=True (dernière étape).
    """

    global _last_report

    key = os.getenv(JOB_KEY_ENV)

    if not key:
        return

    now = time.monotonic()

    if not force and now - _last_report < 0.5:
        return

    _last_report = now

    _write_json(
        _path(key, "progress.json"),
        {
            "current": current,
            "total": total,
            "message": message,
            "updated_at": _now().isoformat()
        }
    )


# =========================================================
# LANCEUR
# =========================================================

def _kill_tree(process):
    """
    Arrête le script et ses éventuels sous-processus. Sous Windows, le
    python.exe d'un venv relance le vrai interpréteur dans un processus
    enfant : on arrête tout l'arbre avec taskkill /T.
    """

    if os.name == "nt":

        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

    else:

        process.kill()


def _run_job(key, script):

    status_path = _path(key, "status.json")
    status = _read_json(status_path) or {
        "key": key,
        "script": script,
        "label": script,
        "started_at": _now().isoformat()
    }

    env = os.environ.copy()
    env[JOB_KEY_ENV] = key
    # Sortie non tamponnée : le journal (et la dernière ligne affichée
    # sous la barre de progression) suit le script en temps réel.
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    kwargs = {}

    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    with open(_path(key, "log"), "w", encoding="utf-8") as log:

        process = subprocess.Popen(
            [sys.executable, script],
            cwd=BASE_DIR,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            **kwargs
        )

        stop_path = _path(key, "stop")
        stopped = False
        last_heartbeat = time.monotonic()

        while True:

            try:
                # Attente courte : une demande d'arrêt est prise en compte
                # en moins d'une seconde.
                returncode = process.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                pass

            if stop_path.exists() and not stopped:

                stopped = True
                log.write("\n[ARRÊT] Synchronisation arrêtée à la demande.\n")
                log.flush()
                _kill_tree(process)

            if time.monotonic() - last_heartbeat >= HEARTBEAT_SECONDS:

                last_heartbeat = time.monotonic()
                status["status"] = "RUNNING"
                status["heartbeat_at"] = _now().isoformat()
                _write_json(status_path, status)

    stop_path.unlink(missing_ok=True)

    if stopped:
        status["status"] = "STOPPED"
    else:
        status["status"] = "DONE" if returncode == 0 else "ERROR"
    status["returncode"] = returncode
    status["finished_at"] = _now().isoformat()
    status["heartbeat_at"] = status["finished_at"]

    _write_json(status_path, status)


if __name__ == "__main__":

    _run_job(sys.argv[1], sys.argv[2])
