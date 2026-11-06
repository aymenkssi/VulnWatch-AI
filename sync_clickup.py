"""
Migration de l'espace ClickUp "DSI Infra SecOps" vers la rubrique
"Scan vulnérabilité" de VulnWatch-AI (méthode API ClickUp).

Lancé en sous-processus détaché par l'appli (comme le téléchargement
historique NVD) : la migration peut durer plusieurs dizaines de minutes
(limite ClickUp : 100 requêtes/minute par token) et ne doit jamais
bloquer l'interface.

Configuration (jamais en dur) :
  - token : VULNWATCH_CLICKUP_TOKEN (transmis par l'appli depuis la
    config en base), sinon config en base directement ;
  - VULNWATCH_CLICKUP_SPACE : id de l'espace (sinon config / défaut) ;
  - VULNWATCH_CLICKUP_COMMENTS=1 : récupérer les commentaires ;
  - VULNWATCH_CLICKUP_ATTACHMENTS=1 : métadonnées des pièces jointes ;
  - VULNWATCH_CLICKUP_DOWNLOAD=1 : télécharger les fichiers (ils
    disparaîtront avec l'instance ClickUp) ;
  - VULNWATCH_CLICKUP_ARCHIVED=1 : inclure listes/tâches archivées ;
  - VULNWATCH_CLICKUP_MAX_MB : taille max d'une pièce jointe (25).

Reprise : une tâche déjà migrée (détail récupéré) et inchangée côté
ClickUp n'est pas re-téléchargée ; les listes terminées sont mémorisées.
Relancer le script après une interruption reprend donc là où il s'est
arrêté, et le relancer plus tard rafraîchit seulement ce qui a changé.
"""

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from database import (
    initialize_database,
    set_sync_state
)
from scan_store import (
    SYNC_KEY,
    ensure_scan_tables,
    get_clickup_token,
    get_clickup_space_id,
    get_done_lists,
    mark_list_done,
    get_synced_task_state,
    save_scan_batch,
    set_attachment_download
)
from services.jobs import report_progress
from collectors.clickup import (
    ClickUpClient,
    ClickUpError,
    ClickUpAuthError,
    normalize_task,
    normalize_comment,
    ms_to_iso
)


ATTACHMENTS_DIR = Path("data/clickup_attachments")

# Enregistrement en base par lots, et battement de cœur du statut.
BATCH_SIZE = 25


def _flag(name, default="0"):

    return os.getenv(name, default).strip() in ("1", "true", "yes", "on")


def _safe_filename(name):

    cleaned = re.sub(r"[^\w.\- ]", "_", name or "fichier", flags=re.UNICODE)

    return cleaned.strip()[:120] or "fichier"


def _now():

    return datetime.now(timezone.utc).isoformat()


def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Migration ClickUp (DSI Infra SecOps)")
    print("=" * 60)
    print()

    initialize_database()
    ensure_scan_tables()

    token = os.getenv("VULNWATCH_CLICKUP_TOKEN") or get_clickup_token()
    space_id = os.getenv("VULNWATCH_CLICKUP_SPACE") or get_clickup_space_id()

    with_comments = _flag("VULNWATCH_CLICKUP_COMMENTS", "1")
    with_attachments = _flag("VULNWATCH_CLICKUP_ATTACHMENTS", "1")
    with_download = _flag("VULNWATCH_CLICKUP_DOWNLOAD", "0")
    include_archived = _flag("VULNWATCH_CLICKUP_ARCHIVED", "0")
    max_bytes = int(float(os.getenv("VULNWATCH_CLICKUP_MAX_MB", "25")) * 1024 * 1024)

    # Le détail d'une tâche (get_task) est nécessaire pour les pièces
    # jointes et les checklists ; les commentaires ont leur propre appel.
    need_detail = with_attachments or with_download

    set_sync_state(SYNC_KEY, "RUNNING", "Démarrage de la migration ClickUp...")

    try:

        client = ClickUpClient(token)

        space = client.get_space(space_id)

        if space is None:
            raise ClickUpError(
                f"Espace ClickUp {space_id} introuvable (id incorrect ou "
                f"token sans accès)."
            )

        print(f"Espace : {space.get('name')} ({space_id})")

        lists = client.get_lists_of_space(space_id, include_archived)

        done_lists = get_done_lists()
        synced = get_synced_task_state()

        print(f"{len(lists)} liste(s) dans l'espace.")
        print()

        totals = {"tasks": 0, "skipped": 0, "comments": 0, "files": 0}

        for list_index, lst in enumerate(lists, start=1):

            label = (
                f"{lst['folder_name']} / {lst['name']}"
                if lst["folder_name"] else lst["name"]
            )

            if lst["id"] in done_lists:

                print(f"[{list_index}/{len(lists)}] {label} : déjà migrée.")
                continue

            print(
                f"[{list_index}/{len(lists)}] {label} "
                f"(~{lst.get('task_count') or '?'} tâches)..."
            )

            report_progress(
                list_index - 1, len(lists),
                f"Liste « {label} »", force=True
            )

            batch = []
            list_tasks = 0

            for raw in client.iter_list_tasks(lst["id"], include_archived):

                list_tasks += 1

                # Limité à une écriture toutes les 0,5 s par jobs.py.
                report_progress(
                    list_index - 1, len(lists),
                    f"Liste « {label} » : {list_tasks} tâches parcourues "
                    f"({totals['tasks']} migrées, {totals['skipped']} déjà "
                    f"à jour, {client.calls} appels API)"
                )

                task_id = str(raw["id"])
                updated_iso = ms_to_iso(raw.get("date_updated"))

                already = synced.get(task_id)

                if already is not None and already == updated_iso:

                    # Détail + commentaires déjà récupérés et tâche
                    # inchangée : on ne refait pas ces appels.
                    totals["skipped"] += 1
                    continue

                task = raw

                if need_detail:

                    detail = client.get_task(task_id)

                    if detail:
                        task = detail

                finding = normalize_task(
                    task, space_id, lst["name"], lst["folder_name"]
                )

                comments = []

                if with_comments:

                    comments = [
                        normalize_comment(c, task_id)
                        for c in client.get_task_comments(task_id)
                    ]

                    totals["comments"] += len(comments)

                batch.append({
                    "finding": finding,
                    "comments": comments,
                    "attachments": finding["attachments"],
                    "details_synced": True
                })

                totals["tasks"] += 1

                if len(batch) >= BATCH_SIZE:

                    save_scan_batch(batch, _now())

                    totals["files"] += _download_attachments(
                        client, batch, with_download, max_bytes
                    )

                    batch = []

                    set_sync_state(
                        SYNC_KEY,
                        "RUNNING",
                        f"Liste {list_index}/{len(lists)} « {label} » : "
                        f"{list_tasks} tâches parcourues "
                        f"({totals['tasks']} migrées au total, "
                        f"{client.calls} appels API)"
                    )

            if batch:

                save_scan_batch(batch, _now())

                totals["files"] += _download_attachments(
                    client, batch, with_download, max_bytes
                )

            mark_list_done(lst["id"])

            print(f"    {list_tasks} tâche(s) parcourue(s).")

            set_sync_state(
                SYNC_KEY,
                "RUNNING",
                f"Liste {list_index}/{len(lists)} « {label} » terminée "
                f"({totals['tasks']} migrées, {totals['skipped']} déjà à "
                f"jour, {client.calls} appels API)"
            )

    except ClickUpAuthError as error:

        print(f"[ERROR] Accès ClickUp refusé : {error}")

        set_sync_state(SYNC_KEY, "ERROR", str(error))

        sys.exit(1)

    except Exception as error:

        print()
        print(f"[ERROR] Migration ClickUp interrompue : {error}")

        # Les listes terminées et les tâches déjà enregistrées sont
        # conservées : relancer reprend sans tout refaire.
        set_sync_state(
            SYNC_KEY,
            "ERROR",
            f"Interrompue : {error} (relancer pour reprendre)"
        )

        sys.exit(1)

    report_progress(len(lists), len(lists), "Migration terminée", force=True)

    print()
    print("Migration terminée.")
    print(f"  Tâches migrées      : {totals['tasks']}")
    print(f"  Déjà à jour (ignorées) : {totals['skipped']}")
    print(f"  Commentaires        : {totals['comments']}")
    print(f"  Fichiers téléchargés: {totals['files']}")
    print(f"  Appels API ClickUp  : {client.calls}")
    print()

    set_sync_state(
        SYNC_KEY,
        "OK",
        f"{totals['tasks']} constats migrés, {totals['skipped']} déjà à jour, "
        f"{totals['comments']} commentaires, {totals['files']} fichiers, "
        f"{client.calls} appels API"
    )


def _download_attachments(client, batch, enabled, max_bytes):

    if not enabled:
        return 0

    downloaded = 0

    for item in batch:

        task_id = item["finding"]["task_id"]

        for attachment in item.get("attachments") or []:

            url = attachment.get("url")

            if not url:
                continue

            target_dir = ATTACHMENTS_DIR / task_id
            target_dir.mkdir(parents=True, exist_ok=True)

            target = target_dir / (
                f"{attachment.get('id')}_"
                f"{_safe_filename(attachment.get('title'))}"
            )

            ok, message = client.download_attachment(url, target, max_bytes)

            set_attachment_download(
                attachment.get("id"),
                str(target) if ok else None,
                "OK" if ok else f"ERREUR : {message}"
            )

            if ok:
                downloaded += 1

    return downloaded


if __name__ == "__main__":
    main()
