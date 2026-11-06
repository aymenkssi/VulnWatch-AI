"""
Client minimal de l'API ClickUp v2, pour la migration de l'espace
"DSI Infra SecOps" (constats Nessus + suivi de traitement) vers
VulnWatch-AI.

Le token personnel ClickUp n'est JAMAIS codé en dur : il est lu dans la
config en base (app_config) par sync_clickup.py, qui le transmet ici via
la variable d'environnement VULNWATCH_CLICKUP_TOKEN (même mécanisme que
la clé API NVD). Le token n'est envoyé qu'à api.clickup.com, jamais aux
domaines de pièces jointes.

Limites connues de l'API (doc d'aide ClickUp) : 100 requêtes/minute par
token. On espace donc les appels et on respecte les 429
(en-tête X-RateLimit-Reset).
"""

import os
import re
import time
from datetime import datetime, timezone

import requests


CLICKUP_BASE_URL = os.getenv(
    "VULNWATCH_CLICKUP_BASE", "https://api.clickup.com/api/v2"
)

# 100 req/min => 0,6 s mini entre deux appels ; marge de sécurité.
MIN_INTERVAL_SECONDS = float(
    os.getenv("VULNWATCH_CLICKUP_MIN_INTERVAL", "0.7")
)

MAX_RETRIES = 5
RETRY_DELAYS = [5, 15, 30, 60, 120]

PAGE_SIZE = 100          # taille de page fixe de GET /list/{id}/task
COMMENT_PAGE_SIZE = 25   # taille de page de GET /task/{id}/comment

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class ClickUpError(Exception):
    pass


class ClickUpAuthError(ClickUpError):
    pass


class ClickUpClient:

    def __init__(self, token, base_url=None, min_interval=None):

        if not token:
            raise ClickUpAuthError(
                "Aucun token ClickUp configuré."
            )

        self.base_url = (base_url or CLICKUP_BASE_URL).rstrip("/")
        self.min_interval = (
            MIN_INTERVAL_SECONDS if min_interval is None else min_interval
        )
        self._token = token
        self._last_call = 0.0
        self._session = requests.Session()
        self.calls = 0

    # -----------------------------------------------------
    # Requête de base : espacement, 429, 5xx, erreurs d'auth
    # -----------------------------------------------------

    def _get(self, path, params=None):

        url = f"{self.base_url}{path}"

        for attempt in range(1, MAX_RETRIES + 1):

            wait = self.min_interval - (time.monotonic() - self._last_call)

            if wait > 0:
                time.sleep(wait)

            try:

                response = self._session.get(
                    url,
                    params=params,
                    headers={
                        # Token personnel : pas de préfixe "Bearer".
                        "Authorization": self._token,
                        "Content-Type": "application/json"
                    },
                    timeout=(10, 60)
                )

            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError
            ):

                self._last_call = time.monotonic()

                if attempt >= MAX_RETRIES:
                    raise

                time.sleep(RETRY_DELAYS[attempt - 1])
                continue

            self._last_call = time.monotonic()
            self.calls += 1

            if response.status_code in (401, 403):

                raise ClickUpAuthError(
                    f"ClickUp a refusé l'accès (HTTP {response.status_code}) "
                    f"sur {path} : token invalide ou sans droit sur cet "
                    f"espace."
                )

            if response.status_code == 429:

                delay = RETRY_DELAYS[attempt - 1]

                reset = response.headers.get("X-RateLimit-Reset")

                if reset and reset.isdigit():
                    # Timestamp epoch (secondes) de remise à zéro.
                    delay = max(
                        1, min(int(reset) - int(time.time()) + 1, 120)
                    )

                if attempt >= MAX_RETRIES:
                    raise ClickUpError(
                        "Limite de débit ClickUp (429) persistante."
                    )

                time.sleep(delay)
                continue

            if response.status_code >= 500:

                if attempt >= MAX_RETRIES:
                    raise ClickUpError(
                        f"ClickUp HTTP {response.status_code} sur {path}."
                    )

                time.sleep(RETRY_DELAYS[attempt - 1])
                continue

            if response.status_code == 404:
                return None

            if response.status_code >= 400:
                raise ClickUpError(
                    f"ClickUp HTTP {response.status_code} sur {path} : "
                    f"{response.text[:300]}"
                )

            return response.json()

        raise ClickUpError(f"Échec de la requête ClickUp sur {path}.")

    # -----------------------------------------------------
    # Découverte de la structure
    # -----------------------------------------------------

    def get_space(self, space_id):

        return self._get(f"/space/{space_id}")

    def get_lists_of_space(self, space_id, include_archived=False):
        """
        Toutes les listes de l'espace, qu'elles soient dans un dossier ou
        à la racine de l'espace. Retourne une liste de dicts
        {id, name, folder_name, archived, task_count}.
        """

        archived = "true" if include_archived else "false"

        lists = []

        folderless = self._get(
            f"/space/{space_id}/list", {"archived": archived}
        ) or {}

        for item in folderless.get("lists", []):

            lists.append({
                "id": str(item["id"]),
                "name": item.get("name"),
                "folder_name": None,
                "archived": bool(item.get("archived")),
                "task_count": item.get("task_count")
            })

        folders = self._get(
            f"/space/{space_id}/folder", {"archived": archived}
        ) or {}

        for folder in folders.get("folders", []):

            for item in folder.get("lists", []):

                lists.append({
                    "id": str(item["id"]),
                    "name": item.get("name"),
                    "folder_name": folder.get("name"),
                    "archived": bool(item.get("archived")),
                    "task_count": item.get("task_count")
                })

        return lists

    # -----------------------------------------------------
    # Tâches (constats)
    # -----------------------------------------------------

    def iter_list_tasks(self, list_id, include_archived=False):
        """
        Générateur sur TOUTES les tâches d'une liste, fermées comprises
        (include_closed=true : indispensable, un statut comme TRAITE est
        de type "closed" et n'apparaît sinon pas) et sous-tâches.
        """

        page = 0

        while True:

            params = {
                "page": page,
                "include_closed": "true",
                "subtasks": "true",
                "include_markdown_description": "true",
                "archived": "true" if include_archived else "false"
            }

            data = self._get(f"/list/{list_id}/task", params) or {}

            tasks = data.get("tasks", [])

            for task in tasks:
                yield task

            if data.get("last_page") is True or len(tasks) < PAGE_SIZE:
                break

            page += 1

    def get_task(self, task_id):
        """
        Détail d'une tâche : apporte `attachments` et `checklists`, que
        la liste des tâches ne garantit pas.
        """

        return self._get(
            f"/task/{task_id}",
            {
                "include_subtasks": "true",
                "include_markdown_description": "true"
            }
        )

    # -----------------------------------------------------
    # Commentaires
    # -----------------------------------------------------

    def get_task_comments(self, task_id, include_replies=True):
        """
        Tous les commentaires d'une tâche (pagination par `start` /
        `start_id`, 25 par page), réponses de fil comprises.
        """

        comments = []
        params = {}

        while True:

            data = self._get(f"/task/{task_id}/comment", params) or {}

            page = data.get("comments", [])

            comments.extend(page)

            if len(page) < COMMENT_PAGE_SIZE:
                break

            last = page[-1]

            params = {
                "start": last.get("date"),
                "start_id": last.get("id")
            }

        if include_replies:

            replies = []

            for comment in comments:

                if int(comment.get("reply_count") or 0) > 0:

                    thread = self._get(
                        f"/comment/{comment['id']}/reply"
                    ) or {}

                    for reply in thread.get("comments", []):

                        reply["parent_comment_id"] = str(comment["id"])
                        replies.append(reply)

            comments.extend(replies)

        return comments

    # -----------------------------------------------------
    # Pièces jointes (téléchargement sans le token)
    # -----------------------------------------------------

    def download_attachment(self, url, dest_path, max_bytes):
        """
        Télécharge une pièce jointe. Le token ClickUp n'est PAS envoyé :
        les liens de pièces jointes sont des URL signées sur un domaine
        distinct, et le token ne doit sortir que vers api.clickup.com.
        Retourne (ok, message).
        """

        try:

            with requests.get(
                url, stream=True, timeout=(10, 120)
            ) as response:

                if response.status_code != 200:
                    return False, f"HTTP {response.status_code}"

                size = int(response.headers.get("Content-Length") or 0)

                if size and size > max_bytes:
                    return False, (
                        f"Ignoré : {size} octets > limite {max_bytes}"
                    )

                written = 0

                with open(dest_path, "wb") as out:

                    for chunk in response.iter_content(64 * 1024):

                        written += len(chunk)

                        if written > max_bytes:
                            out.close()
                            os.remove(dest_path)
                            return False, "Ignoré : taille > limite"

                        out.write(chunk)

                return True, f"{written} octets"

        except requests.exceptions.RequestException as error:

            return False, str(error)


# =========================================================
# NORMALISATION D'UNE TÂCHE
# =========================================================

def ms_to_iso(value):
    """Les dates ClickUp sont des millisecondes epoch (chaîne ou int)."""

    if value in (None, "", 0, "0"):
        return None

    try:

        return datetime.fromtimestamp(
            int(value) / 1000, tz=timezone.utc
        ).isoformat()

    except (ValueError, TypeError, OverflowError, OSError):

        return None


def resolve_custom_field(field):
    """
    Valeur lisible d'un custom field ClickUp. Selon le type, `value` est
    une chaîne, un nombre, un index d'option (drop_down), une liste d'ids
    (labels), des utilisateurs, une date (ms)... On ramène tout à une
    chaîne ; None si le champ est vide.
    """

    value = field.get("value")

    if value in (None, "", []):
        return None

    field_type = field.get("type")
    options = (field.get("type_config") or {}).get("options") or []

    if field_type == "drop_down":

        for option in options:

            if option.get("orderindex") == value or option.get("id") == value:
                return option.get("name") or option.get("label")

        return str(value)

    if field_type == "labels":

        by_id = {o.get("id"): o.get("label") or o.get("name") for o in options}

        return ", ".join(
            str(by_id.get(v, v)) for v in (value if isinstance(value, list) else [value])
        )

    if field_type in ("users", "list_relationship", "tasks"):

        if isinstance(value, list):

            return ", ".join(
                str(
                    v.get("username") or v.get("email") or v.get("name") or v.get("id")
                    if isinstance(v, dict) else v
                )
                for v in value
            )

    if field_type == "date":
        return ms_to_iso(value)

    if field_type == "checkbox":
        return "oui" if str(value).lower() in ("true", "1") else "non"

    if isinstance(value, (list, dict)):
        return str(value)

    return str(value)


def _field_by_name(custom_fields, patterns):
    """
    Première valeur non vide d'un custom field dont le NOM correspond à
    l'une des expressions (insensible à la casse). On utilise des
    expressions avec bornes de mot pour ne pas confondre "Port" avec
    "Support" ou "Rapport".
    """

    for pattern in patterns:

        regex = re.compile(pattern, re.IGNORECASE)

        for name, value in custom_fields.items():

            if value and name and regex.search(name):
                return value

    return None


def extract_cves(*texts):

    found = []

    for text in texts:

        if not text:
            continue

        for match in CVE_PATTERN.findall(str(text)):

            cve = match.upper()

            if cve not in found:
                found.append(cve)

    return found


def normalize_task(task, space_id=None, list_name=None, folder_name=None):
    """
    Transforme une tâche ClickUp brute en enregistrement `scan_finding`.
    Le JSON brut est conservé tel quel (`raw_json`) : rien n'est perdu
    même si un champ n'est pas (encore) exploité par l'appli.
    """

    custom_fields = {}

    for field in task.get("custom_fields") or []:

        custom_fields[field.get("name")] = resolve_custom_field(field)

    status = task.get("status") or {}
    priority = task.get("priority") or {}
    creator = task.get("creator") or {}
    lst = task.get("list") or {}
    folder = task.get("folder") or {}

    description = (
        task.get("markdown_description")
        or task.get("text_content")
        or task.get("description")
    )

    assignees = [
        {
            "id": str(a.get("id")),
            "username": a.get("username"),
            "email": a.get("email")
        }
        for a in task.get("assignees") or []
    ]

    host = _field_by_name(custom_fields, [r"\bhost", r"\bh[oô]te"])
    port = _field_by_name(custom_fields, [r"\bport\b"])
    risk = _field_by_name(
        custom_fields,
        [r"\brisk", r"\brisque", r"\bseverity", r"\bs[ée]v[ée]rit", r"\bcriticit"]
    )

    parent = task.get("parent")

    return {
        "task_id": str(task["id"]),
        "custom_id": task.get("custom_id"),
        "space_id": str(space_id) if space_id else None,
        "list_id": str(lst.get("id")) if lst.get("id") else None,
        "list_name": list_name or lst.get("name"),
        "folder_name": folder_name or folder.get("name"),
        "title": task.get("name"),
        "description": description,
        "status": status.get("status"),
        "status_type": status.get("type"),
        "priority": priority.get("priority"),
        "host": host,
        "port": port,
        "risk": risk,
        "assignees": assignees,
        "tags": [t.get("name") for t in task.get("tags") or []],
        "creator": creator.get("username"),
        "custom_fields": custom_fields,
        "cves": extract_cves(
            task.get("name"),
            description,
            *[v for v in custom_fields.values() if v]
        ),
        "date_created": ms_to_iso(task.get("date_created")),
        "date_updated": ms_to_iso(task.get("date_updated")),
        "date_closed": ms_to_iso(task.get("date_closed")),
        "date_done": ms_to_iso(task.get("date_done")),
        "due_date": ms_to_iso(task.get("due_date")),
        "url": task.get("url"),
        "parent_task_id": str(parent) if parent else None,
        "attachments": task.get("attachments") or [],
        "checklists": task.get("checklists") or [],
        "raw": task
    }


def normalize_comment(comment, task_id):

    user = comment.get("user") or {}

    return {
        "comment_id": str(comment.get("id")),
        "task_id": str(task_id),
        "parent_comment_id": comment.get("parent_comment_id"),
        "author_name": user.get("username"),
        "author_email": user.get("email"),
        "text": comment.get("comment_text"),
        "date": ms_to_iso(comment.get("date"))
    }
