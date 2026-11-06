"""
Stockage de la rubrique "Scan vulnérabilité" : constats Nessus migrés
depuis l'espace ClickUp "DSI Infra SecOps" (et, ensuite, tout import de
scan futur).

Module autonome : il ne modifie pas database.initialize_database(). Ses
propres tables sont créées à la demande (ensure_scan_tables), une seule
fois par process (même garde-fou que database._DB_INITIALIZED, car
Streamlit réexécute tout le script à chaque interaction).

Écritures TOUJOURS par lot dans UNE connexion : une écriture par ligne
(une connexion par constat) a déjà provoqué des "database is locked" /
pages figées sur ce projet.
"""

import json

from database import (
    get_connection,
    get_app_config,
    set_app_config
)


CLICKUP_TOKEN_KEY = "clickup_api_token"
CLICKUP_SPACE_KEY = "clickup_space_id"
CLICKUP_DONE_LISTS_KEY = "clickup_done_lists"

# Espace "DSI Infra SecOps" (URL .../20473392/v/s/60866384/...).
DEFAULT_CLICKUP_SPACE_ID = "60866384"

SYNC_KEY = "clickup_migration"

_TABLES_READY = False


# =========================================================
# SCHÉMA
# =========================================================

def ensure_scan_tables():

    global _TABLES_READY

    if _TABLES_READY:
        return

    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_findings (

            task_id TEXT PRIMARY KEY,
            custom_id TEXT,

            source TEXT DEFAULT 'ClickUp',

            space_id TEXT,
            list_id TEXT,
            list_name TEXT,
            folder_name TEXT,

            title TEXT,
            description TEXT,

            status TEXT,
            status_type TEXT,
            treated INTEGER DEFAULT 0,

            priority TEXT,
            risk TEXT,

            host TEXT,
            port TEXT,

            assignee_names TEXT,
            assignees_json TEXT,
            tags_json TEXT,
            creator TEXT,

            custom_fields_json TEXT,
            checklists_json TEXT,
            raw_json TEXT,

            date_created TEXT,
            date_updated TEXT,
            date_closed TEXT,
            date_done TEXT,
            due_date TEXT,

            url TEXT,
            parent_task_id TEXT,

            details_synced INTEGER DEFAULT 0,
            imported_at TEXT,
            last_synced_at TEXT

        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_finding_cves (

            task_id TEXT,
            cve_id TEXT,

            UNIQUE (task_id, cve_id)

        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_finding_comments (

            comment_id TEXT PRIMARY KEY,
            task_id TEXT,
            parent_comment_id TEXT,

            author_name TEXT,
            author_email TEXT,
            text TEXT,
            date TEXT

        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_finding_attachments (

            attachment_id TEXT PRIMARY KEY,
            task_id TEXT,

            title TEXT,
            extension TEXT,
            size INTEGER,
            url TEXT,
            date TEXT,

            local_path TEXT,
            download_status TEXT

        )
    """)

    for index_sql in (
        "CREATE INDEX IF NOT EXISTS idx_scan_findings_status ON scan_findings(status)",
        "CREATE INDEX IF NOT EXISTS idx_scan_findings_list ON scan_findings(list_name)",
        "CREATE INDEX IF NOT EXISTS idx_scan_findings_host ON scan_findings(host)",
        "CREATE INDEX IF NOT EXISTS idx_scan_cves_cve ON scan_finding_cves(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_comments_task ON scan_finding_comments(task_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_attach_task ON scan_finding_attachments(task_id)"
    ):
        conn.execute(index_sql)

    conn.commit()
    conn.close()

    _TABLES_READY = True


# =========================================================
# CONFIGURATION (jamais de secret dans un fichier)
# =========================================================

def get_clickup_token():

    return get_app_config(CLICKUP_TOKEN_KEY, "")


def set_clickup_token(token):

    # Comme SMTP / Hexiosec / NVD : un champ laissé vide n'écrase jamais
    # un token déjà enregistré.
    if token:
        set_app_config(CLICKUP_TOKEN_KEY, token)


def get_clickup_space_id():

    return get_app_config(CLICKUP_SPACE_KEY, DEFAULT_CLICKUP_SPACE_ID)


def set_clickup_space_id(space_id):

    if space_id:
        set_app_config(CLICKUP_SPACE_KEY, str(space_id).strip())


def get_done_lists():

    raw = get_app_config(CLICKUP_DONE_LISTS_KEY, "[]")

    try:
        return set(json.loads(raw))
    except (ValueError, TypeError):
        return set()


def mark_list_done(list_id):

    done = get_done_lists()
    done.add(str(list_id))

    set_app_config(CLICKUP_DONE_LISTS_KEY, json.dumps(sorted(done)))


def reset_clickup_migration():
    """
    Oublie quelles listes sont terminées (la prochaine exécution
    reparcourt tout). Ne supprime AUCUN constat déjà migré.
    """

    set_app_config(CLICKUP_DONE_LISTS_KEY, "[]")


# =========================================================
# ÉCRITURE
# =========================================================

_FINDING_COLUMNS = (
    "task_id", "custom_id", "space_id", "list_id", "list_name",
    "folder_name", "title", "description", "status", "status_type",
    "treated", "priority", "risk", "host", "port", "assignee_names",
    "assignees_json", "tags_json", "creator", "custom_fields_json",
    "checklists_json", "raw_json", "date_created", "date_updated",
    "date_closed", "date_done", "due_date", "url", "parent_task_id",
    "details_synced", "imported_at", "last_synced_at"
)


def _finding_row(finding, now_iso, details_synced):

    names = ", ".join(
        a.get("username") or a.get("email") or ""
        for a in finding.get("assignees") or []
    )

    return (
        finding["task_id"],
        finding.get("custom_id"),
        finding.get("space_id"),
        finding.get("list_id"),
        finding.get("list_name"),
        finding.get("folder_name"),
        finding.get("title"),
        finding.get("description"),
        finding.get("status"),
        finding.get("status_type"),
        1 if finding.get("status_type") in ("done", "closed") else 0,
        finding.get("priority"),
        finding.get("risk"),
        finding.get("host"),
        finding.get("port"),
        names,
        json.dumps(finding.get("assignees") or [], ensure_ascii=False),
        json.dumps(finding.get("tags") or [], ensure_ascii=False),
        finding.get("creator"),
        json.dumps(finding.get("custom_fields") or {}, ensure_ascii=False),
        json.dumps(finding.get("checklists") or [], ensure_ascii=False),
        json.dumps(finding.get("raw") or {}, ensure_ascii=False),
        finding.get("date_created"),
        finding.get("date_updated"),
        finding.get("date_closed"),
        finding.get("date_done"),
        finding.get("due_date"),
        finding.get("url"),
        finding.get("parent_task_id"),
        1 if details_synced else 0,
        now_iso,
        now_iso
    )


def save_scan_batch(items, now_iso):
    """
    Enregistre un lot en UNE transaction. `items` : liste de dicts
    {finding, comments, attachments, details_synced}, où `finding` vient
    de collectors.clickup.normalize_task(), `comments` de
    normalize_comment() et `attachments` du détail de tâche ClickUp.

    Idempotent : rejouer le même lot met à jour sans doublon, et
    `imported_at` d'origine est conservé.
    """

    ensure_scan_tables()

    placeholders = ", ".join("?" for _ in _FINDING_COLUMNS)

    updates = ", ".join(
        f"{c} = excluded.{c}"
        for c in _FINDING_COLUMNS
        if c not in ("task_id", "imported_at")
    )

    sql = (
        f"INSERT INTO scan_findings ({', '.join(_FINDING_COLUMNS)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT(task_id) DO UPDATE SET {updates}"
    )

    conn = get_connection()

    for item in items:

        finding = item["finding"]
        task_id = finding["task_id"]

        conn.execute(
            sql,
            _finding_row(finding, now_iso, item.get("details_synced"))
        )

        conn.execute(
            "DELETE FROM scan_finding_cves WHERE task_id = ?", (task_id,)
        )

        for cve_id in finding.get("cves") or []:

            conn.execute(
                "INSERT OR IGNORE INTO scan_finding_cves (task_id, cve_id) "
                "VALUES (?, ?)",
                (task_id, cve_id)
            )

        for comment in item.get("comments") or []:

            conn.execute(
                """
                INSERT INTO scan_finding_comments (
                    comment_id, task_id, parent_comment_id,
                    author_name, author_email, text, date
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(comment_id) DO UPDATE SET
                    text = excluded.text,
                    author_name = excluded.author_name,
                    author_email = excluded.author_email,
                    date = excluded.date
                """,
                (
                    comment["comment_id"], task_id,
                    comment.get("parent_comment_id"),
                    comment.get("author_name"), comment.get("author_email"),
                    comment.get("text"), comment.get("date")
                )
            )

        for attachment in item.get("attachments") or []:

            conn.execute(
                """
                INSERT INTO scan_finding_attachments (
                    attachment_id, task_id, title, extension, size, url, date
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(attachment_id) DO UPDATE SET
                    title = excluded.title,
                    url = excluded.url,
                    size = excluded.size
                """,
                (
                    str(attachment.get("id")), task_id,
                    attachment.get("title"), attachment.get("extension"),
                    attachment.get("size"), attachment.get("url"),
                    str(attachment.get("date") or "")
                )
            )

    conn.commit()
    conn.close()


def set_attachment_download(attachment_id, local_path, status):

    conn = get_connection()

    conn.execute(
        "UPDATE scan_finding_attachments "
        "SET local_path = ?, download_status = ? WHERE attachment_id = ?",
        (local_path, status, str(attachment_id))
    )

    conn.commit()
    conn.close()


def get_synced_task_state():
    """
    {task_id: date_updated} des constats dont le détail (pièces jointes +
    commentaires) a déjà été récupéré : permet de reprendre une
    migration interrompue, ou de rafraîchir uniquement ce qui a changé,
    sans refaire les milliers d'appels déjà effectués.
    """

    ensure_scan_tables()

    conn = get_connection()

    rows = conn.execute(
        "SELECT task_id, date_updated FROM scan_findings "
        "WHERE details_synced = 1"
    ).fetchall()

    conn.close()

    return {r["task_id"]: r["date_updated"] for r in rows}


# =========================================================
# LECTURE (rubrique "Scan vulnérabilité")
# =========================================================

def get_scan_summary():

    ensure_scan_tables()

    conn = get_connection()

    total = conn.execute(
        "SELECT COUNT(*) AS n FROM scan_findings"
    ).fetchone()["n"]

    by_status = conn.execute(
        """
        SELECT status, status_type, COUNT(*) AS n
        FROM scan_findings
        GROUP BY status, status_type
        ORDER BY n DESC
        """
    ).fetchall()

    by_list = conn.execute(
        """
        SELECT list_name, COUNT(*) AS n,
               SUM(CASE WHEN treated = 0 THEN 1 ELSE 0 END) AS open_n
        FROM scan_findings
        GROUP BY list_name
        ORDER BY n DESC
        """
    ).fetchall()

    hosts = conn.execute(
        "SELECT COUNT(DISTINCT host) AS n FROM scan_findings "
        "WHERE host IS NOT NULL AND host <> ''"
    ).fetchone()["n"]

    conn.close()

    return {
        "total": total,
        "hosts": hosts,
        "by_status": [dict(r) for r in by_status],
        "by_list": [dict(r) for r in by_list]
    }


def get_scan_filter_options():

    ensure_scan_tables()

    conn = get_connection()

    lists = [
        r["list_name"] for r in conn.execute(
            "SELECT DISTINCT list_name FROM scan_findings "
            "WHERE list_name IS NOT NULL ORDER BY list_name"
        ).fetchall()
    ]

    statuses = [
        r["status"] for r in conn.execute(
            "SELECT DISTINCT status FROM scan_findings "
            "WHERE status IS NOT NULL ORDER BY status"
        ).fetchall()
    ]

    conn.close()

    return {"lists": lists, "statuses": statuses}


def get_scan_findings(
    lists=None, statuses=None, search=None, only_untreated=False,
    limit=5000
):

    ensure_scan_tables()

    query = """
        SELECT
            f.task_id, f.custom_id, f.list_name, f.title, f.status,
            f.status_type, f.treated, f.priority, f.risk, f.host, f.port,
            f.assignee_names, f.date_created, f.date_updated,
            f.date_closed, f.due_date, f.url,
            (SELECT GROUP_CONCAT(c.cve_id, ', ')
               FROM scan_finding_cves c WHERE c.task_id = f.task_id) AS cves
        FROM scan_findings f
        WHERE 1 = 1
    """

    params = []

    if lists:
        query += f" AND f.list_name IN ({', '.join('?' for _ in lists)})"
        params.extend(lists)

    if statuses:
        query += f" AND f.status IN ({', '.join('?' for _ in statuses)})"
        params.extend(statuses)

    if only_untreated:
        query += " AND f.treated = 0"

    if search:

        like = f"%{search}%"

        query += (
            " AND (f.title LIKE ? OR f.host LIKE ? OR f.assignee_names LIKE ?"
            " OR f.description LIKE ? OR f.task_id IN ("
            "   SELECT task_id FROM scan_finding_cves WHERE cve_id LIKE ?))"
        )

        params.extend([like, like, like, like, like])

    query += " ORDER BY f.date_updated DESC LIMIT ?"
    params.append(int(limit))

    conn = get_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    return [dict(r) for r in rows]


def get_scan_finding_detail(task_id):

    ensure_scan_tables()

    conn = get_connection()

    row = conn.execute(
        "SELECT * FROM scan_findings WHERE task_id = ?", (task_id,)
    ).fetchone()

    if row is None:
        conn.close()
        return None

    finding = dict(row)

    finding["custom_fields"] = json.loads(
        finding.pop("custom_fields_json") or "{}"
    )

    finding["comments"] = [
        dict(r) for r in conn.execute(
            "SELECT * FROM scan_finding_comments WHERE task_id = ? "
            "ORDER BY date", (task_id,)
        ).fetchall()
    ]

    finding["attachments"] = [
        dict(r) for r in conn.execute(
            "SELECT * FROM scan_finding_attachments WHERE task_id = ?",
            (task_id,)
        ).fetchall()
    ]

    finding["cves"] = [
        r["cve_id"] for r in conn.execute(
            "SELECT cve_id FROM scan_finding_cves WHERE task_id = ? "
            "ORDER BY cve_id", (task_id,)
        ).fetchall()
    ]

    conn.close()

    return finding


def get_scan_cve_context(cve_ids):
    """
    Croisement des CVE citées dans les constats avec le reste de
    VulnWatch : source (CISA KEV / NVD), priorité, CVSS, date de
    publication NVD, et nombre d'équipements où Defender XDR a vu la CVE.
    Tolère l'absence de `defender_vulnerabilities` (base neuve).
    """

    if not cve_ids:
        return {}

    conn = get_connection()

    placeholders = ", ".join("?" for _ in cve_ids)

    context = {cve: {} for cve in cve_ids}

    try:

        for r in conn.execute(
            f"""
            SELECT cve_id, source, priority, cvss_v3_score, nvd_published
            FROM vulnerabilities
            WHERE cve_id IN ({placeholders})
            """,
            list(cve_ids)
        ).fetchall():

            context[r["cve_id"]].update({
                "source": r["source"],
                "priority": r["priority"],
                "cvss": r["cvss_v3_score"],
                "nvd_published": r["nvd_published"]
            })

    except Exception:
        pass

    try:

        for r in conn.execute(
            f"""
            SELECT cve_id, COUNT(DISTINCT device_id) AS devices
            FROM defender_vulnerabilities
            WHERE cve_id IN ({placeholders})
            GROUP BY cve_id
            """,
            list(cve_ids)
        ).fetchall():

            context[r["cve_id"]]["defender_devices"] = r["devices"]

    except Exception:
        pass

    conn.close()

    return context
