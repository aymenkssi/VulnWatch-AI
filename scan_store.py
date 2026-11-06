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
import re
import uuid

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


def _backfill_nessus_fields(conn):
    """
    Constats déjà migrés avant l'ajout des colonnes Nessus : les valeurs
    sont relues dans le JSON ClickUp brut conservé (raw_json).
    """

    from collectors.clickup import resolve_custom_field, extract_nessus_fields

    rows = conn.execute(
        "SELECT task_id, raw_json FROM scan_findings WHERE raw_json IS NOT NULL"
    ).fetchall()

    for row in rows:

        try:
            raw = json.loads(row["raw_json"] or "{}")
        except (ValueError, TypeError):
            continue

        by_id, by_name = {}, {}

        for field in raw.get("custom_fields") or []:

            value = resolve_custom_field(field)
            by_id[field.get("id")] = value
            by_name[field.get("name")] = value

        nessus = extract_nessus_fields(by_id, by_name)

        conn.execute(
            "UPDATE scan_findings SET plugin_id = ?, cve = ?, cvss = ?, "
            "last_scan = ? WHERE task_id = ?",
            (nessus["plugin_id"], nessus["cve"], nessus["cvss"],
             nessus["last_scan"], row["task_id"])
        )


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

    # Référentiel des personnes à qui l'on assigne un constat (liste
    # déroulante « Assigné »). Rempli une première fois avec les assignés
    # ClickUp migrés, puis complété à la main dans l'interface.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            utilisateur TEXT NOT NULL UNIQUE COLLATE NOCASE,
            mail TEXT,

            -- Nom de l'assigné dans ClickUp : garde le lien quand
            -- l'utilisateur est renommé (« jdupont » -> « Jean DUPONT »).
            clickup_name TEXT COLLATE NOCASE

        )
    """)

    # Correspondances machine détectée par Nessus (IP ou nom) -> hôte,
    # qui remplacent le fichier IP;HOST du script ImportVullns.ps1.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_host_map (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine TEXT NOT NULL UNIQUE COLLATE NOCASE,
            hote TEXT NOT NULL

        )
    """)

    # Assignation locale (VulnWatch), distincte de l'assignation ClickUp
    # d'origine (assignee_names / assignees_json, que la migration
    # réécrit). assigned_manual = 1 : modifiée dans l'interface, le
    # remplissage automatique n'y touche plus.
    existing = {
        r["name"] for r in conn.execute("PRAGMA table_info(scan_findings)")
    }

    if "assigned_user_id" not in existing:
        conn.execute(
            "ALTER TABLE scan_findings ADD COLUMN assigned_user_id INTEGER"
        )

    # Champs Nessus dédiés (Plugin ID, CVE, CVSS, date du dernier scan) :
    # clé de rapprochement de l'import de scan, comme dans le script
    # ImportVullns.ps1. local_modified_at : constat créé ou modifié par
    # un import local ; la migration ClickUp ne l'écrase plus.
    added_nessus = False

    for column in ("plugin_id", "cve", "cvss", "last_scan", "local_modified_at"):

        if column not in existing:

            conn.execute(f"ALTER TABLE scan_findings ADD COLUMN {column} TEXT")

            added_nessus = True

    if added_nessus:
        _backfill_nessus_fields(conn)

    if "assigned_manual" not in existing:
        conn.execute(
            "ALTER TABLE scan_findings "
            "ADD COLUMN assigned_manual INTEGER DEFAULT 0"
        )

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_findings_assigned "
        "ON scan_findings(assigned_user_id)"
    )

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_findings_match "
        "ON scan_findings(list_name, plugin_id)"
    )

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
    "details_synced", "imported_at", "last_synced_at",
    "plugin_id", "cve", "cvss", "last_scan"
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
        now_iso,
        finding.get("plugin_id"),
        finding.get("cve"),
        finding.get("cvss"),
        finding.get("last_scan")
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
        f"ON CONFLICT(task_id) DO UPDATE SET {updates} "
        # Constat modifié par un import de scan local : la version
        # VulnWatch fait foi, la migration ClickUp n'y touche plus.
        f"WHERE scan_findings.local_modified_at IS NULL"
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
        "SELECT task_id, date_updated, local_modified_at FROM scan_findings "
        "WHERE details_synced = 1 OR local_modified_at IS NOT NULL"
    ).fetchall()

    conn.close()

    # Constat modifié localement : valeur spéciale, la migration le
    # saute quoi que dise ClickUp (sa version locale fait foi).
    return {
        r["task_id"]: (
            LOCALLY_MODIFIED if r["local_modified_at"] else r["date_updated"]
        )
        for r in rows
    }


LOCALLY_MODIFIED = "__local__"


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
            f.plugin_id, f.cvss, f.last_scan, f.tags_json, f.source,
            f.assigned_user_id, u.utilisateur AS assigned_user,
            u.mail AS assigned_mail,
            (SELECT GROUP_CONCAT(c.cve_id, ', ')
               FROM scan_finding_cves c WHERE c.task_id = f.task_id) AS cves
        FROM scan_findings f
        LEFT JOIN scan_users u ON u.id = f.assigned_user_id
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
            " OR u.utilisateur LIKE ? OR u.mail LIKE ?"
            " OR f.description LIKE ? OR f.task_id IN ("
            "   SELECT task_id FROM scan_finding_cves WHERE cve_id LIKE ?))"
        )

        params.extend([like] * 7)

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
        "SELECT f.*, u.utilisateur AS assigned_user, u.mail AS assigned_mail "
        "FROM scan_findings f "
        "LEFT JOIN scan_users u ON u.id = f.assigned_user_id "
        "WHERE f.task_id = ?",
        (task_id,)
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


# =========================================================
# UTILISATEURS ET ASSIGNATION
# =========================================================

MAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _clickup_assignee_names(assignees_json):
    """Noms des assignés ClickUp d'un constat, dans l'ordre d'origine."""

    try:
        assignees = json.loads(assignees_json or "[]")
    except (ValueError, TypeError):
        return []

    names = []

    for assignee in assignees:

        name = (assignee.get("username") or "").strip()

        if name and name.lower() not in (n.lower() for n in names):
            names.append(name)

    return names


def seed_scan_users_from_findings():
    """
    Remplissage à partir des données migrées, rejouable sans risque :
      - ajoute chaque assigné ClickUp absent du référentiel (champ
        « utilisateur » seul, le mail est complété à la main) ;
      - assigne au premier assigné ClickUp les constats encore sans
        assignation et jamais modifiés à la main.
    Ne modifie ni les mails saisis, ni une assignation manuelle.
    Retourne (utilisateurs ajoutés, constats assignés).
    """

    ensure_scan_tables()

    conn = get_connection()

    rows = conn.execute(
        "SELECT task_id, assignees_json, assigned_user_id, assigned_manual "
        "FROM scan_findings"
    ).fetchall()

    def clickup_map():

        mapping = {}

        for r in conn.execute(
            "SELECT id, utilisateur, clickup_name FROM scan_users"
        ):

            mapping.setdefault(r["utilisateur"].lower(), r["id"])

            if r["clickup_name"]:
                # Le nom ClickUp d'origine prime sur un homonyme.
                mapping[r["clickup_name"].lower()] = r["id"]

        return mapping

    ids = clickup_map()
    added = 0

    for row in rows:

        for name in _clickup_assignee_names(row["assignees_json"]):

            if name.lower() in ids:
                continue

            conn.execute(
                "INSERT INTO scan_users (utilisateur, clickup_name) "
                "VALUES (?, ?)",
                (name, name)
            )

            ids = clickup_map()
            added += 1

    assigned = 0

    for row in rows:

        if row["assigned_user_id"] is not None or row["assigned_manual"]:
            continue

        names = _clickup_assignee_names(row["assignees_json"])

        if not names:
            continue

        conn.execute(
            "UPDATE scan_findings SET assigned_user_id = ? WHERE task_id = ?",
            (ids[names[0].lower()], row["task_id"])
        )

        assigned += 1

    conn.commit()
    conn.close()

    return added, assigned


def get_scan_users():

    ensure_scan_tables()

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT u.id, u.utilisateur, u.mail,
               (SELECT COUNT(*) FROM scan_findings f
                 WHERE f.assigned_user_id = u.id) AS constats
        FROM scan_users u
        ORDER BY u.utilisateur COLLATE NOCASE
        """
    ).fetchall()

    conn.close()

    return [dict(r) for r in rows]


def save_scan_users(rows):
    """
    Remplace le référentiel par `rows` (liste de dicts id / utilisateur /
    mail, id None pour un nouvel utilisateur), en une transaction.
    Un utilisateur retiré de la liste est supprimé et ses constats
    deviennent non assignés. Lève ValueError si la saisie est invalide
    (rien n'est alors écrit).
    """

    ensure_scan_tables()

    cleaned = []
    seen = set()

    for row in rows:

        name = (row.get("utilisateur") or "").strip()
        mail = (row.get("mail") or "").strip() or None

        if not name and not mail:
            # Ligne vide ajoutée puis abandonnée dans l'éditeur.
            continue

        if not name:
            raise ValueError(f"Utilisateur manquant pour le mail {mail}.")

        if name.lower() in seen:
            raise ValueError(f"Utilisateur en double : {name}.")

        if mail and not MAIL_PATTERN.match(mail):
            raise ValueError(f"Adresse mail invalide pour {name} : {mail}.")

        seen.add(name.lower())

        user_id = row.get("id")
        user_id = int(user_id) if user_id not in (None, "") else None

        cleaned.append((user_id, name, mail))

    conn = get_connection()

    kept = {user_id for user_id, _, _ in cleaned if user_id is not None}

    existing = {
        r["id"] for r in conn.execute("SELECT id FROM scan_users")
    }

    removed = existing - kept

    for user_id in removed:

        conn.execute(
            "UPDATE scan_findings SET assigned_user_id = NULL, "
            "assigned_manual = 1 WHERE assigned_user_id = ?",
            (user_id,)
        )

        conn.execute("DELETE FROM scan_users WHERE id = ?", (user_id,))

    # Renommages d'abord sous un nom temporaire : permet d'échanger deux
    # noms sans heurter la contrainte UNIQUE.
    for user_id, name, mail in cleaned:

        if user_id is not None:
            conn.execute(
                "UPDATE scan_users SET utilisateur = ? WHERE id = ?",
                (f"__tmp_{user_id}", user_id)
            )

    for user_id, name, mail in cleaned:

        if user_id is None:
            conn.execute(
                "INSERT INTO scan_users (utilisateur, mail) VALUES (?, ?)",
                (name, mail)
            )
        else:
            conn.execute(
                "UPDATE scan_users SET utilisateur = ?, mail = ? WHERE id = ?",
                (name, mail, user_id)
            )

    conn.commit()
    conn.close()

    return len(removed)


def set_scan_assignments(assignments):
    """
    `assignments` : {task_id: user_id ou None}. Enregistré en une
    transaction ; marque l'assignation comme manuelle.
    """

    if not assignments:
        return 0

    ensure_scan_tables()

    conn = get_connection()

    for task_id, user_id in assignments.items():

        conn.execute(
            "UPDATE scan_findings SET assigned_user_id = ?, "
            "assigned_manual = 1 WHERE task_id = ?",
            (user_id, task_id)
        )

    conn.commit()
    conn.close()

    return len(assignments)


# =========================================================
# IMPORT DE SCAN NESSUS (voir scan_import.py)
# =========================================================

def _normalize_status(status):

    from scan_import import normalize_status

    return normalize_status(status)


def get_list_info(list_name):
    """list_id / folder_name d'une liste déjà connue (None sinon)."""

    ensure_scan_tables()

    conn = get_connection()

    row = conn.execute(
        "SELECT list_id, folder_name, space_id FROM scan_findings "
        "WHERE list_name = ? AND list_id IS NOT NULL LIMIT 1",
        (list_name,)
    ).fetchone()

    conn.close()

    return dict(row) if row else {
        "list_id": None, "folder_name": None, "space_id": None
    }


def get_import_candidates(list_name):
    """Constats de la liste, fermés compris (clé de rapprochement)."""

    ensure_scan_tables()

    conn = get_connection()

    rows = conn.execute(
        "SELECT task_id, title, plugin_id, port, cve, status "
        "FROM scan_findings WHERE list_name = ?",
        (list_name,)
    ).fetchall()

    conn.close()

    return [dict(r) for r in rows]


def get_status_catalog(list_name=None):
    """
    Statuts connus (orthographe stockée, type ClickUp, ordre) :
    {statut normalisé: {"status", "status_type", "orderindex"}}.
    Ceux de la liste choisie priment sur ceux des autres listes.
    """

    ensure_scan_tables()

    conn = get_connection()

    rows = conn.execute(
        "SELECT status, status_type, raw_json, "
        "       COALESCE(list_name = ?, 0) AS same_list "
        "FROM scan_findings WHERE status IS NOT NULL "
        "GROUP BY status, status_type, same_list",
        (list_name,)
    ).fetchall()

    conn.close()

    catalog = {}

    for row in sorted(rows, key=lambda r: r["same_list"]):

        try:
            orderindex = (
                json.loads(row["raw_json"] or "{}").get("status") or {}
            ).get("orderindex")
        except (ValueError, TypeError, AttributeError):
            orderindex = None

        catalog[_normalize_status(row["status"])] = {
            "status": row["status"],
            "status_type": row["status_type"] or "open",
            "orderindex": orderindex
        }

    return catalog


def default_new_status(catalog):
    """
    Statut d'un nouveau constat : dans ClickUp, le premier statut
    (ouvert) de la liste. À défaut, RÉDUIRE.
    """

    opened = [
        v for v in catalog.values()
        if v["status_type"] == "open" and v["orderindex"] is not None
    ]

    if opened:
        return min(opened, key=lambda v: int(v["orderindex"]))["status"]

    return (catalog.get("reduire") or {}).get("status") or "reduire"


def apply_scan_import(plan, list_name, scan_date, now, author,
                      new_status):
    """
    Écrit le plan de scan_import.build_import_plan() en UNE transaction.
    `scan_date` : date du scan (date), `now` : date d'import (datetime
    avec fuseau), `author` : utilisateur VulnWatch (auteur du
    commentaire), `new_status` : statut des nouveaux constats.
    Retourne les compteurs effectivement appliqués.
    """

    ensure_scan_tables()

    catalog = get_status_catalog(list_name)
    info = get_list_info(list_name)

    def status_of(normalized, fallback):

        entry = catalog.get(normalized)

        return (
            (entry["status"], entry["status_type"]) if entry
            else (fallback, "open")
        )

    reduire, reduire_type = status_of("reduire", "reduire")
    new_status_type = (
        catalog.get(_normalize_status(new_status)) or {}
    ).get("status_type", "open")

    now_iso = now.isoformat()
    scan_iso = scan_date.isoformat()

    # Même texte que le script : « Date d'import: <date et heure> ».
    comment_text = f"Date d'import: {now.strftime('%d/%m/%Y %H:%M:%S')}"

    applied = {}

    conn = get_connection()

    def add_comment(task_id):

        conn.execute(
            "INSERT INTO scan_finding_comments (comment_id, task_id, "
            "author_name, text, date) VALUES (?, ?, ?, ?, ?)",
            (f"VW-{uuid.uuid4().hex}", task_id, author, comment_text, now_iso)
        )

    for item in plan["actions"]:

        action = item["action"]
        row = item["row"]
        task_id = item["task_id"]

        if action in ("unchanged", "duplicate", "info"):
            continue

        if action == "new":

            task_id = f"VW-{uuid.uuid4().hex[:16]}"

            custom_fields = {
                "Plugin ID": row["plugin_id"], "Risk": row["risk"],
                "CVE": row["cve"], "CVSS": row["cvss"], "Port": row["port"],
                "Last Scan": scan_iso, "HOST": row["host"]
            }

            conn.execute(
                """
                INSERT INTO scan_findings (
                    task_id, source, space_id, list_id, list_name,
                    folder_name, title, description, status, status_type,
                    treated, risk, host, port, plugin_id, cve, cvss,
                    last_scan, assignee_names, assignees_json, tags_json,
                    creator, custom_fields_json, checklists_json, raw_json,
                    date_created, date_updated, due_date, details_synced,
                    imported_at, last_synced_at, local_modified_at
                )
                VALUES (?, 'Nessus CSV', ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?,
                        ?, ?, ?, ?, ?, '', '[]', ?, ?, ?, '[]', NULL, ?, ?,
                        ?, 0, ?, ?, ?)
                """,
                (
                    task_id, info["space_id"], info["list_id"], list_name,
                    info["folder_name"], row["srv"], row["description"],
                    new_status, new_status_type, row["risk"], row["host"],
                    row["port"], row["plugin_id"], row["cve"], row["cvss"],
                    scan_iso,
                    json.dumps([row["name"]] if row["name"] else [],
                               ensure_ascii=False),
                    author,
                    json.dumps(custom_fields, ensure_ascii=False),
                    now_iso, now_iso, row["due_date"], now_iso, now_iso,
                    now_iso
                )
            )

            if row["cve"]:
                conn.execute(
                    "INSERT OR IGNORE INTO scan_finding_cves (task_id, cve_id) "
                    "VALUES (?, ?)",
                    (task_id, row["cve"])
                )

        elif action == "reopen":

            conn.execute(
                "UPDATE scan_findings SET status = ?, status_type = ?, "
                "treated = 0, date_closed = NULL, date_done = NULL, "
                "due_date = ?, last_scan = ?, date_updated = ?, "
                "local_modified_at = ? WHERE task_id = ?",
                (reduire, reduire_type, row["due_date"], scan_iso, now_iso,
                 now_iso, task_id)
            )

        elif action == "refresh":

            conn.execute(
                "UPDATE scan_findings SET due_date = ?, last_scan = ?, "
                "date_updated = ?, local_modified_at = ? WHERE task_id = ?",
                (row["due_date"], scan_iso, now_iso, now_iso, task_id)
            )

        elif action == "accepted":

            conn.execute(
                "UPDATE scan_findings SET due_date = NULL, last_scan = ?, "
                "date_updated = ?, local_modified_at = ? WHERE task_id = ?",
                (scan_iso, now_iso, now_iso, task_id)
            )

        add_comment(task_id)

        applied[action] = applied.get(action, 0) + 1

    conn.commit()
    conn.close()

    return applied


# =========================================================
# CORRESPONDANCES MACHINE -> HÔTE (import de scan)
# =========================================================

def get_host_map_rows():

    ensure_scan_tables()

    conn = get_connection()

    rows = conn.execute(
        "SELECT id, machine, hote FROM scan_host_map "
        "ORDER BY hote COLLATE NOCASE, machine COLLATE NOCASE"
    ).fetchall()

    conn.close()

    return [dict(r) for r in rows]


def get_host_map():
    """{machine en minuscules: hôte}, pour scan_import.resolve_hostname."""

    return {r["machine"].lower(): r["hote"] for r in get_host_map_rows()}


def save_host_map(rows):
    """
    Remplace les correspondances par `rows` (dicts id / machine / hote,
    id None pour une nouvelle ligne), en une transaction. Lève
    ValueError si la saisie est invalide (rien n'est alors écrit).
    """

    ensure_scan_tables()

    cleaned = []
    seen = set()

    for row in rows:

        machine = (row.get("machine") or "").strip()
        hote = (row.get("hote") or "").strip()

        if not machine and not hote:
            continue

        if not machine or not hote:
            raise ValueError(
                f"Machine et hôte obligatoires : « {machine or hote} »."
            )

        if machine.lower() in seen:
            raise ValueError(f"Machine en double : {machine}.")

        seen.add(machine.lower())

        row_id = row.get("id")
        row_id = int(row_id) if row_id not in (None, "") else None

        cleaned.append((row_id, machine, hote))

    conn = get_connection()

    kept = {row_id for row_id, _, _ in cleaned if row_id is not None}

    removed = [
        r["id"] for r in conn.execute("SELECT id FROM scan_host_map")
        if r["id"] not in kept
    ]

    for row_id in removed:
        conn.execute("DELETE FROM scan_host_map WHERE id = ?", (row_id,))

    # Nom temporaire d'abord : permet d'échanger deux machines sans
    # heurter la contrainte UNIQUE.
    for row_id, machine, hote in cleaned:

        if row_id is not None:
            conn.execute(
                "UPDATE scan_host_map SET machine = ? WHERE id = ?",
                (f"__tmp_{row_id}", row_id)
            )

    for row_id, machine, hote in cleaned:

        if row_id is None:
            conn.execute(
                "INSERT INTO scan_host_map (machine, hote) VALUES (?, ?)",
                (machine, hote)
            )
        else:
            conn.execute(
                "UPDATE scan_host_map SET machine = ?, hote = ? WHERE id = ?",
                (machine, hote, row_id)
            )

    conn.commit()
    conn.close()

    return len(removed)


def import_host_map(pairs, overwrite=False):
    """
    Ajoute les paires (machine, hôte) du fichier de correspondance.
    overwrite=False : une machine déjà en base garde son hôte (les
    corrections faites dans l'interface sont préservées).
    Retourne {"added", "updated", "kept"}.
    """

    ensure_scan_tables()

    conn = get_connection()

    existing = {
        r["machine"].lower(): r["hote"]
        for r in conn.execute("SELECT machine, hote FROM scan_host_map")
    }

    stats = {"added": 0, "updated": 0, "kept": 0}

    for machine, hote in pairs:

        current = existing.get(machine.lower())

        if current is None:

            conn.execute(
                "INSERT INTO scan_host_map (machine, hote) VALUES (?, ?)",
                (machine, hote)
            )
            existing[machine.lower()] = hote
            stats["added"] += 1

        elif current != hote and overwrite:

            conn.execute(
                "UPDATE scan_host_map SET hote = ? WHERE machine = ?",
                (hote, machine)
            )
            existing[machine.lower()] = hote
            stats["updated"] += 1

        else:

            stats["kept"] += 1

    conn.commit()
    conn.close()

    return stats
