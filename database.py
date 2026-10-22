import sqlite3
import re
import json
import os
import hmac
import hashlib
import secrets
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta


# =========================================================
# CONFIGURATION
# =========================================================

DB_PATH = Path("data/vulnwatch.db")


# =========================================================
# CONNECTION
# =========================================================

def get_connection():
    """
    Open a SQLite connection to the VulnWatch database.
    Creates the data directory automatically.

    Deux réglages pour éviter les "database is locked" :
      - journal_mode=WAL : les lectures ne bloquent plus l'écrivain (et
        inversement), ce qui compte ici car Streamlit relance TOUT le
        script à chaque interaction — donc potentiellement beaucoup de
        connexions ouvertes en parallèle (plusieurs onglets/sessions,
        + les scripts de synchro lancés en arrière-plan).
      - busy_timeout : si deux écritures tombent quand même en même
        temps, SQLite retente pendant ce délai au lieu d'échouer tout
        de suite (le timeout par défaut de sqlite3.connect() est de
        5s, souvent trop court sous Windows).
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    conn = sqlite3.connect(
        DB_PATH,
        timeout=30
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")

    return conn


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

# Streamlit ré-exécute TOUT le script app.py à chaque interaction
# (clic, saisie, auto-refresh...), et app.py appelle
# initialize_database() en haut du fichier — donc à chaque rerun,
# pour CHAQUE session/onglet ouvert. Sans ce garde-fou, c'est une
# salve de CREATE TABLE / ALTER TABLE / UPDATE en écriture à chaque
# clic, sur TOUTES les sessions ouvertes en parallèle : la cause la
# plus probable du "database is locked" observé. Le schéma ne change
# pas en cours de route, donc une seule exécution réelle par process
# (le process Streamlit garde ce module Python en mémoire entre les
# reruns) suffit ; les appels suivants ne font rien.
_DB_INITIALIZED = False


def initialize_database():

    global _DB_INITIALIZED

    if _DB_INITIALIZED:
        return

    conn = get_connection()

    # =====================================================
    # VULNERABILITIES TABLE
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (

            cve_id TEXT PRIMARY KEY,

            vendor TEXT,
            product TEXT,

            vulnerability_name TEXT,
            description TEXT,

            date_added TEXT,
            due_date TEXT,

            known_ransomware TEXT,

            source TEXT,

            risk_score INTEGER,
            priority TEXT,

            -- NVD CVSS 3.x
            cvss_v3_score REAL,
            cvss_v3_severity TEXT,
            cvss_v3_vector TEXT,

            -- NVD CVSS 4.x
            cvss_v4_score REAL,
            cvss_v4_severity TEXT,
            cvss_v4_vector TEXT,

            -- NVD metadata
            cwe TEXT,
            nvd_description TEXT,
            nvd_published TEXT,
            nvd_last_modified TEXT,

            -- NVD enrichment state
            nvd_enriched INTEGER DEFAULT 0,
            nvd_enriched_at TEXT,

            nvd_status TEXT DEFAULT 'PENDING',
            nvd_attempts INTEGER DEFAULT 0,
            nvd_last_error TEXT

        )
    """)


    # =====================================================
    # DEFENDER VULNERABILITIES TABLE
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS defender_vulnerabilities (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id TEXT,
            device_name TEXT,

            os_platform TEXT,
            os_version TEXT,

            software_vendor TEXT,
            software_name TEXT,
            software_version TEXT,

            cve_id TEXT,

            defender_severity TEXT,

            cvss_score REAL,

            recommended_security_update TEXT,
            recommended_security_update_id TEXT,

            exploitability_level TEXT,

            security_update_available INTEGER,

            first_seen_timestamp TEXT,
            last_seen_timestamp TEXT,

            imported_at TEXT,

            UNIQUE (
                device_id,
                software_vendor,
                software_name,
                software_version,
                cve_id
            )

        )
    """)


    # =====================================================
    # APP CONFIG TABLE (admin credentials, app settings)
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_config (

            key TEXT PRIMARY KEY,
            value TEXT

        )
    """)


    # =====================================================
    # SYNC STATE TABLE (last run tracking per sync job)
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_state (

            sync_key TEXT PRIMARY KEY,

            last_run_at TEXT,
            status TEXT,
            detail TEXT

        )
    """)


    # =====================================================
    # MANUAL SERVER OWNERS TABLE (CSV import)
    # =====================================================
    #
    # Séparée de la table `asset_owners` remplie automatiquement
    # par sync_asset_owners.py (Microsoft Graph). Celle-ci est
    # alimentée uniquement par import CSV manuel, pour l'onglet
    # "Windows Server Inventory".

    conn.execute("""
        CREATE TABLE IF NOT EXISTS manual_server_owners (

            device_name TEXT PRIMARY KEY COLLATE NOCASE,

            owner TEXT,
            notification INTEGER DEFAULT 0,

            imported_at TEXT

        )
    """)


    # =====================================================
    # HEXIOSEC ASM FINDINGS TABLE (attack surface management)
    # =====================================================
    #
    # Risques importés depuis l'API publique de Hexiosec ASM
    # (asm.hexiosec.com), scope "Attack Surface" — séparé de CISA
    # KEV / Defender car ce ne sont pas forcément des CVE (certains
    # risques ASM n'ont pas d'identifiant CVE).

    conn.execute("""
        CREATE TABLE IF NOT EXISTS hexiosec_findings (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            external_id TEXT UNIQUE,

            asset TEXT,
            category TEXT,
            title TEXT,
            severity TEXT,
            cve_id TEXT,
            description TEXT,
            status TEXT,

            first_seen TEXT,
            last_seen TEXT,

            imported_at TEXT

        )
    """)


    # =====================================================
    # HEXIOSEC ASM ASSETS TABLE (domaines, IP, services, composants)
    # =====================================================
    #
    # Complète hexiosec_findings (les risques) avec l'inventaire des
    # actifs découverts par Hexiosec ASM, pour un onglet "Attack
    # Surface" filtrable par type/nom, pas seulement par risque.

    conn.execute("""
        CREATE TABLE IF NOT EXISTS hexiosec_assets (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            asset_type TEXT,
            external_id TEXT,

            name TEXT,
            detail TEXT,

            risk_critical INTEGER DEFAULT 0,
            risk_high INTEGER DEFAULT 0,
            risk_medium INTEGER DEFAULT 0,
            risk_low INTEGER DEFAULT 0,
            risk_info INTEGER DEFAULT 0,

            created TEXT,
            last_seen TEXT,

            imported_at TEXT,

            UNIQUE (asset_type, external_id)

        )
    """)


    # =====================================================
    # DEVICE NOTIFICATIONS TABLE (alerte propriétaire, groupée par serveur)
    # =====================================================
    #
    # Nouvelle "philosophie" d'envoi (remplace l'ancienne table
    # email_notifications, un e-mail par couple CVE/serveur) : UNE
    # ligne par SERVEUR, un e-mail regroupant TOUTES les CVE CISA KEV
    # actuellement présentes sur ce serveur. Le déclenchement du
    # premier e-mail n'a lieu que si au moins une de ces CVE atteint
    # le seuil de criticité configuré (voir get_notification_min_priority) ;
    # les CVE sous le seuil sont alors simplement embarquées dans le
    # même e-mail plutôt que de déclencher un envoi séparé ou d'être
    # ignorées. Le détail des CVE couvertes par la notification vit
    # dans device_notification_cves ci-dessous. Après l'envoi initial,
    # notify.py revient vérifier périodiquement (next_check_at) si
    # chaque CVE du groupe est toujours présente : les CVE résolues
    # sont retirées du groupe (marquées resolved=1), une relance est
    # envoyée pour celles qui restent, et la notification passe à
    # RESOLVED quand il n'en reste plus aucune.

    conn.execute("""
        CREATE TABLE IF NOT EXISTS device_notifications (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_name TEXT,
            device_id TEXT,

            owner_email TEXT,

            status TEXT DEFAULT 'SENT',
            -- SENT | REMINDER_SENT | RESOLVED | ERROR

            email_subject TEXT,
            email_body TEXT,

            sent_at TEXT,
            reminder_count INTEGER DEFAULT 0,
            last_reminder_at TEXT,
            next_check_at TEXT,
            resolved_at TEXT,
            last_error TEXT,

            UNIQUE (device_name)

        )
    """)


    # =====================================================
    # DEVICE NOTIFICATION CVEs TABLE (détail du regroupement par serveur)
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS device_notification_cves (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            notification_id INTEGER,

            cve_id TEXT,
            priority TEXT,

            resolved INTEGER DEFAULT 0,
            resolved_at TEXT,

            UNIQUE (notification_id, cve_id)

        )
    """)


    # =====================================================
    # WATCH RECIPIENTS TABLE (liste de diffusion "veille")
    # =====================================================
    #
    # Distincte de manual_server_owners : ici pas de notion de
    # propriétaire de serveur, juste une liste d'adresses (équipe
    # SOC, managers...) à alerter manuellement sur une détection
    # récente (CISA KEV ou pas), via l'onglet "Veille".

    conn.execute("""
        CREATE TABLE IF NOT EXISTS watch_recipients (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            email TEXT UNIQUE COLLATE NOCASE,
            label TEXT,
            active INTEGER DEFAULT 1,

            added_at TEXT

        )
    """)


    # =====================================================
    # WATCH ALERTS TABLE (historique des alertes de veille envoyées)
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS watch_alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            cve_id TEXT,
            recipients TEXT,

            subject TEXT,
            body TEXT,

            affected_device_count INTEGER,

            sent_at TEXT

        )
    """)


    # =====================================================
    # MIGRATION
    # =====================================================

    columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(vulnerabilities)"
        )
    }


    new_columns = {

        "cvss_v3_score": "REAL",
        "cvss_v3_severity": "TEXT",
        "cvss_v3_vector": "TEXT",

        "cvss_v4_score": "REAL",
        "cvss_v4_severity": "TEXT",
        "cvss_v4_vector": "TEXT",

        "cwe": "TEXT",
        "nvd_description": "TEXT",
        "nvd_published": "TEXT",
        "nvd_last_modified": "TEXT",

        "nvd_enriched": "INTEGER DEFAULT 0",
        "nvd_enriched_at": "TEXT",

        "nvd_status": "TEXT DEFAULT 'PENDING'",
        "nvd_attempts": "INTEGER DEFAULT 0",
        "nvd_last_error": "TEXT",

        # AI enrichment (local LLM via Ollama)
        "ai_summary": "TEXT",
        "ai_impact": "TEXT",
        "ai_recommendation": "TEXT",
        "ai_confidence": "TEXT",
        "ai_model": "TEXT",
        "ai_generated_at": "TEXT",

        "ai_status": "TEXT DEFAULT 'PENDING'",
        "ai_attempts": "INTEGER DEFAULT 0",
        "ai_last_error": "TEXT",

        # Date à laquelle les produits vulnérables NVD (CPE) de la CVE ont
        # été récupérés (même si NVD n'en déclare aucun). NULL : CVE
        # importée avant cette fonctionnalité, produits à compléter.
        "cpe_checked_at": "TEXT"

    }


    cpe_column_added = "cpe_checked_at" not in columns

    for column, datatype in new_columns.items():

        if column not in columns:

            conn.execute(
                f"""
                ALTER TABLE vulnerabilities
                ADD COLUMN {column} {datatype}
                """
            )


    # =====================================================
    # RESTORE NVD STATUS FOR EXISTING RECORDS
    # =====================================================

    conn.execute("""
        UPDATE vulnerabilities

        SET nvd_status = 'OK'

        WHERE nvd_enriched = 1

          AND (
              nvd_status IS NULL
              OR nvd_status = 'PENDING'
          )
    """)


    # =====================================================
    # INVENTAIRE LOGICIEL x NVD (équipements touchés selon NVD)
    # =====================================================
    #
    # nvd_cpe_matches     : produits/versions vulnérables déclarés par
    #                       NVD pour chaque CVE (configurations CPE) ;
    # software_inventory  : logiciels installés sur chaque machine
    #                       (export Defender SoftwareInventoryExport
    #                       ou fichier CSV) ;
    # inventory_cve_matches : (produit, version installée) -> CVE, calculé
    #                       par services/inventory_matcher.py ;
    # inventory_cve_summary : nombre de machines touchées par CVE.

    conn.execute("""
        CREATE TABLE IF NOT EXISTS nvd_cpe_matches (
            cve_id TEXT NOT NULL,
            part TEXT,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT,
            version_start_including TEXT,
            version_start_excluding TEXT,
            version_end_including TEXT,
            version_end_excluding TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS software_inventory (
            device_id TEXT NOT NULL,
            device_name TEXT,
            os_platform TEXT,
            os_version TEXT,
            os_architecture TEXT,
            software_vendor TEXT,
            software_name TEXT,
            software_version TEXT,
            cpe_vendor TEXT,
            cpe_product TEXT,
            end_of_support_status TEXT,
            end_of_support_date TEXT,
            imported_at TEXT
        )
    """)

    # Paquets de distributions Linux (services/inventory_matcher.py) :
    # distro_package = 1 quand un paquet (ex. php8.4-common de Debian) a
    # été relié à son produit NVD ; match_version = version amont
    # comparée aux plages NVD.
    inventory_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(software_inventory)")
    }

    if "distro_package" not in inventory_columns:
        conn.execute(
            "ALTER TABLE software_inventory "
            "ADD COLUMN distro_package INTEGER NOT NULL DEFAULT 0"
        )

    if "match_version" not in inventory_columns:
        conn.execute("ALTER TABLE software_inventory ADD COLUMN match_version TEXT")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory_cve_matches (
            cve_id TEXT NOT NULL,
            cpe_vendor TEXT NOT NULL,
            cpe_product TEXT NOT NULL,
            software_version TEXT NOT NULL,
            rule TEXT,
            PRIMARY KEY (cve_id, cpe_vendor, cpe_product, software_version)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory_cve_summary (
            cve_id TEXT PRIMARY KEY,
            affected_devices INTEGER,
            affected_products INTEGER
        )
    """)

    if cpe_column_added:

        # Migration : les CVE dont les produits ont déjà été enregistrés
        # (synchros depuis l'ajout des produits NVD) sont complètes.
        conn.execute("""
            UPDATE vulnerabilities
            SET cpe_checked_at = ?
            WHERE cve_id IN (SELECT DISTINCT cve_id FROM nvd_cpe_matches)
        """, (datetime.now(timezone.utc).isoformat(),))


    # =====================================================
    # UTILISATEURS (admin / lecteur)
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            must_change_password INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT,
            created_by TEXT,
            last_login_at TEXT
        )
    """)


    # =====================================================
    # AUTH SESSIONS (connexion conservée après rafraîchissement)
    # =====================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)


    # =====================================================
    # INDEX
    # =====================================================
    #
    # defender_vulnerabilities dépasse facilement les 2 millions de
    # lignes (une ligne par machine x logiciel x CVE) et la table
    # vulnerabilities plusieurs centaines de milliers après le
    # téléchargement historique NVD. Sans index sur cve_id, chaque
    # jointure / recherche par CVE parcourt toute la table.
    # La création est longue UNE fois (quelques dizaines de secondes
    # sur une grosse base), ensuite IF NOT EXISTS ne coûte rien.

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_defender_vuln_cve
        ON defender_vulnerabilities (cve_id, device_id)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source
        ON vulnerabilities (source)
    """)

    for index_sql in (
        "CREATE INDEX IF NOT EXISTS idx_nvd_cpe_matches_cve "
        "ON nvd_cpe_matches (cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_nvd_cpe_matches_product "
        "ON nvd_cpe_matches (vendor, product)",
        "CREATE INDEX IF NOT EXISTS idx_software_inventory_product "
        "ON software_inventory (cpe_vendor, cpe_product, software_version)",
        "CREATE INDEX IF NOT EXISTS idx_software_inventory_device "
        "ON software_inventory (device_id)",
        "CREATE INDEX IF NOT EXISTS idx_inventory_cve_matches_product "
        "ON inventory_cve_matches (cpe_vendor, cpe_product, software_version)"
    ):
        conn.execute(index_sql)

    # Comptage par jour de publication (état de la base NVD, voir
    # count_cves_by_published_day / nvd_audit.py).
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_nvd_published
        ON vulnerabilities (nvd_published)
    """)


    conn.commit()
    conn.close()

    _DB_INITIALIZED = True


# =========================================================
# CISA VULNERABILITY
# =========================================================

def save_vulnerability(
    vulnerability
):
    """
    Insère ou met à jour une CVE issue du flux CISA KEV.

    IMPORTANT : ne touche QUE les colonnes issues de CISA
    (vendor, product, dates, risk_score, priority, ...). Les
    colonnes d'enrichissement NVD (cvss_v3_*, nvd_*) et IA
    (ai_*) ne sont JAMAIS écrasées ici — elles sont gérées
    exclusivement par update_nvd_enrichment() / update_ai_enrichment().

    Avant, cette fonction faisait un INSERT OR REPLACE sur toute
    la ligne : comme le flux CISA ne contient ni les champs NVD ni
    les champs IA, chaque synchronisation CISA (y compris la
    synchronisation automatique toutes les 12h) effaçait tout
    l'enrichissement NVD/IA déjà calculé pour les CVE déjà connues.
    """

    conn = get_connection()

    conn.execute("""
        INSERT INTO vulnerabilities (

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
            priority

        )

        VALUES (

            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?

        )

        ON CONFLICT(cve_id) DO UPDATE SET

            vendor = excluded.vendor,
            product = excluded.product,

            vulnerability_name = excluded.vulnerability_name,
            description = excluded.description,

            date_added = excluded.date_added,
            due_date = excluded.due_date,

            known_ransomware = excluded.known_ransomware,

            source = excluded.source,

            risk_score = excluded.risk_score,
            priority = excluded.priority
    """, (

        vulnerability.get(
            "cveID"
        ),

        vulnerability.get(
            "vendorProject"
        ),

        vulnerability.get(
            "product"
        ),

        vulnerability.get(
            "vulnerabilityName"
        ),

        vulnerability.get(
            "shortDescription"
        ),

        vulnerability.get(
            "dateAdded"
        ),

        vulnerability.get(
            "dueDate"
        ),

        vulnerability.get(
            "knownRansomwareCampaignUse"
        ),

        "CISA KEV",

        vulnerability.get(
            "risk_score",
            0
        ),

        vulnerability.get(
            "priority",
            "UNKNOWN"
        )

    ))

    conn.commit()
    conn.close()


# =========================================================
# NVD STATUS
# =========================================================

def update_nvd_status(
    cve_id,
    status,
    attempts=None,
    error=None
):

    conn = get_connection()


    if attempts is None:

        conn.execute("""
            UPDATE vulnerabilities

            SET
                nvd_status = ?,
                nvd_last_error = ?

            WHERE cve_id = ?
        """, (
            status,
            error,
            cve_id
        ))

    else:

        conn.execute("""
            UPDATE vulnerabilities

            SET
                nvd_status = ?,
                nvd_attempts = ?,
                nvd_last_error = ?

            WHERE cve_id = ?
        """, (
            status,
            attempts,
            error,
            cve_id
        ))


    conn.commit()
    conn.close()


# =========================================================
# NVD ENRICHMENT
# =========================================================

def update_nvd_enrichment(
    cve_id,
    enrichment
):

    conn = get_connection()

    conn.execute("""
        UPDATE vulnerabilities

        SET

            cvss_v3_score = ?,
            cvss_v3_severity = ?,
            cvss_v3_vector = ?,

            cvss_v4_score = ?,
            cvss_v4_severity = ?,
            cvss_v4_vector = ?,

            cwe = ?,

            nvd_description = ?,

            nvd_published = ?,
            nvd_last_modified = ?,

            nvd_enriched = 1,
            nvd_enriched_at = ?,

            nvd_status = 'OK',
            nvd_last_error = NULL

        WHERE cve_id = ?
    """, (

        enrichment.get(
            "cvss_v3_score"
        ),

        enrichment.get(
            "cvss_v3_severity"
        ),

        enrichment.get(
            "cvss_v3_vector"
        ),

        enrichment.get(
            "cvss_v4_score"
        ),

        enrichment.get(
            "cvss_v4_severity"
        ),

        enrichment.get(
            "cvss_v4_vector"
        ),

        enrichment.get(
            "cwe"
        ),

        enrichment.get(
            "nvd_description"
        ),

        enrichment.get(
            "nvd_published"
        ),

        enrichment.get(
            "nvd_last_modified"
        ),

        enrichment.get(
            "nvd_enriched_at"
        ),

        cve_id

    ))

    # Produits vulnérables NVD (configurations CPE), comme pour les CVE
    # enregistrées par les synchros NVD.
    if "cpe_matches" in enrichment:
        _replace_cpe_matches(conn, cve_id, enrichment["cpe_matches"])

    conn.commit()
    conn.close()


# =========================================================
# AI STATUS (local LLM enrichment)
# =========================================================

def update_ai_status(
    cve_id,
    status,
    attempts=None,
    error=None
):

    conn = get_connection()


    if attempts is None:

        conn.execute("""
            UPDATE vulnerabilities

            SET
                ai_status = ?,
                ai_last_error = ?

            WHERE cve_id = ?
        """, (
            status,
            error,
            cve_id
        ))

    else:

        conn.execute("""
            UPDATE vulnerabilities

            SET
                ai_status = ?,
                ai_attempts = ?,
                ai_last_error = ?

            WHERE cve_id = ?
        """, (
            status,
            attempts,
            error,
            cve_id
        ))


    conn.commit()
    conn.close()


# =========================================================
# AI ENRICHMENT (local LLM enrichment)
# =========================================================

def update_ai_enrichment(
    cve_id,
    enrichment
):

    conn = get_connection()

    conn.execute("""
        UPDATE vulnerabilities

        SET

            ai_summary = ?,
            ai_impact = ?,
            ai_recommendation = ?,
            ai_confidence = ?,

            ai_model = ?,
            ai_generated_at = ?,

            ai_status = 'OK',
            ai_last_error = NULL

        WHERE cve_id = ?
    """, (

        enrichment.get(
            "ai_summary"
        ),

        enrichment.get(
            "ai_impact"
        ),

        enrichment.get(
            "ai_recommendation"
        ),

        enrichment.get(
            "ai_confidence"
        ),

        enrichment.get(
            "ai_model"
        ),

        enrichment.get(
            "ai_generated_at"
        ),

        cve_id

    ))

    conn.commit()
    conn.close()


# =========================================================
# INTERNAL EXPOSURE CONTEXT (for the AI prompt)
# =========================================================

def get_exposure_context(
    cve_id
):
    """
    Summarize what VulnWatch knows internally about a CVE's exposure
    (from Microsoft Defender), so the local LLM can reason about real
    impact rather than the CVE description alone.
    """

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            COUNT(DISTINCT device_id) AS affected_devices,
            COUNT(DISTINCT software_name) AS affected_products,
            GROUP_CONCAT(DISTINCT os_platform) AS os_platforms,
            GROUP_CONCAT(DISTINCT defender_severity) AS defender_severities,
            GROUP_CONCAT(DISTINCT exploitability_level) AS exploitability_levels,
            SUM(security_update_available) AS devices_with_update_available,
            GROUP_CONCAT(DISTINCT recommended_security_update) AS recommended_updates
        FROM defender_vulnerabilities
        WHERE cve_id = ?
        """,
        (cve_id,)
    ).fetchone()

    sample_devices = conn.execute(
        """
        SELECT DISTINCT device_name
        FROM defender_vulnerabilities
        WHERE cve_id = ?
        LIMIT 10
        """,
        (cve_id,)
    ).fetchall()

    conn.close()

    if row is None or (row["affected_devices"] or 0) == 0:

        return {
            "affected_devices": 0,
            "affected_products": 0,
            "os_platforms": [],
            "defender_severities": [],
            "exploitability_levels": [],
            "devices_with_update_available": 0,
            "sample_device_names": [],
            "recommended_updates": [],
            "patch_feasibility": None
        }

    def _split(value):
        if not value:
            return []
        return sorted({item for item in value.split(",") if item})

    affected_devices = row["affected_devices"] or 0
    devices_with_update = row["devices_with_update_available"] or 0

    # "Fusible" = un correctif éditeur existe et couvre TOUS les devices
    # exposés : dans ce cas, la remédiation attendue est d'appliquer la
    # mise à jour. Si AUCUN device exposé n'a de mise à jour disponible,
    # le patch n'est pas fusible (souvent parce que le composant
    # vulnérable — ex: une lib Apache embarquée — dépend d'un éditeur
    # tiers qui n'a pas encore publié de correctif) : il faut alors une
    # mesure d'atténuation en attendant. Entre les deux (certains
    # devices patchables, d'autres non), c'est une situation partielle.
    if devices_with_update <= 0:
        patch_feasibility = "NOT_FEASIBLE"
    elif devices_with_update >= affected_devices:
        patch_feasibility = "FEASIBLE"
    else:
        patch_feasibility = "PARTIAL"

    return {
        "affected_devices": affected_devices,
        "affected_products": row["affected_products"] or 0,
        "os_platforms": _split(row["os_platforms"]),
        "defender_severities": _split(row["defender_severities"]),
        "exploitability_levels": _split(row["exploitability_levels"]),
        "devices_with_update_available": devices_with_update,
        "sample_device_names": [
            r["device_name"] for r in sample_devices if r["device_name"]
        ],
        "recommended_updates": _split(row["recommended_updates"]),
        "patch_feasibility": patch_feasibility
    }


# =========================================================
# DEFENDER INSERT / UPDATE
# =========================================================

def save_defender_vulnerability(
    record
):

    conn = get_connection()

    conn.execute("""
        INSERT OR REPLACE INTO defender_vulnerabilities (

            device_id,
            device_name,

            os_platform,
            os_version,

            software_vendor,
            software_name,
            software_version,

            cve_id,

            defender_severity,

            cvss_score,

            recommended_security_update,
            recommended_security_update_id,

            exploitability_level,

            security_update_available,

            first_seen_timestamp,
            last_seen_timestamp,

            imported_at

        )

        VALUES (

            ?, ?, ?, ?,
            ?, ?, ?,
            ?,
            ?,
            ?,
            ?, ?,
            ?,
            ?,
            ?, ?,
            ?

        )
    """, (

        record.get(
            "deviceId"
        ),

        record.get(
            "deviceName"
        ),

        record.get(
            "osPlatform"
        ),

        record.get(
            "osVersion"
        ),

        record.get(
            "softwareVendor"
        ),

        record.get(
            "softwareName"
        ),

        record.get(
            "softwareVersion"
        ),

        record.get(
            "cveId"
        ),

        record.get(
            "vulnerabilitySeverityLevel"
        ),

        record.get(
            "cvssScore"
        ),

        record.get(
            "recommendedSecurityUpdate"
        ),

        record.get(
            "recommendedSecurityUpdateId"
        ),

        record.get(
            "exploitabilityLevel"
        ),

        int(
            bool(
                record.get(
                    "securityUpdateAvailable",
                    False
                )
            )
        ),

        record.get(
            "firstSeenTimestamp"
        ),

        record.get(
            "lastSeenTimestamp"
        ),

        record.get(
            "imported_at"
        )

    ))

    conn.commit()
    conn.close()


# =========================================================
# BULK DEFENDER INSERT
# =========================================================

def save_defender_vulnerabilities(
    records
):

    conn = get_connection()

    conn.executemany("""
        INSERT OR REPLACE INTO defender_vulnerabilities (

            device_id,
            device_name,

            os_platform,
            os_version,

            software_vendor,
            software_name,
            software_version,

            cve_id,

            defender_severity,

            cvss_score,

            recommended_security_update,
            recommended_security_update_id,

            exploitability_level,

            security_update_available,

            first_seen_timestamp,
            last_seen_timestamp,

            imported_at

        )

        VALUES (

            ?, ?, ?, ?,
            ?, ?, ?,
            ?,
            ?,
            ?,
            ?, ?,
            ?,
            ?,
            ?, ?,
            ?

        )
    """, records)

    conn.commit()
    conn.close()


# =========================================================
# DATABASE STATISTICS
# =========================================================

def get_database_stats():

    conn = get_connection()

    stats = {}

    stats["vulnerabilities"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM vulnerabilities
        """
    ).fetchone()[0]

    stats["nvd_enriched"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM vulnerabilities
        WHERE nvd_enriched = 1
        """
    ).fetchone()[0]

    stats["ai_enriched"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM vulnerabilities
        WHERE ai_status = 'OK'
        """
    ).fetchone()[0]

    stats["defender_records"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM defender_vulnerabilities
        """
    ).fetchone()[0]

    stats["defender_devices"] = conn.execute(
        """
        SELECT COUNT(DISTINCT device_id)
        FROM defender_vulnerabilities
        """
    ).fetchone()[0]

    stats["defender_cves"] = conn.execute(
        """
        SELECT COUNT(DISTINCT cve_id)
        FROM defender_vulnerabilities
        """
    ).fetchone()[0]

    conn.close()

    return stats


# =========================================================
# MANUAL SERVER OWNERS (CSV import)
# =========================================================

def import_manual_server_owners(
    rows
):
    """
    Bulk upsert des propriétaires/notification importés par CSV
    pour l'inventaire Windows Server.

    rows : liste de dicts avec les clés :
        device_name  (nom du serveur, obligatoire)
        owner        (texte libre, peut être None)
        notification (0 ou 1)
    """

    if not rows:
        return 0

    conn = get_connection()

    imported_at = datetime.now(timezone.utc).isoformat()

    conn.executemany("""
        INSERT INTO manual_server_owners (

            device_name,
            owner,
            notification,
            imported_at

        )

        VALUES (?, ?, ?, ?)

        ON CONFLICT(device_name) DO UPDATE SET

            owner = excluded.owner,
            notification = excluded.notification,
            imported_at = excluded.imported_at
    """, [
        (
            row["device_name"],
            row.get("owner"),
            int(row.get("notification") or 0),
            imported_at
        )
        for row in rows
        if row.get("device_name")
    ])

    conn.commit()
    conn.close()

    return len(rows)


def get_manual_server_owners():

    conn = get_connection()

    df_rows = conn.execute(
        """
        SELECT device_name, owner, notification, imported_at
        FROM manual_server_owners
        ORDER BY device_name
        """
    ).fetchall()

    conn.close()

    return [dict(row) for row in df_rows]


# =========================================================
# SYNC STATE (last run tracking per sync job)
# =========================================================

def set_sync_state(
    sync_key,
    status,
    detail=None
):
    """
    Enregistre l'heure et le statut de la dernière exécution d'un
    job de synchronisation (ex: "cisa_kev").
    """

    conn = get_connection()

    conn.execute("""
        INSERT INTO sync_state (
            sync_key,
            last_run_at,
            status,
            detail
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(sync_key) DO UPDATE SET
            last_run_at = excluded.last_run_at,
            status = excluded.status,
            detail = excluded.detail
    """, (
        sync_key,
        datetime.now(timezone.utc).isoformat(),
        status,
        detail
    ))

    conn.commit()
    conn.close()


def get_sync_state(
    sync_key
):
    """
    Retourne {"last_run_at", "status", "detail"} ou None si ce job
    n'a jamais tourné.
    """

    conn = get_connection()

    row = conn.execute(
        """
        SELECT last_run_at, status, detail
        FROM sync_state
        WHERE sync_key = ?
        """,
        (sync_key,)
    ).fetchone()

    conn.close()

    return dict(row) if row else None


def get_pending_nvd_count():
    """
    Nombre de CVE dont l'enrichissement NVD (CVSS/sévérité) n'a
    jamais réussi. C'est ce compteur qui explique les colonnes
    "CVSS 3.1" / "Sévérité NVD" vides tant qu'il n'est pas à zéro.
    """

    conn = get_connection()

    count = conn.execute(
        """
        SELECT COUNT(*)
        FROM vulnerabilities
        WHERE COALESCE(nvd_enriched, 0) = 0
        """
    ).fetchone()[0]

    conn.close()

    return count


def get_enrichment_integrity_snapshot():
    """
    "Photo" du nombre de CVE enrichies (NVD + IA) à un instant donné.
    Utilisé pour vérifier, avant/après une synchronisation CISA, que
    save_vulnerability() n'a pas réinitialisé l'enrichissement déjà
    effectué (voir sync.py). Si ces compteurs baissent après un sync,
    c'est le signe d'une régression de type "INSERT OR REPLACE".
    """

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN nvd_status = 'OK' THEN 1 ELSE 0 END) AS nvd_ok,
            SUM(CASE WHEN ai_status = 'OK' THEN 1 ELSE 0 END) AS ai_ok
        FROM vulnerabilities
        """
    ).fetchone()

    conn.close()

    return {
        "total": row["total"] or 0,
        "nvd_ok": row["nvd_ok"] or 0,
        "ai_ok": row["ai_ok"] or 0
    }


# =========================================================
# APP CONFIG (generic key/value settings)
# =========================================================

def set_app_config(
    key,
    value
):

    conn = get_connection()

    conn.execute("""
        INSERT INTO app_config (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (key, value))

    conn.commit()
    conn.close()


def get_app_config(
    key,
    default=None
):

    conn = get_connection()

    row = conn.execute(
        "SELECT value FROM app_config WHERE key = ?",
        (key,)
    ).fetchone()

    conn.close()

    return row["value"] if row else default


# =========================================================
# ADMIN CREDENTIALS (stored in DB, never hardcoded)
# =========================================================
#
# Le mot de passe n'est jamais stocké en clair : on stocke un sel
# aléatoire (par installation) et un hash PBKDF2-HMAC-SHA256 de
# (mot de passe + sel). Comparaisons en temps constant (hmac).

PBKDF2_ITERATIONS = 200_000


def _hash_password(password, salt):

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    ).hex()


def get_admin_credentials():
    """
    Retourne {"username", "salt", "hash"} ou None si aucun compte
    n'a encore été créé (première installation pas encore initialisée).
    """

    username = get_app_config("admin_username")
    salt = get_app_config("admin_password_salt")
    password_hash = get_app_config("admin_password_hash")

    if not username or not salt or not password_hash:
        return None

    return {
        "username": username,
        "salt": salt,
        "hash": password_hash
    }


def set_admin_credentials(
    username,
    password
):
    """
    Définit (ou change) le compte admin. Écrase l'existant.
    """

    salt = secrets.token_bytes(16)

    password_hash = _hash_password(
        password,
        salt
    )

    set_app_config("admin_username", username)
    set_app_config("admin_password_salt", salt.hex())
    set_app_config("admin_password_hash", password_hash)

    # Nouveaux identifiants : toutes les sessions ouvertes (autres
    # navigateurs, postes) doivent se reconnecter.
    delete_all_auth_sessions()


# =========================================================
# SESSIONS DE CONNEXION
# =========================================================
#
# Streamlit perd st.session_state à chaque rafraîchissement de la page
# (nouvelle session côté serveur) : sans ceci, il fallait se
# reconnecter à chaque F5. À la connexion, un jeton aléatoire est
# déposé dans un cookie du navigateur ; seule son empreinte SHA-256 est
# stockée ici, avec une date d'expiration. "Se déconnecter" et un
# changement d'identifiants suppriment la session.

AUTH_SESSION_DAYS = int(os.getenv("VULNWATCH_SESSION_DAYS", "30"))


def _token_hash(token):

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_auth_session(username):
    """Crée une session et retourne le jeton à mettre dans le cookie."""

    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)

    conn = get_connection()

    conn.execute(
        "DELETE FROM auth_sessions WHERE expires_at < ?",
        (now.isoformat(),)
    )

    conn.execute(
        """
        INSERT INTO auth_sessions (token_hash, username, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            _token_hash(token),
            username,
            now.isoformat(),
            (now + timedelta(days=AUTH_SESSION_DAYS)).isoformat()
        )
    )

    conn.commit()
    conn.close()

    return token


def get_auth_session_user(token):
    """
    Utilisateur (dict, voir get_user) de la session si le jeton est
    valide (connu, non expiré, utilisateur existant et actif), sinon None.
    """

    # Cookie absent ou mal formé : simplement pas de session.
    if not isinstance(token, str) or not token:
        return None

    conn = get_connection()

    row = conn.execute(
        "SELECT username, expires_at FROM auth_sessions WHERE token_hash = ?",
        (_token_hash(token),)
    ).fetchone()

    conn.close()

    if not row:
        return None

    if row["expires_at"] < datetime.now(timezone.utc).isoformat():
        delete_auth_session(token)
        return None

    user = get_user(row["username"])

    if not user or not user["active"]:
        return None

    return user


def delete_auth_session(token):

    if not token:
        return

    conn = get_connection()
    conn.execute(
        "DELETE FROM auth_sessions WHERE token_hash = ?",
        (_token_hash(token),)
    )
    conn.commit()
    conn.close()


def delete_all_auth_sessions():

    conn = get_connection()
    conn.execute("DELETE FROM auth_sessions")
    conn.commit()
    conn.close()


def verify_admin_credentials(
    username,
    password
):
    """
    Vérifie nom d'utilisateur + mot de passe en temps constant.
    """

    creds = get_admin_credentials()

    if creds is None:
        return False

    salt = bytes.fromhex(creds["salt"])

    computed_hash = _hash_password(
        password,
        salt
    )

    username_ok = hmac.compare_digest(
        username,
        creds["username"]
    )

    password_ok = hmac.compare_digest(
        computed_hash,
        creds["hash"]
    )

    return username_ok and password_ok


def ensure_admin_seeded():
    """
    Garantit qu'un compte administrateur existe (table users).

    - Installation existante : l'ancien compte admin unique (app_config)
      est repris tel quel, même mot de passe.
    - Première installation : VULNWATCH_ADMIN_USER / _PASSWORD si
      définies, sinon "admin" avec un mot de passe aléatoire à changer à
      la première connexion.

    Retourne {"username", "password"} UNIQUEMENT quand un mot de passe a
    été généré ici (affichage unique), sinon None.
    """

    conn = get_connection()
    has_users = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    conn.close()

    if has_users:
        return None

    legacy = get_admin_credentials()
    now = datetime.now(timezone.utc).isoformat()

    if legacy is not None:

        conn = get_connection()
        conn.execute(
            """
            INSERT INTO users (
                username, password_salt, password_hash, role,
                must_change_password, active, created_at, created_by
            )
            VALUES (?, ?, ?, 'admin', 0, 1, ?, 'migration')
            """,
            (legacy["username"], legacy["salt"], legacy["hash"], now)
        )
        conn.commit()
        conn.close()

        return None

    username = os.getenv("VULNWATCH_ADMIN_USER") or "admin"
    env_password = os.getenv("VULNWATCH_ADMIN_PASSWORD")
    generated = env_password is None
    password = env_password or secrets.token_urlsafe(18)

    create_user(
        username,
        password,
        role="admin",
        must_change_password=generated,
        created_by="installation",
        enforce_policy=False
    )

    if generated:
        return {"username": username, "password": password}

    return None


# =========================================================
# UTILISATEURS ET POLITIQUE DE MOT DE PASSE
# =========================================================
#
# Deux rôles :
#   - admin  : tout (configuration, imports, synchros, utilisateurs) ;
#   - viewer : consultation et rafraîchissement de l'affichage seulement.

ROLES = {
    "admin": "Administrateur",
    "viewer": "Lecteur (consultation)"
}

PASSWORD_MIN_LENGTH = 15


def password_policy_checks(password):
    """
    [(exigence, respectée)] : la liste est affichée à l'utilisateur pour
    qu'il voie ce qui est déjà respecté et ce qui ne l'est pas encore.
    """

    password = password or ""

    return [
        (f"Au moins {PASSWORD_MIN_LENGTH} caractères "
         f"(actuellement {len(password)})",
         len(password) >= PASSWORD_MIN_LENGTH),
        ("Au moins un chiffre (0-9)",
         any(c.isdigit() for c in password)),
        ("Au moins une lettre (a-z, A-Z)",
         any(c.isalpha() for c in password)),
        ("Au moins un caractère spécial (ex. ! @ # $ % & * ? - _)",
         any(not c.isalnum() and not c.isspace() for c in password))
    ]


def password_is_valid(password):

    return all(ok for _, ok in password_policy_checks(password))


def get_user(username):

    conn = get_connection()

    row = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if not row:
        return None

    user = dict(row)
    user["active"] = bool(user["active"])
    user["must_change_password"] = bool(user["must_change_password"])

    return user


def list_users():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT username, role, must_change_password, active,
               created_at, created_by, last_login_at
        FROM users
        ORDER BY role, username
        """
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def create_user(
    username,
    password,
    role="viewer",
    must_change_password=True,
    created_by=None,
    enforce_policy=True
):
    """Crée un utilisateur. Lève ValueError si invalide ou déjà existant."""

    username = (username or "").strip()

    if not username:
        raise ValueError("Nom d'utilisateur obligatoire.")

    if role not in ROLES:
        raise ValueError(f"Rôle inconnu : {role}")

    if enforce_policy and not password_is_valid(password):
        raise ValueError("Le mot de passe ne respecte pas la politique.")

    if get_user(username):
        raise ValueError(f"L'utilisateur « {username} » existe déjà.")

    salt = secrets.token_bytes(16)

    conn = get_connection()
    conn.execute(
        """
        INSERT INTO users (
            username, password_salt, password_hash, role,
            must_change_password, active, created_at, created_by
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            username,
            salt.hex(),
            _hash_password(password, salt),
            role,
            1 if must_change_password else 0,
            datetime.now(timezone.utc).isoformat(),
            created_by
        )
    )
    conn.commit()
    conn.close()


def verify_user_credentials(username, password):
    """
    Utilisateur (dict) si nom + mot de passe corrects et compte actif,
    sinon None. Comparaison en temps constant ; un calcul de hash est
    fait même pour un utilisateur inconnu (pas d'indice sur son
    existence par le temps de réponse).
    """

    user = get_user((username or "").strip())

    if user is None:
        _hash_password(password or "", secrets.token_bytes(16))
        return None

    computed = _hash_password(password or "", bytes.fromhex(user["password_salt"]))

    if not hmac.compare_digest(computed, user["password_hash"]):
        return None

    if not user["active"]:
        return None

    conn = get_connection()
    conn.execute(
        "UPDATE users SET last_login_at = ? WHERE username = ?",
        (datetime.now(timezone.utc).isoformat(), user["username"])
    )
    conn.commit()
    conn.close()

    return user


def set_user_password(username, password, must_change_password=False):
    """
    Change le mot de passe (politique appliquée) et ferme toutes les
    sessions de l'utilisateur (autres navigateurs, postes).
    """

    if not password_is_valid(password):
        raise ValueError("Le mot de passe ne respecte pas la politique.")

    salt = secrets.token_bytes(16)

    conn = get_connection()
    conn.execute(
        """
        UPDATE users
        SET password_salt = ?, password_hash = ?, must_change_password = ?
        WHERE username = ?
        """,
        (salt.hex(), _hash_password(password, salt),
         1 if must_change_password else 0, username)
    )
    conn.commit()
    conn.close()

    delete_user_sessions(username)


def count_active_admins(exclude=None):

    conn = get_connection()

    count = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1 "
        "AND username <> ?",
        (exclude or "",)
    ).fetchone()[0]

    conn.close()

    return count


def update_user(username, role=None, active=None):
    """
    Change le rôle et/ou l'état d'un utilisateur. Refuse de retirer le
    dernier administrateur actif.
    """

    user = get_user(username)

    if user is None:
        raise ValueError("Utilisateur introuvable.")

    removes_admin = user["role"] == "admin" and user["active"] and (
        (role is not None and role != "admin")
        or (active is not None and not active)
    )

    if removes_admin and count_active_admins(exclude=username) == 0:
        raise ValueError("Impossible : c'est le dernier administrateur actif.")

    conn = get_connection()

    if role is not None:
        conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))

    if active is not None:
        conn.execute(
            "UPDATE users SET active = ? WHERE username = ?",
            (1 if active else 0, username)
        )

    conn.commit()
    conn.close()

    if active is False or role is not None:
        delete_user_sessions(username)


def delete_user(username):

    user = get_user(username)

    if user is None:
        return

    if user["role"] == "admin" and user["active"] and count_active_admins(exclude=username) == 0:
        raise ValueError("Impossible : c'est le dernier administrateur actif.")

    delete_user_sessions(username)

    conn = get_connection()
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def delete_user_sessions(username):

    conn = get_connection()
    conn.execute("DELETE FROM auth_sessions WHERE username = ?", (username,))
    conn.commit()
    conn.close()


# =========================================================
# EMAIL NOTIFICATIONS (alerte propriétaire de serveur + relances IA)
# =========================================================
#
# Un propriétaire (owner) dont la case "Notification" est activée
# reçoit un e-mail généré par l'IA locale dès qu'une CVE CISA KEV est
# détectée sur son serveur. Si la CVE est toujours présente après un
# délai configurable (selon la criticité), une relance est envoyée.
# Le délai est stocké dans app_config, les identifiants SMTP aussi
# (jamais codés en dur).

DEFAULT_NOTIFICATION_DELAY_HOURS = {
    "CRITICAL": 24,
    "HIGH": 72,
    "MEDIUM": 168,   # 7 jours
    "LOW": 336       # 14 jours
}

NOTIFICATION_DELAY_CONFIG_KEYS = {
    "CRITICAL": "notif_delay_critical_hours",
    "HIGH": "notif_delay_high_hours",
    "MEDIUM": "notif_delay_medium_hours",
    "LOW": "notif_delay_low_hours"
}


def get_notification_delays():
    """
    Retourne le délai (en heures) avant relance pour chaque niveau de
    criticité, en lisant app_config (valeurs par défaut sinon).
    """

    delays = {}

    for priority, default_hours in DEFAULT_NOTIFICATION_DELAY_HOURS.items():

        raw = get_app_config(
            NOTIFICATION_DELAY_CONFIG_KEYS[priority]
        )

        try:
            delays[priority] = float(raw) if raw is not None else default_hours
        except (TypeError, ValueError):
            delays[priority] = default_hours

    return delays


def set_notification_delay(priority, hours):

    key = NOTIFICATION_DELAY_CONFIG_KEYS.get(priority)

    if not key:
        raise ValueError(f"Priorité inconnue : {priority}")

    set_app_config(key, str(float(hours)))


def get_notification_delay_hours(priority):

    return get_notification_delays().get(
        priority,
        DEFAULT_NOTIFICATION_DELAY_HOURS.get("LOW")
    )


# ---------------------------------------------------------
# SMTP configuration (stockée en base, jamais en dur)
# ---------------------------------------------------------

SMTP_CONFIG_KEYS = {
    "host": "smtp_host",
    "port": "smtp_port",
    "username": "smtp_username",
    "password": "smtp_password",
    "from_addr": "smtp_from_addr",
    "use_tls": "smtp_use_tls"
}


def get_smtp_config():

    return {
        "host": get_app_config(SMTP_CONFIG_KEYS["host"], ""),
        "port": int(get_app_config(SMTP_CONFIG_KEYS["port"], "587") or 587),
        "username": get_app_config(SMTP_CONFIG_KEYS["username"], ""),
        "password": get_app_config(SMTP_CONFIG_KEYS["password"], ""),
        "from_addr": get_app_config(SMTP_CONFIG_KEYS["from_addr"], ""),
        "use_tls": get_app_config(SMTP_CONFIG_KEYS["use_tls"], "1") == "1"
    }


def set_smtp_config(host, port, username, password, from_addr, use_tls):

    set_app_config(SMTP_CONFIG_KEYS["host"], host or "")
    set_app_config(SMTP_CONFIG_KEYS["port"], str(int(port)))
    set_app_config(SMTP_CONFIG_KEYS["username"], username or "")

    # Ne jamais écraser un mot de passe déjà enregistré avec une
    # valeur vide (ex: champ laissé vide volontairement au
    # ré-enregistrement d'autres paramètres depuis l'UI).
    if password:
        set_app_config(SMTP_CONFIG_KEYS["password"], password)

    set_app_config(SMTP_CONFIG_KEYS["from_addr"], from_addr or "")
    set_app_config(SMTP_CONFIG_KEYS["use_tls"], "1" if use_tls else "0")


def is_smtp_configured():

    cfg = get_smtp_config()

    return bool(cfg["host"] and cfg["from_addr"])


# ---------------------------------------------------------
# Seuil de criticité déclenchant l'envoi (nouvelle "philosophie")
# ---------------------------------------------------------
#
# Avant : un e-mail partait immédiatement, pour CHAQUE CVE, quelle
# que soit sa criticité. Maintenant : le premier e-mail pour un
# serveur ne part que si au moins une de ses CVE atteint ce seuil ;
# les CVE moins critiques ne déclenchent jamais un envoi à elles
# seules, mais sont regroupées dans le même e-mail dès qu'une CVE
# plus grave le déclenche pour ce serveur (voir get_notification_candidates).

PRIORITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

NOTIF_MIN_PRIORITY_KEY = "notif_min_priority"
DEFAULT_NOTIF_MIN_PRIORITY = "HIGH"


def _priority_rank(priority):

    return PRIORITY_ORDER.get((priority or "").upper(), 0)


def get_notification_min_priority():

    value = get_app_config(NOTIF_MIN_PRIORITY_KEY, DEFAULT_NOTIF_MIN_PRIORITY)

    return value if value in PRIORITY_ORDER else DEFAULT_NOTIF_MIN_PRIORITY


def set_notification_min_priority(priority):

    if priority not in PRIORITY_ORDER:
        raise ValueError(f"Priorité inconnue : {priority}")

    set_app_config(NOTIF_MIN_PRIORITY_KEY, priority)


# ---------------------------------------------------------
# Candidats à notifier / relancer (regroupés par serveur)
# ---------------------------------------------------------

def get_notification_candidates():
    """
    Regroupe par SERVEUR (device_name) les CVE CISA KEV actuellement
    présentes (Defender) chez les propriétaires notifiables (case
    "Notification" activée + adresse e-mail valide dans le champ
    "Propriétaire").

    Un serveur ne devient candidat à un NOUVEL envoi que si :
      - il n'a pas déjà de notification active (statut SENT ou
        REMINDER_SENT) — sinon c'est le cycle de relance qui prend
        le relais (voir get_due_notifications) ;
      - au moins une de ses CVE atteint le seuil de criticité
        configuré (get_notification_min_priority()).

    Quand un serveur qualifie, l'e-mail regroupe TOUTES les CVE
    actuellement présentes sur ce serveur (y compris celles sous le
    seuil), pour un seul e-mail par serveur plutôt qu'un e-mail par
    CVE.

    Retourne une liste de dicts :
        {"device_name", "device_id", "owner_email",
         "cves": [{"cve_id", "priority", "risk_score"}, ...]}
    """

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT DISTINCT
            d.cve_id,
            d.device_name,
            d.device_id,
            m.owner AS owner_email,
            v.priority,
            v.risk_score

        FROM defender_vulnerabilities d

        INNER JOIN manual_server_owners m
            ON m.device_name = d.device_name
            AND m.notification = 1
            AND m.owner IS NOT NULL
            AND m.owner LIKE '%@%'

        INNER JOIN vulnerabilities v
            ON v.cve_id = d.cve_id
            AND v.source = 'CISA KEV'

        LEFT JOIN device_notifications n
            ON n.device_name = d.device_name
            AND n.status IN ('SENT', 'REMINDER_SENT')

        WHERE n.id IS NULL
        """
    ).fetchall()

    conn.close()

    grouped = {}

    for row in rows:

        device_name = row["device_name"]

        group = grouped.setdefault(
            device_name,
            {
                "device_name": device_name,
                "device_id": row["device_id"],
                "owner_email": row["owner_email"],
                "cves": []
            }
        )

        group["cves"].append({
            "cve_id": row["cve_id"],
            "priority": row["priority"] or "UNKNOWN",
            "risk_score": row["risk_score"] or 0
        })

    min_rank = _priority_rank(get_notification_min_priority())

    candidates = []

    for group in grouped.values():

        top_rank = max(
            _priority_rank(cve["priority"])
            for cve in group["cves"]
        )

        if top_rank < min_rank:
            continue

        group["cves"].sort(
            key=lambda cve: (
                -_priority_rank(cve["priority"]),
                -(cve["risk_score"] or 0)
            )
        )

        candidates.append(group)

    candidates.sort(
        key=lambda group: -max(
            _priority_rank(cve["priority"])
            for cve in group["cves"]
        )
    )

    return candidates


def _add_hours_iso(dt, hours):

    return (dt + timedelta(hours=hours)).isoformat()


def _min_delay_hours(cves):
    """
    Le prochain contrôle (next_check_at) d'un e-mail groupé est calé
    sur le délai le plus COURT parmi les CVE du groupe : c'est la CVE
    la plus urgente qui pilote la fréquence de relance de tout le
    serveur.
    """

    if not cves:
        return get_notification_delay_hours("LOW")

    return min(
        get_notification_delay_hours(cve["priority"])
        for cve in cves
    )


def create_device_notification(
    device_name,
    device_id,
    owner_email,
    cves,
    subject,
    body
):
    """
    Crée (ou réactive, si une notification précédente pour ce serveur
    a été RESOLVED) une notification groupée, avec le détail des CVE
    couvertes dans device_notification_cves.

    cves : liste de dicts {"cve_id", "priority"}.
    """

    now = datetime.now(timezone.utc)
    delay_hours = _min_delay_hours(cves)

    conn = get_connection()

    conn.execute(
        """
        INSERT INTO device_notifications (
            device_name, device_id, owner_email,
            status, email_subject, email_body, sent_at,
            reminder_count, next_check_at
        )
        VALUES (?, ?, ?, 'SENT', ?, ?, ?, 0, ?)
        ON CONFLICT(device_name) DO UPDATE SET
            device_id = excluded.device_id,
            owner_email = excluded.owner_email,
            status = 'SENT',
            email_subject = excluded.email_subject,
            email_body = excluded.email_body,
            sent_at = excluded.sent_at,
            reminder_count = 0,
            last_reminder_at = NULL,
            next_check_at = excluded.next_check_at,
            resolved_at = NULL,
            last_error = NULL
        """,
        (
            device_name, device_id, owner_email,
            subject, body, now.isoformat(),
            _add_hours_iso(now, delay_hours)
        )
    )

    notification_id = conn.execute(
        "SELECT id FROM device_notifications WHERE device_name = ?",
        (device_name,)
    ).fetchone()["id"]

    conn.execute(
        "DELETE FROM device_notification_cves WHERE notification_id = ?",
        (notification_id,)
    )

    conn.executemany(
        """
        INSERT INTO device_notification_cves (
            notification_id, cve_id, priority, resolved
        )
        VALUES (?, ?, ?, 0)
        """,
        [
            (notification_id, cve["cve_id"], cve["priority"])
            for cve in cves
        ]
    )

    conn.commit()
    conn.close()

    return notification_id


def get_notification_cves(notification_id, only_unresolved=False):

    conn = get_connection()

    query = (
        "SELECT * FROM device_notification_cves WHERE notification_id = ?"
    )
    params = [notification_id]

    if only_unresolved:
        query += " AND resolved = 0"

    rows = conn.execute(query, params).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_due_notifications():
    """
    Notifications déjà envoyées (SENT ou REMINDER_SENT) dont l'échéance
    de vérification (next_check_at) est passée : il faut vérifier si
    chacune des CVE du groupe est toujours présente sur le device, et
    relancer (pour celles qui restent) ou résoudre (si plus aucune).
    """

    conn = get_connection()

    now_iso = datetime.now(timezone.utc).isoformat()

    rows = conn.execute(
        """
        SELECT *
        FROM device_notifications
        WHERE status IN ('SENT', 'REMINDER_SENT')
          AND next_check_at IS NOT NULL
          AND next_check_at <= ?
        ORDER BY next_check_at ASC
        """,
        (now_iso,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def is_cve_still_on_device(cve_id, device_name):

    conn = get_connection()

    row = conn.execute(
        """
        SELECT 1
        FROM defender_vulnerabilities
        WHERE cve_id = ? AND device_name = ?
        LIMIT 1
        """,
        (cve_id, device_name)
    ).fetchone()

    conn.close()

    return row is not None


def mark_notification_cve_resolved(notification_id, cve_id):

    conn = get_connection()

    conn.execute(
        """
        UPDATE device_notification_cves
        SET resolved = 1, resolved_at = ?
        WHERE notification_id = ? AND cve_id = ?
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            notification_id,
            cve_id
        )
    )

    conn.commit()
    conn.close()


def mark_notification_reminder_sent(
    notification_id,
    subject,
    body,
    remaining_cves
):

    now = datetime.now(timezone.utc)
    delay_hours = _min_delay_hours(remaining_cves)

    conn = get_connection()

    conn.execute(
        """
        UPDATE device_notifications
        SET status = 'REMINDER_SENT',
            email_subject = ?,
            email_body = ?,
            reminder_count = reminder_count + 1,
            last_reminder_at = ?,
            next_check_at = ?,
            last_error = NULL
        WHERE id = ?
        """,
        (
            subject, body, now.isoformat(),
            _add_hours_iso(now, delay_hours),
            notification_id
        )
    )

    conn.commit()
    conn.close()


def mark_notification_resolved(notification_id):

    conn = get_connection()

    conn.execute(
        """
        UPDATE device_notifications
        SET status = 'RESOLVED',
            resolved_at = ?,
            next_check_at = NULL
        WHERE id = ?
        """,
        (datetime.now(timezone.utc).isoformat(), notification_id)
    )

    conn.commit()
    conn.close()


def mark_notification_error(notification_id, error):

    conn = get_connection()

    conn.execute(
        """
        UPDATE device_notifications
        SET status = 'ERROR',
            last_error = ?
        WHERE id = ?
        """,
        (str(error), notification_id)
    )

    conn.commit()
    conn.close()


def get_notification_history(limit=200):
    """
    Une ligne par serveur notifié, avec la liste agrégée des CVE
    couvertes par la notification (résolues ou non).
    """

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            n.id,
            n.device_name,
            n.owner_email,
            n.status,
            n.sent_at,
            n.reminder_count,
            n.last_reminder_at,
            n.next_check_at,
            n.resolved_at,
            n.last_error,
            GROUP_CONCAT(DISTINCT c.cve_id) AS cve_ids,
            COUNT(DISTINCT c.cve_id) AS cve_count,
            SUM(CASE WHEN c.resolved = 0 THEN 1 ELSE 0 END) AS cve_open_count
        FROM device_notifications n
        LEFT JOIN device_notification_cves c
            ON c.notification_id = n.id
        GROUP BY n.id
        ORDER BY
            COALESCE(n.last_reminder_at, n.sent_at) DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


# =========================================================
# HEXIOSEC ASM (Attack Surface Management)
# =========================================================
#
# Intégration générique : la clé API et les paramètres de connexion
# sont stockés en base (jamais codés en dur, jamais dans un fichier
# livré), exactement comme pour le SMTP. Le chemin d'endpoint est
# configurable car l'API publique Hexiosec est scopée par
# organisation/scan (ex: "SCC Group / SCC Own Asset Monitoring /
# SCC France") et son URL exacte dépend du compte du client.

HEXIOSEC_CONFIG_KEYS = {
    "base_url": "hexiosec_base_url",
    "api_key": "hexiosec_api_key",
    "auth_header": "hexiosec_auth_header",
    "auth_prefix": "hexiosec_auth_prefix",
    "endpoint_path": "hexiosec_endpoint_path",
    "scan_id": "hexiosec_scan_id",
    "label": "hexiosec_label"
}

# Valeurs confirmées via la spec OpenAPI officielle
# (https://asm.hexiosec.com/api/openapi.yml) : authentification par
# header "X-Hexiosec-API-Key" (pas de préfixe "Bearer"), endpoint
# GET /v1/scan_data/{scan_id}/risks, pagination par limit/offset.
HEXIOSEC_DEFAULTS = {
    "base_url": "https://asm.hexiosec.com/api",
    "auth_header": "X-Hexiosec-API-Key",
    "auth_prefix": "",
    "endpoint_path": "/v1/scan_data/{scan_id}/risks",
    "label": "SCC France"
}


def get_hexiosec_config():

    return {
        "base_url": get_app_config(
            HEXIOSEC_CONFIG_KEYS["base_url"],
            HEXIOSEC_DEFAULTS["base_url"]
        ),
        "api_key": get_app_config(HEXIOSEC_CONFIG_KEYS["api_key"], ""),
        "auth_header": get_app_config(
            HEXIOSEC_CONFIG_KEYS["auth_header"],
            HEXIOSEC_DEFAULTS["auth_header"]
        ),
        "auth_prefix": get_app_config(
            HEXIOSEC_CONFIG_KEYS["auth_prefix"],
            HEXIOSEC_DEFAULTS["auth_prefix"]
        ),
        "endpoint_path": get_app_config(
            HEXIOSEC_CONFIG_KEYS["endpoint_path"],
            HEXIOSEC_DEFAULTS["endpoint_path"]
        ),
        "scan_id": get_app_config(HEXIOSEC_CONFIG_KEYS["scan_id"], ""),
        "label": get_app_config(
            HEXIOSEC_CONFIG_KEYS["label"],
            HEXIOSEC_DEFAULTS["label"]
        )
    }


def set_hexiosec_config(
    base_url,
    api_key,
    auth_header,
    auth_prefix,
    endpoint_path,
    scan_id,
    label
):

    set_app_config(HEXIOSEC_CONFIG_KEYS["base_url"], base_url or "")
    set_app_config(HEXIOSEC_CONFIG_KEYS["auth_header"], auth_header or "")
    set_app_config(HEXIOSEC_CONFIG_KEYS["auth_prefix"], auth_prefix or "")
    set_app_config(HEXIOSEC_CONFIG_KEYS["endpoint_path"], endpoint_path or "")
    set_app_config(HEXIOSEC_CONFIG_KEYS["scan_id"], scan_id or "")
    set_app_config(HEXIOSEC_CONFIG_KEYS["label"], label or "")

    # Comme pour le SMTP : ne jamais écraser une clé déjà enregistrée
    # par une valeur vide (champ laissé vide volontairement).
    if api_key:
        set_app_config(HEXIOSEC_CONFIG_KEYS["api_key"], api_key)


def is_hexiosec_configured():

    cfg = get_hexiosec_config()

    needs_scan_id = "{scan_id}" in (cfg["endpoint_path"] or "")

    return bool(
        cfg["base_url"]
        and cfg["api_key"]
        and cfg["endpoint_path"]
        and (cfg["scan_id"] if needs_scan_id else True)
    )


def save_hexiosec_findings(findings):
    """
    Upsert d'une liste de risques normalisés (voir
    collectors/hexiosec.py). Ne touche que les colonnes propres à
    Hexiosec ; ne recoupe pas avec `vulnerabilities` (des CVE
    peuvent apparaître dans les deux, cve_id sert juste d'indice
    visuel ici).
    """

    conn = get_connection()

    now = datetime.now(timezone.utc).isoformat()

    count = 0

    for finding in findings:

        conn.execute(
            """
            INSERT INTO hexiosec_findings (
                external_id, asset, category, title, severity,
                cve_id, description, status, first_seen, last_seen,
                imported_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(external_id) DO UPDATE SET
                asset = excluded.asset,
                category = excluded.category,
                title = excluded.title,
                severity = excluded.severity,
                cve_id = excluded.cve_id,
                description = excluded.description,
                status = excluded.status,
                last_seen = excluded.last_seen,
                imported_at = excluded.imported_at
            """,
            (
                finding.get("external_id"),
                finding.get("asset"),
                finding.get("category"),
                finding.get("title"),
                finding.get("severity"),
                finding.get("cve_id"),
                finding.get("description"),
                finding.get("status"),
                finding.get("first_seen"),
                finding.get("last_seen"),
                now
            )
        )

        count += 1

    conn.commit()
    conn.close()

    return count


def get_hexiosec_findings():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            external_id, asset, category, title, severity,
            cve_id, description, status, first_seen, last_seen,
            imported_at
        FROM hexiosec_findings
        ORDER BY
            CASE UPPER(COALESCE(severity, ''))
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            last_seen DESC
        """
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_hexiosec_severity_counts():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            UPPER(COALESCE(severity, 'UNKNOWN')) AS severity,
            COUNT(*) AS total
        FROM hexiosec_findings
        GROUP BY UPPER(COALESCE(severity, 'UNKNOWN'))
        """
    ).fetchall()

    conn.close()

    return {row["severity"]: row["total"] for row in rows}


# ---------------------------------------------------------
# Inventaire d'actifs Hexiosec (domaines, IP, services, composants)
# ---------------------------------------------------------

def save_hexiosec_assets(assets):
    """
    Upsert d'une liste d'actifs normalisés (voir
    collectors/hexiosec.normalize_asset). Une ligne par (asset_type,
    external_id) : les IDs Hexiosec ne sont uniques que dans leur
    propre type de nœud.
    """

    conn = get_connection()

    now = datetime.now(timezone.utc).isoformat()

    count = 0

    for asset in assets:

        if not asset.get("external_id"):
            continue

        conn.execute(
            """
            INSERT INTO hexiosec_assets (
                asset_type, external_id, name, detail,
                risk_critical, risk_high, risk_medium, risk_low, risk_info,
                created, last_seen, imported_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_type, external_id) DO UPDATE SET
                name = excluded.name,
                detail = excluded.detail,
                risk_critical = excluded.risk_critical,
                risk_high = excluded.risk_high,
                risk_medium = excluded.risk_medium,
                risk_low = excluded.risk_low,
                risk_info = excluded.risk_info,
                last_seen = excluded.last_seen,
                imported_at = excluded.imported_at
            """,
            (
                asset.get("asset_type"),
                str(asset.get("external_id")),
                asset.get("name"),
                asset.get("detail"),
                asset.get("risk_critical", 0),
                asset.get("risk_high", 0),
                asset.get("risk_medium", 0),
                asset.get("risk_low", 0),
                asset.get("risk_info", 0),
                asset.get("created"),
                asset.get("last_seen"),
                now
            )
        )

        count += 1

    conn.commit()
    conn.close()

    return count


def get_hexiosec_assets(asset_types=None, search=None, min_severity=None):
    """
    Inventaire des actifs Hexiosec, filtrable par type (liste parmi
    DOMAIN/IP/SERVICE/COMPONENT), texte libre (nom/détail) et
    sévérité minimale des risques associés (ne garde que les actifs
    ayant au moins un risque de ce niveau ou plus grave).
    """

    conn = get_connection()

    query = """
        SELECT
            asset_type, external_id, name, detail,
            risk_critical, risk_high, risk_medium, risk_low, risk_info,
            created, last_seen, imported_at
        FROM hexiosec_assets
        WHERE 1=1
    """

    params = []

    if asset_types:

        placeholders = ", ".join("?" for _ in asset_types)

        query += f" AND asset_type IN ({placeholders})"

        params.extend(asset_types)

    if search:

        query += " AND (name LIKE ? OR detail LIKE ?)"

        like = f"%{search}%"

        params.extend([like, like])

    severity_columns = {
        "CRITICAL": ["risk_critical"],
        "HIGH": ["risk_critical", "risk_high"],
        "MEDIUM": ["risk_critical", "risk_high", "risk_medium"],
        "LOW": ["risk_critical", "risk_high", "risk_medium", "risk_low"]
    }

    if min_severity and min_severity in severity_columns:

        clause = " + ".join(severity_columns[min_severity])

        query += f" AND ({clause}) > 0"

    query += """
        ORDER BY
            (risk_critical + risk_high) DESC,
            last_seen DESC
    """

    rows = conn.execute(query, params).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_hexiosec_asset_type_counts():

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT asset_type, COUNT(*) AS total
        FROM hexiosec_assets
        GROUP BY asset_type
        """
    ).fetchall()

    conn.close()

    return {row["asset_type"]: row["total"] for row in rows}


# =========================================================
# VEILLE VULNÉRABILITÉS (détections récentes + liste de diffusion)
# =========================================================
#
# Partout ailleurs dans l'app, defender_vulnerabilities n'est exploitée
# qu'après un INNER JOIN sur vulnerabilities WHERE source='CISA KEV' :
# on ne voit donc que les CVE Defender qui ont AUSSI été ajoutées au
# catalogue CISA KEV — avec le décalage que ça implique (CISA n'ajoute
# une CVE qu'une fois l'exploitation active confirmée). Hors, la
# synchro Defender (sync_defender.py / collectors/defender.py, export
# TVM "SoftwareVulnerabilitiesExport") ramène en réalité TOUTES les
# vulnérabilités détectées par le moteur Defender XDR, CISA KEV ou
# pas. Cette section expose cette donnée déjà collectée sans ce
# filtre, pour une veille réactive (ex: annonce d'un 0-day style
# "PHP2Shell" avant même qu'il soit référencé CISA KEV), plus une
# liste de diffusion dédiée (indépendante des propriétaires de
# serveur) pour alerter par e-mail.

# =========================================================
# RÉSUMÉ DEFENDER PAR CVE (précalculé)
# =========================================================
#
# defender_vulnerabilities contient une ligne par machine x logiciel x
# CVE (plusieurs millions de lignes). Agréger tout ça à chaque
# affichage (exposition NVD, onglet Veille) prenait des dizaines de
# secondes et figeait la page. Ces données ne changent qu'à l'import
# Defender : on calcule donc UNE ligne par CVE dans
# defender_cve_summary, reconstruite par sync_defender.py après chaque
# import (et une première fois automatiquement sur une base existante).

DEFENDER_SUMMARY_READY_KEY = "defender_cve_summary_ready"


def rebuild_defender_cve_summary():
    """
    (Re)construit defender_cve_summary. La table est préparée sous un
    autre nom puis échangée dans une seule transaction : l'interface
    ne voit jamais une table absente ou à moitié remplie.
    """

    conn = get_connection()

    conn.execute("DROP TABLE IF EXISTS defender_cve_summary_new")

    conn.execute("""
        CREATE TABLE defender_cve_summary_new AS
        SELECT
            cve_id,
            MAX(software_vendor) AS software_vendor,
            MAX(software_name) AS software_name,
            MAX(defender_severity) AS defender_severity,
            MAX(cvss_score) AS defender_cvss_score,
            MAX(exploitability_level) AS exploitability_level,
            COUNT(DISTINCT device_id) AS affected_devices,
            COUNT(
                DISTINCT software_vendor || '|' || software_name
            ) AS affected_products,
            SUM(security_update_available) AS devices_with_update_available,
            MAX(recommended_security_update) AS recommended_security_update,
            MIN(first_seen_timestamp) AS first_seen,
            MAX(last_seen_timestamp) AS last_seen
        FROM defender_vulnerabilities
        WHERE cve_id IS NOT NULL AND TRIM(cve_id) <> ''
        GROUP BY cve_id
    """)

    conn.commit()

    conn.execute("BEGIN")
    conn.execute("DROP TABLE IF EXISTS defender_cve_summary")
    conn.execute(
        "ALTER TABLE defender_cve_summary_new RENAME TO defender_cve_summary"
    )
    conn.execute("""
        CREATE UNIQUE INDEX idx_defender_cve_summary_cve
        ON defender_cve_summary (cve_id)
    """)
    conn.execute("""
        CREATE INDEX idx_defender_cve_summary_first_seen
        ON defender_cve_summary (first_seen)
    """)
    conn.commit()

    count = conn.execute(
        "SELECT COUNT(*) FROM defender_cve_summary"
    ).fetchone()[0]

    conn.close()

    set_app_config(DEFENDER_SUMMARY_READY_KEY, "1")

    return count


# Plusieurs sessions Streamlit (onglets) tournent dans le même process :
# une seule construit le résumé la première fois, les autres attendent.
_DEFENDER_SUMMARY_LOCK = threading.Lock()


def _ensure_defender_cve_summary():

    if get_app_config(DEFENDER_SUMMARY_READY_KEY) == "1":
        return

    with _DEFENDER_SUMMARY_LOCK:

        if get_app_config(DEFENDER_SUMMARY_READY_KEY) != "1":
            rebuild_defender_cve_summary()


def get_recent_defender_detections(limit=200, search=None):
    """
    Une ligne par CVE vue par Defender (TOUT le catalogue Defender, pas
    seulement CISA KEV), triées par date de première détection la plus
    récente — c'est la vue "qu'est-ce qui vient d'apparaître dans
    l'environnement", y compris une CVE qui n'est pas encore dans notre
    table `vulnerabilities`.

    `search` filtre sur le CVE ID, l'éditeur ou le produit (LIKE).

    Enrichit avec les colonnes CISA KEV / NVD / IA quand la CVE s'y
    trouve aussi (LEFT JOIN, donc jamais bloquant).

    Sans recherche (affichage par défaut, à chaque chargement de la
    page) : lit le résumé précalculé defender_cve_summary.
    """

    if search:
        return _search_defender_detections(limit, search)

    _ensure_defender_cve_summary()

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            s.cve_id,
            s.software_vendor,
            s.software_name,
            s.defender_severity,
            s.defender_cvss_score,
            s.exploitability_level,
            s.affected_devices,
            s.devices_with_update_available,
            s.recommended_security_update,
            s.first_seen,
            s.last_seen,
            v.source AS cisa_source,
            v.priority AS cisa_priority,
            v.vulnerability_name,
            v.cvss_v3_score AS nvd_cvss_v3_score,
            v.nvd_published,
            v.due_date AS cisa_due_date
        FROM defender_cve_summary s
        LEFT JOIN vulnerabilities v
            ON v.cve_id = s.cve_id
        ORDER BY s.first_seen DESC, s.cve_id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def _search_defender_detections(limit, search):
    """
    Recherche de l'onglet Veille : agrège les lignes Defender qui
    correspondent à la recherche (pas le résumé précalculé), pour que
    l'éditeur, le produit et le nombre d'équipements affichés soient
    ceux du produit recherché. Ne tourne que quand une recherche est
    saisie (résultat mis en cache par l'interface).

    Regroupe defender_vulnerabilities par CVE (TOUT le catalogue
    Defender, pas seulement CISA KEV), triées par date de première
    détection la plus récente — c'est la vue "qu'est-ce qui vient
    d'apparaître dans l'environnement", y compris une CVE qui n'est
    pas encore dans notre table `vulnerabilities`.

    `search` filtre sur le CVE ID, l'éditeur ou le produit (LIKE).
    Enrichit avec les colonnes CISA KEV / NVD / IA quand la CVE s'y
    trouve aussi (LEFT JOIN, donc jamais bloquant).
    """

    conn = get_connection()

    query = """
        SELECT
            d.cve_id,

            MAX(d.software_vendor) AS software_vendor,
            MAX(d.software_name) AS software_name,

            MAX(d.defender_severity) AS defender_severity,
            MAX(d.cvss_score) AS defender_cvss_score,
            MAX(d.exploitability_level) AS exploitability_level,

            COUNT(DISTINCT d.device_id) AS affected_devices,
            SUM(d.security_update_available) AS devices_with_update_available,
            MAX(d.recommended_security_update) AS recommended_security_update,

            MIN(d.first_seen_timestamp) AS first_seen,
            MAX(d.last_seen_timestamp) AS last_seen,

            MAX(v.source) AS cisa_source,
            MAX(v.priority) AS cisa_priority,
            MAX(v.vulnerability_name) AS vulnerability_name,
            MAX(v.cvss_v3_score) AS nvd_cvss_v3_score,
            MAX(v.nvd_published) AS nvd_published,
            MAX(v.due_date) AS cisa_due_date

        FROM defender_vulnerabilities d

        LEFT JOIN vulnerabilities v
            ON v.cve_id = d.cve_id

        WHERE d.cve_id IS NOT NULL AND TRIM(d.cve_id) <> ''
    """

    params = []

    if search:

        query += """
            AND (
                d.cve_id LIKE ?
                OR d.software_vendor LIKE ?
                OR d.software_name LIKE ?
            )
        """

        like = f"%{search}%"
        params.extend([like, like, like])

    query += """
        GROUP BY d.cve_id
        ORDER BY first_seen DESC
        LIMIT ?
    """

    params.append(limit)

    rows = conn.execute(query, params).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_devices_for_cve(cve_id):
    """
    Tous les équipements (toutes plateformes, pas seulement Windows
    Server) où Defender a détecté cette CVE — "actifs touchés" pour
    la veille et le contenu de l'e-mail d'alerte.
    """

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT DISTINCT
            device_id,
            device_name,
            os_platform,
            os_version,
            software_vendor,
            software_name,
            software_version,
            defender_severity,
            exploitability_level,
            security_update_available,
            recommended_security_update,
            first_seen_timestamp,
            last_seen_timestamp
        FROM defender_vulnerabilities
        WHERE cve_id = ?
        ORDER BY device_name ASC
        """,
        (cve_id,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


# ---------------------------------------------------------
# Liste de diffusion (indépendante des propriétaires de serveur)
# ---------------------------------------------------------

def add_watch_recipient(email, label=None):

    conn = get_connection()

    conn.execute(
        """
        INSERT INTO watch_recipients (email, label, active, added_at)
        VALUES (?, ?, 1, ?)
        ON CONFLICT(email) DO UPDATE SET
            label = excluded.label,
            active = 1
        """,
        (
            email.strip(),
            (label or "").strip() or None,
            datetime.now(timezone.utc).isoformat()
        )
    )

    conn.commit()
    conn.close()


def get_watch_recipients(active_only=False):

    conn = get_connection()

    query = "SELECT * FROM watch_recipients"

    if active_only:
        query += " WHERE active = 1"

    query += " ORDER BY email ASC"

    rows = conn.execute(query).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def set_watch_recipient_active(recipient_id, active):

    conn = get_connection()

    conn.execute(
        "UPDATE watch_recipients SET active = ? WHERE id = ?",
        (1 if active else 0, recipient_id)
    )

    conn.commit()
    conn.close()


def delete_watch_recipient(recipient_id):

    conn = get_connection()

    conn.execute(
        "DELETE FROM watch_recipients WHERE id = ?",
        (recipient_id,)
    )

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# Historique des alertes de veille envoyées
# ---------------------------------------------------------

def record_watch_alert(
    cve_id,
    recipients,
    subject,
    body,
    affected_device_count
):

    conn = get_connection()

    conn.execute(
        """
        INSERT INTO watch_alerts (
            cve_id, recipients, subject, body,
            affected_device_count, sent_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            cve_id,
            ", ".join(recipients),
            subject,
            body,
            affected_device_count,
            datetime.now(timezone.utc).isoformat()
        )
    )

    conn.commit()
    conn.close()


def get_watch_alert_history(limit=200):

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT * FROM watch_alerts
        ORDER BY sent_at DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


# =========================================================
# NVD COMME SOURCE PRINCIPALE (ingestion quotidienne + croisement XDR)
# =========================================================
#
# Jusqu'ici, `vulnerabilities` n'était peuplée QUE par CISA KEV
# (save_vulnerability), NVD servant seulement à enrichir (CVSS,
# description) les CVE déjà connues via CISA KEV. Cette section fait
# de NVD une source d'ENTRÉE à part entière : chaque jour,
# sync_nvd_feed.py récupère les CVE nouvellement PUBLIÉES par NVD
# (toutes, pas seulement CISA KEV) et les croise avec l'inventaire
# XDR (defender_vulnerabilities) pour ne garder que celles qui
# concernent réellement l'environnement.
#
# CISA KEV garde son rôle actuel intact : si une CVE existe déjà
# (source='CISA KEV'), save_nvd_discovery() ne touche JAMAIS ses
# colonnes d'identité CISA (vendor/product/vulnerability_name/
# source/due_date/...) — seules les colonnes d'enrichissement NVD
# (cvss_v3_*, nvd_description, ...) sont rafraîchies, exactement
# comme update_nvd_enrichment() le fait déjà ailleurs.

NVD_API_KEY_CONFIG_KEY = "nvd_api_key"


def get_nvd_api_key():

    return get_app_config(NVD_API_KEY_CONFIG_KEY, "")


def set_nvd_api_key(api_key):

    # Comme pour le SMTP/Hexiosec : ne jamais écraser une clé déjà
    # enregistrée par une valeur vide (champ laissé vide volontairement).
    if api_key:
        set_app_config(NVD_API_KEY_CONFIG_KEY, api_key)


def _priority_from_cvss_severity(severity):

    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW"
    }

    return mapping.get((severity or "").upper(), "UNKNOWN")


def save_nvd_discovery(cve_id, enrichment):
    """
    Ingestion quotidienne NVD (source principale) pour UNE CVE :

    1) Garantit que la ligne existe dans `vulnerabilities`, SANS
       jamais écraser une entrée déjà présente (notamment une CVE
       CISA KEV — son `source`, sa priorité CISA etc. restent
       intacts). Si la ligne n'existe pas du tout, elle est créée
       avec source='NVD' et une priorité dérivée de la sévérité CVSS
       NVD (faute de classification CISA pour une CVE qui n'y est
       pas).
    2) Rafraîchit ENSUITE, dans tous les cas, les colonnes
       d'enrichissement NVD (cvss_v3_*, description, ...) via
       update_nvd_enrichment() — qu'il s'agisse d'une CVE toute
       neuve ou d'une CVE CISA KEV déjà suivie.
    """

    severity = (
        enrichment.get("cvss_v3_severity")
        or enrichment.get("cvss_v4_severity")
    )

    cvss = (
        enrichment.get("cvss_v3_score")
        or enrichment.get("cvss_v4_score")
        or 0
    )

    conn = get_connection()

    conn.execute(
        """
        INSERT INTO vulnerabilities (
            cve_id, vulnerability_name, description,
            date_added, source, risk_score, priority
        )
        VALUES (?, NULL, ?, ?, 'NVD', ?, ?)
        ON CONFLICT(cve_id) DO NOTHING
        """,
        (
            cve_id,
            enrichment.get("nvd_description"),
            enrichment.get("nvd_published"),
            int(round(cvss * 10)) if cvss else 0,
            _priority_from_cvss_severity(severity)
        )
    )

    conn.commit()
    conn.close()

    update_nvd_enrichment(cve_id, enrichment)


def get_cve_ids_present_in_defender(cve_ids):
    """
    Parmi une liste de CVE ID (ex: celles tout juste récupérées de
    NVD aujourd'hui), lesquelles existent déjà dans l'inventaire XDR
    (defender_vulnerabilities) — c'est la "correspondance" recherchée
    par la synchro NVD quotidienne.
    """

    if not cve_ids:
        return []

    conn = get_connection()

    placeholders = ", ".join("?" for _ in cve_ids)

    rows = conn.execute(
        f"""
        SELECT DISTINCT cve_id
        FROM defender_vulnerabilities
        WHERE cve_id IN ({placeholders})
        """,
        list(cve_ids)
    ).fetchall()

    conn.close()

    return [row["cve_id"] for row in rows]


def get_detection_context_for_cve(cve_id):
    """
    Même forme qu'une ligne de get_recent_defender_detections(), mais
    pour UNE SEULE CVE en correspondance exacte (pas de LIKE flou) —
    utilisé par sync_nvd_feed.py pour construire l'e-mail d'alerte
    automatique sur une correspondance NVD <-> XDR.
    """

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            d.cve_id,

            MAX(d.software_vendor) AS software_vendor,
            MAX(d.software_name) AS software_name,

            MAX(d.defender_severity) AS defender_severity,
            MAX(d.cvss_score) AS defender_cvss_score,
            MAX(d.exploitability_level) AS exploitability_level,

            COUNT(DISTINCT d.device_id) AS affected_devices,
            SUM(d.security_update_available) AS devices_with_update_available,
            MAX(d.recommended_security_update) AS recommended_security_update,

            MIN(d.first_seen_timestamp) AS first_seen,
            MAX(d.last_seen_timestamp) AS last_seen,

            MAX(v.source) AS cisa_source,
            MAX(v.priority) AS cisa_priority,
            MAX(v.vulnerability_name) AS vulnerability_name,
            MAX(v.cvss_v3_score) AS nvd_cvss_v3_score,
            MAX(v.nvd_published) AS nvd_published,
            MAX(v.due_date) AS cisa_due_date

        FROM defender_vulnerabilities d

        LEFT JOIN vulnerabilities v
            ON v.cve_id = d.cve_id

        WHERE d.cve_id = ?

        GROUP BY d.cve_id
        """,
        (cve_id,)
    ).fetchone()

    conn.close()

    return dict(row) if row else None


def get_cvss_lookup():
    """
    {cve_id: {"cvss_v3_score", "cvss_v4_score", "nvd_published"}} pour
    toute CVE déjà enrichie en base.

    Utilisé par sync.py : le flux CISA KEV brut (collectors/cisa.py)
    ne contient NI score CVSS NI date de publication NVD, donc
    calculate_risk() ne peut jamais dépasser le palier MEDIUM en se
    basant uniquement dessus (30 pts KEV + 20 pts ransomware max,
    alors que HIGH démarre à 60). Résultat sans ce correctif : CHAQUE
    resynchro CISA périodique (toutes les ~12h) écrasait la priorité
    CRITICAL/HIGH d'une CVE déjà enrichie en la ramenant à MEDIUM/LOW,
    même si son CVSS réel justifiait un niveau plus élevé. En
    fournissant ce CVSS déjà connu à calculate_risk(), la priorité
    recalculée à chaque sync reste cohérente avec l'enrichissement
    déjà en base plutôt que de repartir de zéro.
    """

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT cve_id, cvss_v3_score, cvss_v4_score, nvd_published
        FROM vulnerabilities
        WHERE cvss_v3_score IS NOT NULL OR cvss_v4_score IS NOT NULL
        """
    ).fetchall()

    conn.close()

    return {
        row["cve_id"]: {
            "cvss_v3_score": row["cvss_v3_score"],
            "cvss_v4_score": row["cvss_v4_score"],
            "nvd_published": row["nvd_published"]
        }
        for row in rows
    }


# =========================================================
# NVD HISTORICAL BACKFILL (téléchargement initial depuis 2020)
# =========================================================
#
# Au tout premier lancement, en plus du flux quotidien (nouvelles
# publications), on rapatrie l'historique complet NVD depuis le
# 1er janvier 2020 -- par fenêtres successives (voir
# sync_nvd_backfill.py, qui réutilise fetch_recent_nvd_cves()).
# Potentiellement plusieurs milliers de pages : le curseur ci-dessous
# permet de reprendre exactement où on s'est arrêté si l'appli est
# redémarrée ou si la synchro est interrompue, sans tout retélécharger.

NVD_BACKFILL_START_KEY = "nvd_backfill_start"
NVD_BACKFILL_CURSOR_KEY = "nvd_backfill_cursor"
NVD_BACKFILL_DONE_KEY = "nvd_backfill_done"

# Point de départ par défaut (modifiable via l'interface avant le
# premier lancement de la synchro, sinon fixé une fois pour toutes au
# premier passage).
DEFAULT_NVD_BACKFILL_START = "2020-01-01T00:00:00+00:00"


def get_nvd_backfill_start():

    return get_app_config(
        NVD_BACKFILL_START_KEY,
        DEFAULT_NVD_BACKFILL_START
    )


def set_nvd_backfill_start(start_iso):
    # N'a d'effet que tant que la synchro n'a pas encore commencé à
    # avancer (pas de curseur enregistré) -- changer la date de
    # départ en cours de route n'aurait pas de sens.
    if not get_app_config(NVD_BACKFILL_CURSOR_KEY):
        set_app_config(NVD_BACKFILL_START_KEY, start_iso)


def get_nvd_backfill_cursor():
    """
    Prochaine date de début de fenêtre à traiter. None si la synchro
    n'a encore jamais avancé (démarrera depuis get_nvd_backfill_start()).
    """

    return get_app_config(NVD_BACKFILL_CURSOR_KEY, None)


def set_nvd_backfill_cursor(cursor_iso):

    set_app_config(NVD_BACKFILL_CURSOR_KEY, cursor_iso)


def is_nvd_backfill_done():

    return get_app_config(NVD_BACKFILL_DONE_KEY, "0") == "1"


def mark_nvd_backfill_done():

    set_app_config(NVD_BACKFILL_DONE_KEY, "1")


def reset_nvd_backfill():
    """
    Relance l'historique complet depuis zéro (bouton "Relancer" côté
    interface) -- n'efface aucune CVE déjà en base, le réimport est
    sans danger (ON CONFLICT DO NOTHING sur l'identité, voir
    save_nvd_discovery()).
    """

    conn = get_connection()
    conn.execute(
        "DELETE FROM app_config WHERE key IN (?, ?)",
        (NVD_BACKFILL_CURSOR_KEY, NVD_BACKFILL_DONE_KEY)
    )
    conn.commit()
    conn.close()


# =========================================================
# SYNCHRO NVD : CURSEUR ET ÉTAT DE LA BASE
# =========================================================
#
# La synchro quotidienne repartait de sync_state.last_run_at, qui avance
# aussi quand la synchro ÉCHOUE : les CVE publiées pendant une fenêtre
# ratée n'étaient jamais récupérées. Le curseur ci-dessous n'avance
# qu'après une fenêtre téléchargée et enregistrée avec succès.

NVD_FEED_CURSOR_KEY = "nvd_feed_covered_until"
NVD_AUDIT_REPORT_KEY = "nvd_audit_report"


def get_nvd_feed_cursor():

    return get_app_config(NVD_FEED_CURSOR_KEY)


def set_nvd_feed_cursor(covered_until_iso):

    set_app_config(NVD_FEED_CURSOR_KEY, covered_until_iso)


def get_known_cve_ids(cve_ids):
    """Sous-ensemble de cve_ids déjà présent dans `vulnerabilities`."""

    cve_ids = list(cve_ids)
    known = set()

    if not cve_ids:
        return known

    conn = get_connection()

    for i in range(0, len(cve_ids), 900):

        chunk = cve_ids[i:i + 900]
        placeholders = ", ".join("?" for _ in chunk)

        known.update(
            row[0]
            for row in conn.execute(
                f"SELECT cve_id FROM vulnerabilities "
                f"WHERE cve_id IN ({placeholders})",
                chunk
            )
        )

    conn.close()

    return known


def count_cves_by_published_day(start_day, end_day):
    """
    {"AAAA-MM-JJ": {"total", "with_cpe", "unchecked"}} pour les CVE de la
    base dont la date de publication NVD (UTC, format NVD
    "AAAA-MM-JJTHH:MM:SS.mmm") tombe entre start_day et end_day inclus
    (objets date). Toutes sources confondues.

      - total     : CVE présentes ;
      - with_cpe  : dont les produits vulnérables NVD sont connus ;
      - unchecked : dont les produits n'ont jamais été récupérés (à
                    compléter ; une CVE pas encore analysée par NVD n'a
                    pas de produits mais n'est pas "à compléter").
    """

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            substr(v.nvd_published, 1, 10) AS day,
            COUNT(*) AS total,
            SUM(
                EXISTS (SELECT 1 FROM nvd_cpe_matches c WHERE c.cve_id = v.cve_id)
            ) AS with_cpe,
            SUM(v.cpe_checked_at IS NULL) AS unchecked
        FROM vulnerabilities v
        WHERE v.nvd_published >= ? AND v.nvd_published < ?
        GROUP BY day
        """,
        (
            start_day.isoformat(),
            (end_day + timedelta(days=1)).isoformat()
        )
    ).fetchall()

    conn.close()

    return {
        row["day"]: {
            "total": row["total"],
            "with_cpe": row["with_cpe"] or 0,
            "unchecked": row["unchecked"] or 0
        }
        for row in rows
    }


def get_day_refreshed_at(day):
    """
    Date de la plus ancienne mise à jour NVD des CVE publiées ce jour-là
    (cpe_checked_at), ou None si l'une d'elles n'a jamais été mise à jour
    (ou s'il n'y en a aucune).
    """

    conn = get_connection()

    row = conn.execute(
        """
        SELECT COUNT(*), SUM(cpe_checked_at IS NULL), MIN(cpe_checked_at)
        FROM vulnerabilities
        WHERE nvd_published >= ? AND nvd_published < ?
        """,
        (day.isoformat(), (day + timedelta(days=1)).isoformat())
    ).fetchone()

    conn.close()

    if not row[0] or row[1]:
        return None

    return row[2]


def count_cves_without_cpe_check():
    """CVE dont les produits vulnérables NVD n'ont jamais été récupérés."""

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            SUM(cpe_checked_at IS NULL),
            MIN(CASE WHEN cpe_checked_at IS NULL THEN nvd_published END)
        FROM vulnerabilities
        -- Sans date de publication NVD (CVE CISA pas encore enrichie),
        -- rien à télécharger par date : l'enrichissement NVD s'en charge.
        WHERE nvd_published IS NOT NULL
        """
    ).fetchone()

    conn.close()

    return row[0] or 0, row[1]


def get_nvd_audit_report():

    raw = get_app_config(NVD_AUDIT_REPORT_KEY)

    if not raw:
        return None

    try:
        return json.loads(raw)
    except ValueError:
        return None


def set_nvd_audit_report(report):

    set_app_config(NVD_AUDIT_REPORT_KEY, json.dumps(report))


# =========================================================
# ONGLET "CVE NVD" : RECHERCHE DANS TOUTE LA BASE
# =========================================================

NVD_SEARCH_SORTS = {
    "published_desc": "v.nvd_published DESC, v.cve_id DESC",
    "published_asc": "v.nvd_published IS NULL, v.nvd_published ASC, v.cve_id ASC",
    "score_desc": (
        "COALESCE(v.cvss_v3_score, v.cvss_v4_score) IS NULL, "
        "COALESCE(v.cvss_v3_score, v.cvss_v4_score) DESC, "
        "v.nvd_published DESC"
    ),
    "modified_desc": "v.nvd_last_modified DESC, v.cve_id DESC"
}

# Colonnes textuelles parcourues par la recherche libre.
_NVD_SEARCH_COLUMNS = (
    "v.cve_id",
    "v.nvd_description",
    "v.description",
    "v.vulnerability_name",
    "v.vendor",
    "v.product",
    "v.cwe"
)


def search_nvd_cves(
    search=None,
    published_from=None,
    published_to=None,
    severities=None,
    min_score=None,
    on_parc_only=False,
    kev_only=False,
    sort="published_desc",
    limit=100,
    offset=0
):
    """
    Recherche dans TOUTE la table vulnerabilities (CVE NVD et CISA KEV),
    filtrée et paginée côté base : plusieurs centaines de milliers de
    CVE, impossible de tout envoyer au navigateur.

    - search : identifiant exact ("CVE-2024-1234") ou mots-clés ; chaque
      mot doit apparaître dans l'ID, la description, le nom CISA,
      l'éditeur/produit CISA ou le CWE ;
    - published_from / published_to : dates (incluses) de publication NVD ;
    - severities : liste parmi CRITICAL, HIGH, MEDIUM, LOW, NONE
      ("NONE" = pas encore de score) ;
    - min_score : score CVSS minimal (3.1, sinon 4.0) ;
    - on_parc_only : seulement les CVE détectées par Defender ;
    - kev_only : seulement les CVE du catalogue CISA KEV.

    Retourne (nombre total de résultats, liste de dicts de la page).
    """

    _ensure_defender_cve_summary()

    where = []
    params = []

    search = (search or "").strip()

    if search:

        if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,}", search):

            where.append("v.cve_id = ?")
            params.append(search.upper())

        else:

            for word in search.split():

                like = f"%{word}%"
                where.append(
                    "("
                    + " OR ".join(f"{col} LIKE ?" for col in _NVD_SEARCH_COLUMNS)
                    + ")"
                )
                params.extend([like] * len(_NVD_SEARCH_COLUMNS))

    if published_from:
        where.append("v.nvd_published >= ?")
        params.append(published_from.isoformat())

    if published_to:
        where.append("v.nvd_published < ?")
        params.append((published_to + timedelta(days=1)).isoformat())

    if severities:

        severity_sql = "UPPER(COALESCE(v.cvss_v3_severity, v.cvss_v4_severity))"
        conditions = []
        named = [s for s in severities if s != "NONE"]

        if named:
            conditions.append(
                f"{severity_sql} IN ({', '.join('?' for _ in named)})"
            )
            params.extend(named)

        if "NONE" in severities:
            conditions.append(
                "(v.cvss_v3_severity IS NULL AND v.cvss_v4_severity IS NULL)"
            )

        where.append("(" + " OR ".join(conditions) + ")")

    if min_score:
        where.append("COALESCE(v.cvss_v3_score, v.cvss_v4_score) >= ?")
        params.append(float(min_score))

    if on_parc_only:
        where.append("s.cve_id IS NOT NULL")

    if kev_only:
        where.append("v.source = 'CISA KEV'")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    from_sql = """
        FROM vulnerabilities v
        LEFT JOIN defender_cve_summary s
            ON s.cve_id = v.cve_id
    """

    conn = get_connection()

    total = conn.execute(
        f"SELECT COUNT(*) {from_sql} {where_sql}",
        params
    ).fetchone()[0]

    rows = conn.execute(
        f"""
        SELECT
            v.cve_id,
            v.nvd_published,
            v.nvd_last_modified,
            COALESCE(v.cvss_v3_severity, v.cvss_v4_severity) AS severity,
            v.cvss_v3_score,
            v.cvss_v4_score,
            v.cwe,
            v.source,
            COALESCE(s.affected_devices, 0) AS affected_devices,
            COALESCE(v.nvd_description, v.description) AS description
        {from_sql}
        {where_sql}
        ORDER BY {NVD_SEARCH_SORTS.get(sort, NVD_SEARCH_SORTS["published_desc"])}
        LIMIT ? OFFSET ?
        """,
        params + [int(limit), int(offset)]
    ).fetchall()

    conn.close()

    return total, [dict(row) for row in rows]


def get_cve_details(cve_id):
    """Toutes les colonnes d'une CVE + son exposition Defender."""

    _ensure_defender_cve_summary()

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            v.*,
            COALESCE(s.affected_devices, 0) AS parc_devices,
            COALESCE(s.affected_products, 0) AS parc_products,
            s.first_seen AS parc_first_seen,
            s.last_seen AS parc_last_seen
        FROM vulnerabilities v
        LEFT JOIN defender_cve_summary s
            ON s.cve_id = v.cve_id
        WHERE v.cve_id = ?
        """,
        (cve_id,)
    ).fetchone()

    conn.close()

    return dict(row) if row else None


# =========================================================
# INVENTAIRE LOGICIEL x NVD : LECTURE POUR L'INTERFACE
# =========================================================

def get_inventory_status():
    """Chiffres de l'inventaire et de la couverture produits NVD."""

    conn = get_connection()

    inventory = conn.execute(
        """
        SELECT
            COUNT(*) AS rows_count,
            COUNT(DISTINCT device_id) AS devices,
            COUNT(DISTINCT cpe_vendor || ':' || cpe_product) AS products,
            MAX(imported_at) AS imported_at
        FROM software_inventory
        """
    ).fetchone()

    cves_with_cpe = conn.execute(
        "SELECT COUNT(DISTINCT cve_id) FROM nvd_cpe_matches"
    ).fetchone()[0]

    total_cves = conn.execute(
        "SELECT COUNT(*) FROM vulnerabilities"
    ).fetchone()[0]

    matched = conn.execute(
        "SELECT COUNT(*) FROM inventory_cve_summary"
    ).fetchone()[0]

    affected_devices = conn.execute(
        """
        SELECT COUNT(DISTINCT i.device_id)
        FROM inventory_cve_matches m
        JOIN software_inventory i
            ON i.cpe_vendor = m.cpe_vendor
            AND i.cpe_product = m.cpe_product
            AND i.software_version = m.software_version
        """
    ).fetchone()[0]

    conn.close()

    return {
        "inventory_rows": inventory["rows_count"],
        "inventory_devices": inventory["devices"],
        "inventory_products": inventory["products"],
        "inventory_imported_at": inventory["imported_at"],
        "cves_with_cpe": cves_with_cpe,
        "total_cves": total_cves,
        "matched_cves": matched,
        "affected_devices": affected_devices
    }


def get_inventory_matched_cves(search=None, limit=200):
    """
    CVE touchant au moins une machine selon l'inventaire x NVD, les plus
    récentes d'abord, avec en regard le nombre de machines selon Defender.
    """

    _ensure_defender_cve_summary()

    where = ""
    params = []

    if search:
        like = f"%{search.strip()}%"
        where = """
            WHERE s.cve_id LIKE ?
               OR v.nvd_description LIKE ?
               OR s.cve_id IN (
                   SELECT cve_id FROM inventory_cve_matches
                   WHERE cpe_vendor LIKE ? OR cpe_product LIKE ?
               )
        """
        params = [like, like, like, like]

    conn = get_connection()

    rows = conn.execute(
        f"""
        SELECT
            s.cve_id,
            v.nvd_published,
            COALESCE(v.cvss_v3_severity, v.cvss_v4_severity) AS severity,
            COALESCE(v.cvss_v3_score, v.cvss_v4_score) AS cvss,
            s.affected_devices,
            s.affected_products,
            COALESCE(d.affected_devices, 0) AS defender_devices,
            v.source,
            (
                SELECT GROUP_CONCAT(DISTINCT m.cpe_vendor || ' ' || m.cpe_product)
                FROM inventory_cve_matches m
                WHERE m.cve_id = s.cve_id
            ) AS products,
            COALESCE(v.nvd_description, v.description) AS description
        FROM inventory_cve_summary s
        LEFT JOIN vulnerabilities v ON v.cve_id = s.cve_id
        LEFT JOIN defender_cve_summary d ON d.cve_id = s.cve_id
        {where}
        ORDER BY v.nvd_published DESC, s.cve_id DESC
        LIMIT ?
        """,
        params + [int(limit)]
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_inventory_devices_for_cve(cve_id):
    """Machines touchées par une CVE selon l'inventaire x NVD."""

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT DISTINCT
            i.device_name,
            i.os_platform,
            i.os_version,
            i.software_vendor,
            i.software_name,
            i.software_version,
            m.rule,
            i.end_of_support_status,
            CASE WHEN i.distro_package = 1 THEN 'Paquet Linux : vérifier le changelog (correctif rétroporté possible)' ELSE '' END AS distro_note
        FROM inventory_cve_matches m
        JOIN software_inventory i
            ON i.cpe_vendor = m.cpe_vendor
            AND i.cpe_product = m.cpe_product
            AND i.software_version = m.software_version
        WHERE m.cve_id = ?
        ORDER BY i.device_name
        """,
        (cve_id,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_inventory_device_count(cve_id):

    conn = get_connection()

    row = conn.execute(
        "SELECT affected_devices FROM inventory_cve_summary WHERE cve_id = ?",
        (cve_id,)
    ).fetchone()

    conn.close()

    return row[0] if row else 0


# =========================================================
# ONGLET "INVENTAIRE" : PAR MACHINE / PAR PRODUIT
# =========================================================

# Jointure entre une correspondance (produit, version) -> CVE et les
# machines qui ont ce produit dans cette version.
_MATCH_JOIN = """
    JOIN software_inventory i
        ON i.cpe_vendor = m.cpe_vendor
        AND i.cpe_product = m.cpe_product
        AND i.software_version = m.software_version
"""

_SEVERITY_SQL = "UPPER(COALESCE(v.cvss_v3_severity, v.cvss_v4_severity))"


def get_inventory_machines(search=None):
    """
    Une ligne par machine de l'inventaire : nom, OS, nombre de logiciels,
    logiciels en fin de support, CVE touchant la machine selon NVD (dont
    critiques). `search` filtre sur le nom, l'identifiant ou l'OS.
    """

    conn = get_connection()

    where = ""
    params = []

    if search:
        like = f"%{search.strip()}%"
        where = """
            WHERE device_name LIKE ? OR device_id LIKE ?
               OR os_platform LIKE ? OR os_version LIKE ?
        """
        params = [like] * 4

    machines = conn.execute(
        f"""
        SELECT
            device_id,
            MAX(device_name) AS device_name,
            MAX(os_platform) AS os_platform,
            MAX(os_version) AS os_version,
            MAX(os_architecture) AS os_architecture,
            COUNT(DISTINCT COALESCE(software_vendor, '') || ':'
                  || COALESCE(software_name, '') || ':'
                  || software_version) AS software_count,
            COUNT(DISTINCT CASE
                WHEN COALESCE(end_of_support_status, '') NOT IN ('', 'None')
                THEN COALESCE(software_vendor, '') || ':'
                     || COALESCE(software_name, '') || ':' || software_version
            END) AS eos_count
        FROM software_inventory
        {where}
        GROUP BY device_id
        ORDER BY device_name
        """,
        params
    ).fetchall()

    cves = {
        row["device_id"]: (row["cves"], row["critical"])
        for row in conn.execute(
            f"""
            SELECT
                i.device_id,
                COUNT(DISTINCT m.cve_id) AS cves,
                COUNT(DISTINCT CASE WHEN {_SEVERITY_SQL} = 'CRITICAL'
                      THEN m.cve_id END) AS critical
            FROM inventory_cve_matches m
            {_MATCH_JOIN}
            LEFT JOIN vulnerabilities v ON v.cve_id = m.cve_id
            GROUP BY i.device_id
            """
        )
    }

    conn.close()

    result = []

    for row in machines:
        item = dict(row)
        item["nvd_cves"], item["nvd_critical"] = cves.get(item["device_id"], (0, 0))
        result.append(item)

    return result


def get_inventory_products(search=None):
    """
    Une ligne par produit (éditeur + produit) : nombre de versions et de
    machines, versions installées, fin de support, CVE selon NVD.
    """

    conn = get_connection()

    where = ""
    params = []

    if search:
        like = f"%{search.strip()}%"
        where = """
            WHERE cpe_vendor LIKE ? OR cpe_product LIKE ?
               OR software_vendor LIKE ? OR software_name LIKE ?
        """
        params = [like] * 4

    products = conn.execute(
        f"""
        SELECT
            cpe_vendor,
            cpe_product,
            MAX(software_vendor) AS software_vendor,
            MAX(software_name) AS software_name,
            COUNT(DISTINCT software_version) AS version_count,
            COUNT(DISTINCT device_id) AS device_count,
            GROUP_CONCAT(DISTINCT software_version) AS versions,
            COUNT(DISTINCT CASE
                WHEN COALESCE(end_of_support_status, '') NOT IN ('', 'None')
                THEN device_id
            END) AS eos_installs
        FROM software_inventory
        {where}
        GROUP BY cpe_vendor, cpe_product
        ORDER BY device_count DESC
        """,
        params
    ).fetchall()

    cves = {
        (row["cpe_vendor"], row["cpe_product"]): (row["cves"], row["critical"])
        for row in conn.execute(
            f"""
            SELECT
                m.cpe_vendor,
                m.cpe_product,
                COUNT(DISTINCT m.cve_id) AS cves,
                COUNT(DISTINCT CASE WHEN {_SEVERITY_SQL} = 'CRITICAL'
                      THEN m.cve_id END) AS critical
            FROM inventory_cve_matches m
            LEFT JOIN vulnerabilities v ON v.cve_id = m.cve_id
            GROUP BY m.cpe_vendor, m.cpe_product
            """
        )
    }

    conn.close()

    result = []

    for row in products:
        item = dict(row)
        item["nvd_cves"], item["nvd_critical"] = cves.get(
            (item["cpe_vendor"], item["cpe_product"]), (0, 0)
        )
        result.append(item)

    return result


def get_machine_software(device_id):
    """Logiciels installés sur une machine, avec les CVE NVD de chaque version."""

    conn = get_connection()

    rows = conn.execute(
        f"""
        SELECT
            i.software_vendor,
            i.software_name,
            i.software_version,
            i.cpe_vendor || ':' || i.cpe_product AS cpe,
            i.end_of_support_status,
            NULLIF(i.end_of_support_date, 'Invalid date') AS end_of_support_date,
            COUNT(DISTINCT m.cve_id) AS nvd_cves,
            COUNT(DISTINCT CASE WHEN {_SEVERITY_SQL} = 'CRITICAL'
                  THEN m.cve_id END) AS nvd_critical,
            MAX(COALESCE(v.cvss_v3_score, v.cvss_v4_score)) AS max_cvss
        FROM software_inventory i
        LEFT JOIN inventory_cve_matches m
            ON m.cpe_vendor = i.cpe_vendor
            AND m.cpe_product = i.cpe_product
            AND m.software_version = i.software_version
        LEFT JOIN vulnerabilities v ON v.cve_id = m.cve_id
        WHERE i.device_id = ?
        -- Une ligne par logiciel / paquet réel : plusieurs paquets Linux
        -- (php8.3-common, php8.3-cli...) peuvent être reliés au même
        -- produit NVD, ils restent listés séparément.
        GROUP BY i.software_vendor, i.software_name, i.software_version
        ORDER BY nvd_critical DESC, nvd_cves DESC, i.software_vendor, i.software_name
        """,
        (device_id,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_machine_nvd_cves(device_id):
    """CVE touchant une machine selon NVD, avec le logiciel concerné."""

    conn = get_connection()

    rows = conn.execute(
        f"""
        SELECT
            m.cve_id,
            v.nvd_published,
            {_SEVERITY_SQL} AS severity,
            COALESCE(v.cvss_v3_score, v.cvss_v4_score) AS cvss,
            v.source,
            i.software_name,
            i.software_version,
            m.rule,
            CASE WHEN i.distro_package = 1 THEN 'Paquet Linux : vérifier le changelog (correctif rétroporté possible)' ELSE '' END AS distro_note,
            COALESCE(v.nvd_description, v.description) AS description
        FROM inventory_cve_matches m
        {_MATCH_JOIN}
        LEFT JOIN vulnerabilities v ON v.cve_id = m.cve_id
        WHERE i.device_id = ?
        ORDER BY cvss DESC, v.nvd_published DESC
        """,
        (device_id,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_machine_defender_cves(device_id):
    """CVE détectées par Defender sur une machine (dernier import Defender)."""

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            d.cve_id,
            d.software_name,
            d.software_version,
            d.defender_severity,
            d.cvss_score,
            d.exploitability_level,
            d.recommended_security_update,
            d.first_seen_timestamp,
            CASE WHEN v.source = 'CISA KEV' THEN 'Oui' ELSE '' END AS kev
        FROM defender_vulnerabilities d
        LEFT JOIN vulnerabilities v ON v.cve_id = d.cve_id
        WHERE d.device_id = ?
        ORDER BY d.cvss_score DESC
        """,
        (device_id,)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_product_versions(cpe_vendor, cpe_product):
    """Versions installées d'un produit : machines, fin de support, CVE NVD."""

    conn = get_connection()

    rows = conn.execute(
        f"""
        SELECT
            i.software_version,
            COUNT(DISTINCT i.device_id) AS device_count,
            MAX(i.end_of_support_status) AS end_of_support_status,
            MAX(NULLIF(i.end_of_support_date, 'Invalid date')) AS end_of_support_date,
            (
                SELECT COUNT(DISTINCT m.cve_id)
                FROM inventory_cve_matches m
                WHERE m.cpe_vendor = i.cpe_vendor
                  AND m.cpe_product = i.cpe_product
                  AND m.software_version = i.software_version
            ) AS nvd_cves,
            (
                SELECT MAX(COALESCE(v.cvss_v3_score, v.cvss_v4_score))
                FROM inventory_cve_matches m
                JOIN vulnerabilities v ON v.cve_id = m.cve_id
                WHERE m.cpe_vendor = i.cpe_vendor
                  AND m.cpe_product = i.cpe_product
                  AND m.software_version = i.software_version
            ) AS max_cvss
        FROM software_inventory i
        WHERE i.cpe_vendor = ? AND i.cpe_product = ?
        GROUP BY i.software_version
        ORDER BY device_count DESC
        """,
        (cpe_vendor, cpe_product)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_product_machines(cpe_vendor, cpe_product):
    """Machines ayant un produit installé, avec la version."""

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT DISTINCT
            device_name,
            device_id,
            os_platform,
            os_version,
            software_version,
            end_of_support_status,
            software_name,
            CASE WHEN distro_package = 1
                 THEN 'Paquet Linux : vérifier le changelog (correctif rétroporté possible)'
                 ELSE '' END AS distro_note
        FROM software_inventory
        WHERE cpe_vendor = ? AND cpe_product = ?
        ORDER BY device_name
        """,
        (cpe_vendor, cpe_product)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_product_nvd_cves(cpe_vendor, cpe_product):
    """CVE touchant un produit (versions installées) selon NVD."""

    conn = get_connection()

    rows = conn.execute(
        f"""
        SELECT
            m.cve_id,
            v.nvd_published,
            {_SEVERITY_SQL} AS severity,
            COALESCE(v.cvss_v3_score, v.cvss_v4_score) AS cvss,
            v.source,
            GROUP_CONCAT(DISTINCT m.software_version) AS versions,
            MAX(m.rule) AS rule,
            COALESCE(v.nvd_description, v.description) AS description
        FROM inventory_cve_matches m
        LEFT JOIN vulnerabilities v ON v.cve_id = m.cve_id
        WHERE m.cpe_vendor = ? AND m.cpe_product = ?
        GROUP BY m.cve_id
        ORDER BY cvss DESC, v.nvd_published DESC
        """,
        (cpe_vendor, cpe_product)
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


# =========================================================
# ALERTES DE VEILLE : DÉDOUBLONNAGE
# =========================================================

def _filter_cve_ids(sql, cve_ids, extra_params=()):
    """Exécute `sql` (avec {placeholders}) par paquets, retourne un set."""

    cve_ids = list(dict.fromkeys(cve_ids))
    found = set()

    if not cve_ids:
        return found

    conn = get_connection()

    for start in range(0, len(cve_ids), 900):

        chunk = cve_ids[start:start + 900]
        placeholders = ", ".join("?" for _ in chunk)

        found.update(
            row[0] for row in conn.execute(
                sql.format(placeholders=placeholders),
                chunk + list(extra_params)
            )
        )

    conn.close()

    return found


def get_alerted_cve_ids(cve_ids):
    """CVE ayant déjà fait l'objet d'une alerte de veille."""

    return _filter_cve_ids(
        "SELECT DISTINCT cve_id FROM watch_alerts "
        "WHERE cve_id IN ({placeholders})",
        cve_ids
    )


def get_inventory_matched_cve_ids(cve_ids):
    """CVE touchant au moins une machine selon l'inventaire x NVD."""

    return _filter_cve_ids(
        "SELECT cve_id FROM inventory_cve_summary "
        "WHERE cve_id IN ({placeholders})",
        cve_ids
    )


def get_cve_ids_published_since(cve_ids, days):
    """CVE publiées par NVD depuis moins de `days` jours."""

    since = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()

    return _filter_cve_ids(
        "SELECT cve_id FROM vulnerabilities "
        "WHERE cve_id IN ({placeholders}) AND nvd_published >= ?",
        cve_ids,
        (since,)
    )


def get_nvd_total_count():

    conn = get_connection()

    row = conn.execute(
        "SELECT COUNT(*) AS n FROM vulnerabilities WHERE source = 'NVD'"
    ).fetchone()

    conn.close()

    return row["n"] if row else 0


def _replace_cpe_matches(conn, cve_id, cpe_matches):

    conn.execute("DELETE FROM nvd_cpe_matches WHERE cve_id = ?", (cve_id,))

    conn.execute(
        "UPDATE vulnerabilities SET cpe_checked_at = ? WHERE cve_id = ?",
        (datetime.now(timezone.utc).isoformat(), cve_id)
    )

    if cpe_matches:
        conn.executemany(
            """
            INSERT INTO nvd_cpe_matches (
                cve_id, part, vendor, product, version,
                version_start_including, version_start_excluding,
                version_end_including, version_end_excluding
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    cve_id, m["part"], m["vendor"], m["product"], m["version"],
                    m["version_start_including"], m["version_start_excluding"],
                    m["version_end_including"], m["version_end_excluding"]
                )
                for m in cpe_matches
            ]
        )


def bulk_save_nvd_discoveries(discoveries):
    """
    Import en masse de CVE NVD (fichier téléchargé manuellement et
    envoyé via l'onglet Veille, voir parse_nvd_feed_bytes()) : UNE
    seule connexion/transaction pour tout le lot au lieu d'un
    aller-retour par CVE (save_nvd_discovery) -- nettement plus
    rapide pour un fichier de plusieurs dizaines de milliers
    d'entrées (flux annuel complet nvd.nist.gov/vuln/data-feeds).

    Mêmes garanties que save_nvd_discovery() : une CVE déjà connue
    (notamment source='CISA KEV') ne voit jamais son identité
    écrasée -- seul son enrichissement NVD (CVSS, description, ...)
    est rafraîchi.

    Retourne le nombre de CVE traitées.
    """

    conn = get_connection()

    processed = 0

    for cve_id, enrichment in discoveries:

        severity = (
            enrichment.get("cvss_v3_severity")
            or enrichment.get("cvss_v4_severity")
        )

        cvss = (
            enrichment.get("cvss_v3_score")
            or enrichment.get("cvss_v4_score")
            or 0
        )

        conn.execute(
            """
            INSERT INTO vulnerabilities (
                cve_id, vulnerability_name, description,
                date_added, source, risk_score, priority
            )
            VALUES (?, NULL, ?, ?, 'NVD', ?, ?)
            ON CONFLICT(cve_id) DO NOTHING
            """,
            (
                cve_id,
                enrichment.get("nvd_description"),
                enrichment.get("nvd_published"),
                int(round(cvss * 10)) if cvss else 0,
                _priority_from_cvss_severity(severity)
            )
        )

        conn.execute("""
            UPDATE vulnerabilities

            SET

                cvss_v3_score = ?,
                cvss_v3_severity = ?,
                cvss_v3_vector = ?,

                cvss_v4_score = ?,
                cvss_v4_severity = ?,
                cvss_v4_vector = ?,

                cwe = ?,

                nvd_description = ?,

                nvd_published = ?,
                nvd_last_modified = ?,

                nvd_enriched = 1,
                nvd_enriched_at = ?,

                nvd_status = 'OK',
                nvd_last_error = NULL

            WHERE cve_id = ?
        """, (
            enrichment.get("cvss_v3_score"),
            enrichment.get("cvss_v3_severity"),
            enrichment.get("cvss_v3_vector"),
            enrichment.get("cvss_v4_score"),
            enrichment.get("cvss_v4_severity"),
            enrichment.get("cvss_v4_vector"),
            enrichment.get("cwe"),
            enrichment.get("nvd_description"),
            enrichment.get("nvd_published"),
            enrichment.get("nvd_last_modified"),
            enrichment.get("nvd_enriched_at"),
            cve_id
        ))

        # Produits vulnérables NVD (configurations CPE) : remplacés à
        # chaque enregistrement, NVD peut les corriger après coup.
        if "cpe_matches" in enrichment:
            _replace_cpe_matches(conn, cve_id, enrichment["cpe_matches"])

        processed += 1

        if processed % 500 == 0:
            conn.commit()

    conn.commit()
    conn.close()

    return processed


def get_nvd_defender_exposure():
    """
    Présence dans l'environnement pour les CVE sourcées NVD
    (source='NVD' dans `vulnerabilities`).

    ATTENTION : contrairement à `cisa_defender_exposure` (remplie par
    build_exposure.py), ce calcul :
      - n'est PAS limité aux CVE CISA KEV (c'est tout l'intérêt ici) ;
      - n'exige PAS que le device ait un propriétaire résolu dans
        asset_owners -- cisa_defender_exposure exclut volontairement
        les équipements "non attribués" car cette table sert aussi au
        ciblage des notifications par propriétaire (voir notify.py),
        alors qu'ici on répond juste à la question "est-ce que
        Microsoft Defender XDR a déjà vu cette CVE quelque part dans
        le parc ?", comme le fait déjà get_cve_ids_present_in_defender()
        utilisé par la synchro quotidienne / l'onglet Veille.

    Sans cette distinction, le tableau de bord affichait TOUJOURS 0
    pour "NVD présentes dans l'environnement", quel que soit le
    nombre de CVE NVD en base : `df` était fusionné uniquement avec
    `cisa_defender_exposure`, qui ne contient par construction aucune
    ligne pour une CVE source='NVD'.

    Retourne {cve_id: {"affected_devices": n, "affected_products": m}}.
    """

    # Lit le résumé précalculé (voir rebuild_defender_cve_summary) au
    # lieu d'agréger les millions de lignes Defender à chaque affichage.
    _ensure_defender_cve_summary()

    conn = get_connection()

    rows = conn.execute("""
        SELECT
            s.cve_id,
            s.affected_devices,
            s.affected_products
        FROM defender_cve_summary s
        INNER JOIN vulnerabilities v
            ON v.cve_id = s.cve_id
        WHERE v.source = 'NVD'
    """).fetchall()

    conn.close()

    return {
        row["cve_id"]: {
            "affected_devices": row["affected_devices"],
            "affected_products": row["affected_products"]
        }
        for row in rows
    }
