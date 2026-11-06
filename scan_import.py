"""
Import d'un scan Nessus (export CSV) dans la rubrique "Scan vulnérabilité".

Reprend la logique du script PowerShell ImportVullns.ps1, qui importait
les scans dans ClickUp, mais écrit dans la base VulnWatch (l'instance
ClickUp est décommissionnée) :

  1. une liste (périmètre : VLANs_Nanterre, ESAM...) est choisie ;
  2. chaque ligne du CSV Nessus est rapprochée des constats existants de
     cette liste, fermés compris : même hôte (nom du constat = colonne
     Host de Nessus), même Plugin ID, même port et, si la ligne a une
     CVE, même CVE ;
  3. selon le statut du constat existant :
       - TRAITÉ ou ATTÉNUÉ -> repasse en RÉDUIRE (vulnérabilité revue
         au scan), échéance recalculée ;
       - RÉDUIRE           -> échéance recalculée ;
       - ACCEPTÉ           -> échéance retirée (risque accepté) ;
       - autre (REFUSÉ...) -> aucun changement ;
     et, dans ces trois cas, commentaire « Date d'import: ... » et date
     du dernier scan mise à jour ;
  4. sans constat existant : nouveau constat (description SYNOPSIS /
     DESCRIPTION / SOLUTION / PLUGIN OUTPUT, nom de la vulnérabilité en
     étiquette, échéance selon le risque), avec le même commentaire.

Échéance à partir de la date d'import : Critical 7 j, High 14 j,
Medium 21 j, Low 42 j.

Hôte : colonne HOST du fichier de correspondance (IP,HOST) ; à défaut,
nom court du FQDN (srv01.domaine.local -> srv01).

Différences volontaires avec le script :
  - une adresse IP absente de la correspondance est gardée entière (le
    script n'en gardait que le premier octet : "10.1.2.3" -> "10") ;
  - deux lignes identiques dans le même CSV ne créent qu'un constat ;
  - les lignes Risk = None (informatives) peuvent être ignorées
    (option, cochée par défaut) ;
  - analyse (aperçu) avant écriture, puis écriture en une transaction.

Ce module ne fait que lire et calculer : l'écriture est faite par
scan_store.apply_scan_import().
"""

import io
import ipaddress
import unicodedata
from datetime import timedelta

import pandas as pd


REQUIRED_COLUMNS = ["Host", "Plugin ID", "CVE", "Port", "Name", "Risk"]

OPTIONAL_COLUMNS = [
    "CVSS v3.0 Base Score", "Synopsis", "Description", "Solution",
    "Plugin Output"
]

# Délai de traitement selon le risque Nessus (jours, depuis l'import).
DUE_DAYS = {"critical": 7, "high": 14, "medium": 21, "low": 42}

ACTION_LABELS = {
    "new": "Nouveau constat",
    "reopen": "Réouvert (TRAITÉ / ATTÉNUÉ -> RÉDUIRE)",
    "refresh": "Mis à jour (RÉDUIRE : échéance recalculée)",
    "accepted": "Mis à jour (ACCEPTÉ : sans échéance)",
    "unchanged": "Inchangé (autre statut)",
    "duplicate": "Ligne en double dans le CSV",
    "info": "Ignoré (Risk = None)"
}


class ScanImportError(ValueError):
    pass


# =========================================================
# LECTURE DES FICHIERS
# =========================================================

def _read_csv(data):

    if hasattr(data, "getvalue"):
        data = data.getvalue()

    for encoding in ("utf-8-sig", "cp1252"):

        try:

            frame = pd.read_csv(
                io.BytesIO(data), sep=",", dtype=str,
                keep_default_na=False, encoding=encoding
            )

            frame.columns = [str(c).strip() for c in frame.columns]

            return frame

        except UnicodeDecodeError:
            continue

    raise ScanImportError("Encodage du fichier non reconnu.")


def read_nessus_csv(data):

    frame = _read_csv(data)

    missing = [c for c in REQUIRED_COLUMNS if c not in frame.columns]

    if missing:
        raise ScanImportError(
            "Colonnes absentes du CSV Nessus : " + ", ".join(missing)
            + ". Colonnes trouvées : " + ", ".join(frame.columns[:20])
        )

    for column in OPTIONAL_COLUMNS:

        if column not in frame.columns:
            frame[column] = ""

    return frame


def read_host_table(data):
    """Fichier de correspondance à 2 colonnes IP,HOST -> {ip: host}."""

    if data is None:
        return {}

    frame = _read_csv(data)

    columns = {c.lower(): c for c in frame.columns}

    if "ip" not in columns or "host" not in columns:
        raise ScanImportError(
            "Le fichier de correspondance doit avoir les colonnes IP et HOST."
        )

    table = {}

    for ip, host in zip(frame[columns["ip"]], frame[columns["host"]]):

        ip, host = str(ip).strip(), str(host).strip()

        if ip and host:
            table[ip.lower()] = host

    return table


# =========================================================
# RÈGLES DU SCRIPT
# =========================================================

def normalize_status(status):
    """« Traité », « TRAITE », « traité » -> « traite »."""

    text = unicodedata.normalize("NFKD", str(status or "").strip().lower())

    return "".join(c for c in text if not unicodedata.combining(c))


def resolve_hostname(srv, host_table):

    found = host_table.get(srv.lower())

    if found:
        return found

    try:
        ipaddress.ip_address(srv)
        return srv
    except ValueError:
        pass

    return srv.split(".")[0] or srv


def due_date_for(risk, now):

    days = DUE_DAYS.get(str(risk or "").strip().lower())

    return (now + timedelta(days=days)).isoformat() if days else None


def build_description(row):

    return (
        f"SYNOPSIS:\n{row['Synopsis']}\n\n"
        f"DESCRIPTION:\n{row['Description']}\n\n"
        f"SOLUTION:\n{row['Solution']}\n\n"
        f"PLUGIN OUTPUT:\n{row['Plugin Output']}"
    )


def _key(value):

    return str(value or "").strip().lower()


def build_import_plan(frame, host_table, existing, now, skip_info=True):
    """
    Calcule, sans rien écrire, l'action de chaque ligne du CSV.

    `existing` : constats de la liste choisie (scan_store.
    get_import_candidates), dicts task_id / title / plugin_id / port /
    cve / status. `now` : date d'import (datetime avec fuseau).

    Retourne {"actions": [...], "counts": {action: n}}. Chaque action :
    {"action", "task_id" (constat existant, sinon None), "row" (valeurs
    à écrire), "status_before"}.
    """

    index = {}

    for finding in existing:

        index.setdefault(
            (
                _key(finding["title"]),
                _key(finding["plugin_id"]),
                _key(finding["port"])
            ),
            []
        ).append(finding)

    actions = []
    created = set()

    for _, line in frame.iterrows():

        srv = str(line["Host"]).strip()
        plugin_id = str(line["Plugin ID"]).strip()
        cve = str(line["CVE"]).strip().upper()
        port = str(line["Port"]).strip()
        risk = str(line["Risk"]).strip()

        if not srv or not plugin_id:
            continue

        row = {
            "srv": srv,
            "host": resolve_hostname(srv, host_table),
            "plugin_id": plugin_id,
            "cve": cve or None,
            "port": port,
            "name": str(line["Name"]).strip(),
            "risk": risk,
            "cvss": str(line["CVSS v3.0 Base Score"]).strip() or None,
            "description": build_description(line),
            "due_date": due_date_for(risk, now)
        }

        if skip_info and risk.lower() in ("none", "info", ""):

            actions.append({
                "action": "info", "task_id": None, "row": row,
                "status_before": None
            })
            continue

        matches = index.get((_key(srv), _key(plugin_id), _key(port)), [])

        if cve:
            matches = [m for m in matches if _key(m["cve"]) == cve.lower()]

        if not matches:

            signature = (_key(srv), _key(plugin_id), _key(port), cve.lower())

            action = "duplicate" if signature in created else "new"

            created.add(signature)

            actions.append({
                "action": action, "task_id": None, "row": row,
                "status_before": None
            })
            continue

        for match in matches:

            status = normalize_status(match["status"])

            if status in ("traite", "attenue"):
                action = "reopen"
            elif status == "reduire":
                action = "refresh"
            elif status == "accepte":
                action = "accepted"
            else:
                action = "unchanged"

            actions.append({
                "action": action, "task_id": match["task_id"], "row": row,
                "status_before": match["status"]
            })

    counts = {key: 0 for key in ACTION_LABELS}

    for action in actions:
        counts[action["action"]] += 1

    return {"actions": actions, "counts": counts}
