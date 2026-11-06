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

Hôte (colonne « Host » de Nessus -> champ hôte) :
  - recherche dans la base de correspondances machine -> hôte
    (scan_host_map, remplie depuis le fichier de correspondance IP;HOST
    du script puis complétée dans l'interface) ;
  - sinon, nom de machine : partie avant le premier point
    (LIEFCS61.alliumfr.Corp.priv -> LIEFCS61, LIEFCS61 -> LIEFCS61) ;
  - sinon, adresse IP sans correspondance : gardée telle quelle et
    signalée dans l'aperçu, pour compléter la base.

Différences volontaires avec le script :
  - correspondances en base au lieu d'un fichier à chaque import ;
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

def _read_csv(data, sep=","):
    """sep=None : séparateur détecté (« ; » d'Excel FR ou « , »)."""

    if hasattr(data, "getvalue"):
        data = data.getvalue()

    for encoding in ("utf-8-sig", "cp1252"):

        try:

            frame = pd.read_csv(
                io.BytesIO(data), sep=sep, dtype=str,
                keep_default_na=False, encoding=encoding,
                engine="python" if sep is None else "c"
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
    """
    Fichier de correspondance du script, 2 colonnes IP;HOST (ou IP,HOST).
    La colonne IP peut aussi contenir un nom de machine (FQDN).

    Retourne (paires, conflits) : paires [(machine, hôte)] dédupliquées,
    la DERNIÈRE ligne d'une machine l'emportant (le fichier est complété
    au fil de l'eau) ; conflits [(machine, ancien hôte, hôte retenu)]
    quand une même machine a deux hôtes différents. Lignes sans hôte
    ignorées.
    """

    frame = _read_csv(data, sep=None)

    columns = {c.lower(): c for c in frame.columns}

    if "ip" not in columns or "host" not in columns:
        raise ScanImportError(
            "Le fichier de correspondance doit avoir les colonnes IP et HOST "
            "(séparées par « ; » ou « , »). Colonnes trouvées : "
            + ", ".join(frame.columns)
        )

    pairs = {}
    conflicts = []

    for machine, host in zip(frame[columns["ip"]], frame[columns["host"]]):

        machine, host = str(machine).strip(), str(host).strip()

        if not machine or not host:
            continue

        key = machine.lower()

        if key in pairs and pairs[key][1] != host:

            if pairs[key][1].lower() != host.lower():
                conflicts.append((machine, pairs[key][1], host))

        pairs[key] = (machine, host)

    return list(pairs.values()), conflicts


# =========================================================
# RÈGLES DU SCRIPT
# =========================================================

def normalize_status(status):
    """« Traité », « TRAITE », « traité » -> « traite »."""

    text = unicodedata.normalize("NFKD", str(status or "").strip().lower())

    return "".join(c for c in text if not unicodedata.combining(c))


def is_ip_address(value):

    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def resolve_hostname(srv, host_map):
    """
    `host_map` : {machine en minuscules: hôte} (scan_store.get_host_map).
    Retourne (hôte, trouvé_en_base).
    """

    srv = str(srv).strip()

    found = host_map.get(srv.lower())

    if found:
        return found, True

    if is_ip_address(srv):
        return srv, False

    # x.alliumfr.Corp.priv (ou tout FQDN) -> x ; x -> x
    return srv.split(".")[0] or srv, False


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


def build_import_plan(frame, host_map, existing, now, skip_info=True):
    """
    Calcule, sans rien écrire, l'action de chaque ligne du CSV.

    `existing` : constats de la liste choisie (scan_store.
    get_import_candidates), dicts task_id / title / plugin_id / port /
    cve / status. `now` : date d'import (datetime avec fuseau).

    `host_map` : correspondances machine -> hôte (scan_store.get_host_map).

    Retourne {"actions": [...], "counts": {action: n}, "unmapped_ips":
    [...]}. Chaque action :
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
    unmapped_ips = []

    for _, line in frame.iterrows():

        srv = str(line["Host"]).strip()
        plugin_id = str(line["Plugin ID"]).strip()
        cve = str(line["CVE"]).strip().upper()
        port = str(line["Port"]).strip()
        risk = str(line["Risk"]).strip()

        if not srv or not plugin_id:
            continue

        host, mapped = resolve_hostname(srv, host_map)

        if not mapped and is_ip_address(srv) and srv not in unmapped_ips:
            unmapped_ips.append(srv)

        row = {
            "srv": srv,
            "host": host,
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

    return {
        "actions": actions,
        "counts": counts,
        "unmapped_ips": unmapped_ips
    }
