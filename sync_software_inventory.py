"""
Import de l'inventaire logiciel de chaque machine, puis calcul des
équipements touchés selon NVD (services/inventory_matcher.py).

Source :
  - par défaut, l'API Advanced Hunting de Defender (table
    DeviceTvmSoftwareInventory, par lots de machines sous la limite de
    100 000 lignes ; permission AdvancedQuery.Read.All). Si elle est
    refusée : export SoftwareInventoryExport (Software.Read.All) ;
  - VULNWATCH_INVENTORY_SOURCE=export : export SoftwareInventoryExport ;
  - VULNWATCH_INVENTORY_DEVICE=<DeviceId> : une seule machine (Advanced
    Hunting), les autres machines ne sont pas touchées ;
  - VULNWATCH_INVENTORY_CSV=<chemin> : un fichier CSV au format du
    portail Defender (DeviceId, DeviceName, OSPlatform, OSVersion,
    SoftwareVendor, SoftwareName, SoftwareVersion, ProductCodeCpe, ...).

Avec Advanced Hunting, VULNWATCH_INVENTORY_MODE choisit :
  - "full" (défaut) : tout l'inventaire est retéléchargé ;
  - "delta" : une requête légère donne l'empreinte (SHA-256 de la liste
    des logiciels) de chaque machine ; seules les machines dont
    l'empreinte a changé depuis le dernier import, et les nouvelles,
    sont retéléchargées. Les machines disparues sont retirées.

Dans les deux cas, les changements (logiciel ajouté / supprimé / version
modifiée, machine apparue / retirée) et les CVE qu'ils introduisent ou
corrigent sont enregistrés (onglet Inventaire > Changements). Si un
changement introduit une CVE critique, un e-mail récapitulatif est envoyé
à la liste de diffusion de veille.
"""

import csv
import gzip
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from database import (
    initialize_database,
    set_sync_state,
    get_connection,
    get_inventory_fingerprints,
    save_inventory_fingerprints,
    forget_inventory_fingerprints,
    mark_inventory_full_import,
    set_app_config,
    INVENTORY_SOURCE_KEY,
    get_watch_recipients,
    record_watch_alert,
    is_smtp_configured
)
from collectors.defender import (
    get_access_token,
    request_export,
    download_export_file,
    SOFTWARE_INVENTORY_EXPORT_URL,
    hunting_fingerprints,
    iter_hunting_inventory_for,
    hunting_inventory_for_devices
)
from services.inventory_matcher import (
    replace_software_inventory,
    rebuild_all_matches,
    normalize_inventory_record
)
from services.inventory_delta import apply_inventory_update
from services.mailer import send_email
from services.jobs import report_progress


SYNC_KEY = "software_inventory"

# Actualisation d'une seule machine : état séparé, pour ne pas remplacer
# celui de l'import complet (date, nombre de machines, source).
DEVICE_SYNC_KEY = "software_inventory_device"

# Les exports de résultats Advanced Hunting (table
# DeviceTvmSoftwareInventory, mêmes colonnes que ce CSV) sont plafonnés à
# 100 000 lignes : un fichier de cette taille est très probablement
# tronqué (machines avec une partie seulement de leurs logiciels).
CSV_EXPORT_LIMIT = 100_000

_read_rows = {"count": 0}
EXPORT_DIR = Path("data/defender_exports")


def _read_csv(path):

    # Le portail Defender exporte en UTF-8 avec BOM.
    with open(path, encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            _read_rows["count"] += 1
            yield row


def _read_defender_export():

    print("Demande de l'export d'inventaire à Defender...")

    export = request_export(
        sas_valid_hours=6,
        url=SOFTWARE_INVENTORY_EXPORT_URL
    )

    files = export["export_files"]

    print(f"Export généré le {export['generated_time']} : {len(files)} fichier(s)")

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    for index, url in enumerate(files, start=1):

        report_progress(
            index - 1,
            len(files),
            f"Téléchargement du fichier d'inventaire {index}/{len(files)}",
            force=True
        )

        destination = EXPORT_DIR / f"inventory_part_{index:05d}.json.gz"
        download_export_file(url, destination)

        with gzip.open(destination, "rt", encoding="utf-8-sig") as source:

            for line in source:

                line = line.strip()

                if not line:
                    continue

                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

        destination.unlink(missing_ok=True)


def _is_access_denied(error):

    return "(403)" in str(error) or "(401)" in str(error)


def _report_batch(done, total, devices, rows):

    report_progress(
        done, total,
        f"Advanced Hunting : lot {done}/{total} "
        f"({devices} machines, {rows} logiciels)",
        force=True
    )


def _report_matching(done, total):

    report_progress(done, total, "Comparaison avec les produits vulnérables NVD")


def _group_rows(records):
    """{device_id: [tuple software_inventory]}."""

    imported_at = datetime.now(timezone.utc).isoformat()
    by_device = defaultdict(list)

    for record in records:

        row = normalize_inventory_record(record, imported_at)

        if row is not None:
            by_device[row[0]].append(row)

    return by_device


def _inventory_device_ids():

    conn = get_connection()
    ids = {row[0] for row in conn.execute("SELECT DISTINCT device_id FROM software_inventory")}
    conn.close()

    return ids


def _sync_hunting(mode):
    """
    Import par Advanced Hunting, complet ou delta. Retourne (libellé de
    la source, résultat de apply_inventory_update, machines vérifiées,
    machines retéléchargées, lignes importées).
    """

    token = get_access_token()

    report_progress(None, None, "Empreintes de l'inventaire de chaque machine", force=True)

    fingerprints = hunting_fingerprints(token)
    current_ids = {row["DeviceId"] for row in fingerprints}

    print(f"Empreintes : {len(fingerprints)} machine(s) dans Defender")

    stored = get_inventory_fingerprints()

    full = mode != "delta" or not stored

    if mode == "delta" and not stored:
        print("Aucune empreinte enregistrée : import complet (référence de départ).")

    if full:
        to_fetch = fingerprints
        removed = set()
    else:
        to_fetch = [
            row for row in fingerprints
            if stored.get(row["DeviceId"]) != row["Fingerprint"]
        ]
        removed = (set(stored) | _inventory_device_ids()) - current_ids

    print(
        f"{len(to_fetch)} machine(s) à télécharger, "
        f"{len(removed)} machine(s) retirée(s) de Defender"
    )

    by_device = _group_rows(
        iter_hunting_inventory_for(to_fetch, token, progress=_report_batch)
    ) if to_fetch else {}

    report_progress(None, None, "Mise à jour de l'inventaire et calcul du delta", force=True)

    result = apply_inventory_update(
        by_device, removed, full=full, progress=_report_matching
    )

    # Une machine dont Defender n'a renvoyé aucune ligne entre les deux
    # requêtes garde son ancienne empreinte : elle sera revue au passage
    # suivant.
    fetched_ids = {row["DeviceId"] for row in to_fetch}

    save_inventory_fingerprints([
        row for row in fingerprints
        if row["DeviceId"] in by_device or row["DeviceId"] not in fetched_ids
    ])

    if full:
        mark_inventory_full_import()

    label = "Defender (Advanced Hunting, complet)" if full else "Defender (delta)"

    return (
        label, result, len(fingerprints), len(by_device),
        sum(len(rows) for rows in by_device.values())
    )


def _send_critical_alert(result):
    """E-mail récapitulatif à la liste de veille si un changement introduit une CVE critique."""

    critical = result["critical"]

    if not critical:
        return None

    if not is_smtp_configured():
        print("[INFO] CVE critique introduite mais SMTP non configuré : pas d'alerte envoyée.")
        return None

    recipients = [r["email"] for r in get_watch_recipients(active_only=True)]

    if not recipients:
        print("[INFO] CVE critique introduite mais aucune liste de diffusion active (onglet Veille).")
        return None

    critical_cves = sorted(result["critical_cves"])
    devices = {change["device_id"] for change in critical}

    subject = (
        f"[VulnWatch] Inventaire : {len(critical)} changement(s) introduisent "
        f"{len(critical_cves)} CVE critique(s) sur {len(devices)} machine(s)"
    )

    lines = [
        "Bonjour,",
        "",
        "La dernière vérification de l'inventaire logiciel (Microsoft Defender) a "
        "détecté des changements qui introduisent des CVE critiques selon NVD :",
        ""
    ]

    for change in critical:

        cves = [cve for cve in change["cves_introduced"] if cve in result["critical_cves"]]
        vendor, name = change.get("software_vendor"), change.get("software_name")
        software = (
            name if not vendor or vendor == name else f"{vendor} {name}"
        ) or "inventaire de la machine"
        versions = " -> ".join(
            part for part in (change.get("old_version"), change.get("new_version")) if part
        )

        lines.append(
            f"- {change.get('device_name') or change['device_id']} : {software}"
            + (f" ({versions})" if versions else "")
            + f" : {', '.join(cves)}"
        )

    lines += [
        "",
        "Détail : onglet Inventaire > Changements de VulnWatch AI.",
        "",
        "-- VulnWatch AI"
    ]

    body = "\n".join(lines)
    sent_to = []

    for recipient in recipients:
        try:
            send_email(recipient, subject, body)
            sent_to.append(recipient)
        except Exception as error:
            print(f"[ERROR] Alerte non envoyée à {recipient} : {error}")

    if sent_to:
        record_watch_alert(
            cve_id=", ".join(critical_cves)[:500],
            recipients=sent_to,
            subject=subject,
            body=body,
            affected_device_count=len(devices)
        )

    return len(sent_to)


def _replace_all(records):
    """
    CSV ou export de fichiers : remplacement complet, sans calcul de delta
    (pas d'empreintes pour ces sources). Les empreintes sont oubliées : la
    prochaine vérification delta repart d'un import complet.
    """

    rows, devices = replace_software_inventory(
        records,
        progress=lambda count: report_progress(
            None, None, f"{count:,} logiciels importés".replace(",", " ")
        )
    )

    forget_inventory_fingerprints()

    print(f"Inventaire : {rows} ligne(s), {devices} machine(s)")

    report_progress(None, None, "Comparaison avec les produits vulnérables NVD", force=True)

    matched_cves, _ = rebuild_all_matches(progress=_report_matching)

    return {
        "details": f"{devices} machine(s), {rows} logiciel(s)",
        "matched_cves": matched_cves,
        "critical": []
    }


def main():

    print()
    print("=" * 60)
    print("VulnWatch AI - Inventaire logiciel et équipements touchés (NVD)")
    print("=" * 60)
    print()

    initialize_database()

    csv_path = os.getenv("VULNWATCH_INVENTORY_CSV")
    device_id = os.getenv("VULNWATCH_INVENTORY_DEVICE")
    mode = os.getenv("VULNWATCH_INVENTORY_MODE", "full")
    sync_key = DEVICE_SYNC_KEY if device_id else SYNC_KEY
    result = None
    alerts = None

    try:

        if device_id:

            # Une seule machine : Advanced Hunting, remplacement de ses
            # seules lignes d'inventaire.
            report_progress(None, None, "Inventaire de la machine (Advanced Hunting)", force=True)

            by_device = _group_rows(hunting_inventory_for_devices([device_id]))
            rows = len(by_device.get(device_id, []))

            if not rows:
                raise RuntimeError("Defender ne renvoie aucun logiciel pour cette machine.")

            result = apply_inventory_update(
                {device_id: by_device[device_id]}, progress=_report_matching
            )

            # Empreinte oubliée : la prochaine vérification delta la
            # recalcule pour cette machine.
            forget_inventory_fingerprints([device_id])

            source_label = "Defender (machine)"
            details = f"1 machine, {rows} logiciel(s)"

            print(f"Machine {device_id} : {rows} logiciel(s)")

        elif csv_path or os.getenv("VULNWATCH_INVENTORY_SOURCE") == "export":

            if csv_path:
                records = _read_csv(csv_path)
                source_label = "CSV"
            else:
                records = _read_defender_export()
                source_label = "Defender (export)"

            result = _replace_all(records)
            details = result.pop("details")

        else:

            try:
                source_label, result, checked, fetched, rows = _sync_hunting(mode)
                details = (
                    f"{checked} machine(s) vérifiée(s), {fetched} téléchargée(s), "
                    f"{rows} logiciel(s) importé(s), {result['changes']} changement(s)"
                )
            except RuntimeError as error:

                if not _is_access_denied(error):
                    raise

                print(
                    f"[AVERTISSEMENT] Advanced Hunting refusé ({error}). "
                    "Ajoutez la permission AdvancedQuery.Read.All à l'application "
                    "Azure. Import par l'export de fichiers à la place."
                )

                result = _replace_all(_read_defender_export())
                details = result.pop("details")
                source_label = "Defender (export, Advanced Hunting refusé)"

        if result.get("critical"):
            alerts = _send_critical_alert(result)

    except Exception as error:

        print(f"[ERROR] {error}")
        set_sync_state(sync_key, "ERROR", str(error))
        sys.exit(1)

    finally:

        if csv_path:
            Path(csv_path).unlink(missing_ok=True)

    detail = (
        f"{source_label} : {details} ; "
        f"{result['matched_cves']} CVE touchent le parc selon NVD"
    )

    if result.get("critical"):
        detail += (
            f" ; {len(result['critical'])} changement(s) introduisent une CVE critique"
            + (f" (alerte envoyée à {alerts} destinataire(s))" if alerts else "")
        )

    status = "OK"

    if csv_path and _read_rows["count"] == CSV_EXPORT_LIMIT:

        status = "WARNING"
        limit = f"{CSV_EXPORT_LIMIT:,}".replace(",", " ")

        detail = (
            f"Fichier CSV de {limit} lignes exactement : très probablement "
            "tronqué (limite des exports Advanced Hunting), certaines "
            "machines n'ont qu'une partie de leurs logiciels. Préférez "
            "« Importer l'inventaire depuis Defender » (API, sans limite) "
            "ou découpez l'export. "
            + detail
        )

    if not device_id:
        set_app_config(INVENTORY_SOURCE_KEY, "csv" if csv_path else "defender")

    print(detail)
    set_sync_state(sync_key, status, detail)


if __name__ == "__main__":
    main()
