"""
Rubrique "Scan vulnérabilité" de VulnWatch-AI.

À brancher dans app.py :

    from ui_scan_vuln import render_scan_vulnerabilites
    ...
    with tab_scan:
        render_scan_vulnerabilites(is_admin=IS_ADMIN, render_job=render_job)

Rôle Lecteur : consultation, filtres et exports uniquement ; la
configuration du token et la migration sont réservées aux
administrateurs (même règle que les autres onglets).

Contenu : migration depuis ClickUp (token, test de connexion, lancement
en arrière-plan avec suivi), indicateurs, filtres, tableau des constats,
détail (commentaires, pièces jointes, champs ClickUp bruts, croisement
CVE avec NVD / CISA KEV / Defender), export CSV.
"""

import json
import os
from datetime import date, datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from database import get_sync_state
from services.jobs import start_job, is_job_running
from scan_store import (
    SYNC_KEY,
    get_clickup_token,
    set_clickup_token,
    get_clickup_space_id,
    set_clickup_space_id,
    reset_clickup_migration,
    get_scan_summary,
    get_scan_filter_options,
    get_scan_findings,
    get_scan_finding_detail,
    get_scan_cve_context,
    get_scan_users,
    save_scan_users,
    set_scan_assignments,
    seed_scan_users_from_findings,
    get_import_candidates,
    get_status_catalog,
    default_new_status,
    apply_scan_import,
    get_host_map,
    get_host_map_rows,
    save_host_map,
    import_host_map
)
from scan_import import (
    ACTION_LABELS,
    ScanImportError,
    read_nessus_csv,
    read_host_table,
    build_import_plan
)

# Lancée via services/jobs.py comme les autres synchros : barre de
# progression, journal dans data/jobs/, bouton « Arrêter » et pas de
# double lancement. Clé = nom du script sans extension (convention de
# app.launch_job).
MIGRATION_SCRIPT = "sync_clickup.py"
MIGRATION_JOB_KEY = "sync_clickup"
MIGRATION_LABEL = "Migration ClickUp"

STATUS_ICONS = {
    "TRAITE": "✅",
    "ACCEPTE": "🟦",
    "REFUSE": "🟥",
    "ATTENUE": "🔵",
    "REDUIRE": "🟠"
}


def _status_label(status):

    if not status:
        return "⚪ (aucun)"

    key = (
        status.upper()
        .replace("É", "E").replace("È", "E").replace("Ê", "E")
    )

    return f"{STATUS_ICONS.get(key, '⚪')} {status}"


def _tags(tags_json):
    """Étiquettes ClickUp : le script y plaçait le nom de la vulnérabilité."""

    try:
        return ", ".join(json.loads(tags_json or "[]"))
    except (ValueError, TypeError):
        return ""


def _day(value):

    return str(value)[:10] if value else ""


def _format_ts(iso_value):

    if not iso_value:
        return "jamais"

    try:

        dt = datetime.fromisoformat(iso_value)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone().strftime("%d/%m/%Y %H:%M")

    except ValueError:

        return iso_value


def _launch_migration(with_comments, with_attachments, with_download,
                      include_archived):

    env = os.environ.copy()

    env["VULNWATCH_CLICKUP_TOKEN"] = get_clickup_token()
    env["VULNWATCH_CLICKUP_SPACE"] = get_clickup_space_id()
    env["VULNWATCH_CLICKUP_COMMENTS"] = "1" if with_comments else "0"
    env["VULNWATCH_CLICKUP_ATTACHMENTS"] = "1" if with_attachments else "0"
    env["VULNWATCH_CLICKUP_DOWNLOAD"] = "1" if with_download else "0"
    env["VULNWATCH_CLICKUP_ARCHIVED"] = "1" if include_archived else "0"

    # start_job ne fait rien si la migration tourne déjà.
    return start_job(
        MIGRATION_JOB_KEY, MIGRATION_SCRIPT, MIGRATION_LABEL, env=env
    )


def _test_connection(with_comments, need_detail):

    from collectors.clickup import ClickUpClient, ClickUpError

    client = ClickUpClient(get_clickup_token())

    space_id = get_clickup_space_id()

    space = client.get_space(space_id)

    if space is None:
        raise ClickUpError(f"Espace {space_id} introuvable.")

    lists = client.get_lists_of_space(space_id)

    total_tasks = sum(int(x.get("task_count") or 0) for x in lists)

    calls_per_task = 1 + (1 if with_comments else 0) + (1 if need_detail else 0)

    # ~100 appels/minute (limite ClickUp), + pagination des listes.
    estimate_min = (total_tasks * calls_per_task + len(lists) * 20) / 100

    return {
        "space": space.get("name"),
        "lists": lists,
        "total_tasks": total_tasks,
        "estimate_min": estimate_min
    }


def _render_users(is_admin):
    """
    Référentiel de la liste déroulante « Assigné » : utilisateur (nom et
    prénom) + mail. Rempli une première fois avec les assignés ClickUp
    migrés ; mails et nouveaux utilisateurs saisis ici.
    """

    users = get_scan_users()
    missing_mail = sum(1 for u in users if not u["mail"])

    title = f"Utilisateurs — liste « Assigné » ({len(users)})"

    if missing_mail:
        title += f" · {missing_mail} sans mail"

    with st.expander(title, expanded=False):

        table = pd.DataFrame(
            users, columns=["id", "utilisateur", "mail", "constats"]
        )

        if not is_admin:

            st.dataframe(
                table.drop(columns=["id"]).rename(columns={
                    "utilisateur": "Utilisateur", "mail": "Mail",
                    "constats": "Constats assignés"
                }),
                use_container_width=True, hide_index=True
            )

            return

        st.caption(
            "Utilisateur : nom et prénom. Ajoutez une ligne avec « + » en "
            "bas du tableau ; supprimez-en une en la cochant puis 🗑. Un "
            "utilisateur supprimé laisse ses constats non assignés."
        )

        edited = st.data_editor(
            table,
            key="scan_users_editor",
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            column_order=["utilisateur", "mail", "constats"],
            disabled=["constats"],
            column_config={
                "utilisateur": st.column_config.TextColumn(
                    "Utilisateur (nom et prénom)", required=True,
                    max_chars=120
                ),
                "mail": st.column_config.TextColumn(
                    "Mail", max_chars=254,
                    validate=r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$"
                ),
                "constats": st.column_config.NumberColumn(
                    "Constats assignés"
                )
            }
        )

        c1, c2 = st.columns(2)

        if c1.button(
            "Enregistrer les utilisateurs",
            key="scan_users_save",
            type="primary",
            use_container_width=True
        ):

            rows = [
                {
                    "id": None if pd.isna(r["id"]) else int(r["id"]),
                    "utilisateur": r["utilisateur"] if isinstance(r["utilisateur"], str) else "",
                    "mail": r["mail"] if isinstance(r["mail"], str) else ""
                }
                for r in edited.to_dict("records")
            ]

            try:

                removed = save_scan_users(rows)

            except ValueError as error:

                st.error(str(error))

            else:

                st.session_state.pop("scan_users_editor", None)

                st.success(
                    "Utilisateurs enregistrés"
                    + (f" ({removed} supprimé(s))." if removed else ".")
                )

                st.rerun()

        if c2.button(
            "Importer les assignés ClickUp",
            key="scan_users_seed",
            use_container_width=True,
            help=(
                "Ajoute les assignés ClickUp absents de la liste et assigne "
                "les constats sans assignation. Ne modifie ni les mails, ni "
                "les assignations faites à la main."
            )
        ):

            added, assigned = seed_scan_users_from_findings()

            st.session_state.pop("scan_users_editor", None)

            st.success(
                f"{added} utilisateur(s) ajouté(s), "
                f"{assigned} constat(s) assigné(s)."
            )

            st.rerun()


def _render_nessus_import(is_admin, current_user):
    """
    Import d'un export CSV Nessus, avec les mêmes règles que le script
    ImportVullns.ps1 (voir scan_import.py) : analyse d'abord, écriture
    après confirmation.
    """

    result = st.session_state.pop("nessus_import_result", None)

    with st.expander(
        "Importer un scan Nessus (CSV)", expanded=result is not None
    ):

        if result:
            st.success(result)

        if not is_admin:
            st.caption("🔒 Import réservé aux administrateurs.")
            return

        st.caption(
            "Mêmes règles que le script ImportVullns.ps1 : rapprochement "
            "avec les constats de la liste (fermés compris) par hôte, "
            "Plugin ID, port et CVE. Existant TRAITÉ / ATTÉNUÉ → repasse en "
            "RÉDUIRE ; RÉDUIRE → échéance recalculée ; ACCEPTÉ → sans "
            "échéance ; autre statut → inchangé. Sinon : nouveau constat. "
            "Échéance depuis l'import : Critical 7 j, High 14 j, Medium "
            "21 j, Low 42 j. Commentaire « Date d'import » et date du "
            "dernier scan sur chaque constat traité."
        )

        lists = get_scan_filter_options()["lists"]
        new_list_label = "➕ Nouvelle liste…"

        c1, c2 = st.columns(2)

        choice = c1.selectbox(
            "Liste (périmètre)", lists + [new_list_label],
            key="nessus_list"
        )

        if choice == new_list_label:
            list_name = c1.text_input(
                "Nom de la nouvelle liste", key="nessus_new_list"
            ).strip()
        else:
            list_name = choice

        scan_date = c2.date_input(
            "Date du scan", value=date.today(), format="DD/MM/YYYY",
            key="nessus_scan_date"
        )

        nessus_file = st.file_uploader(
            "Fichier des vulnérabilités (export CSV Nessus)",
            type=["csv"], key="nessus_file"
        )

        host_map = get_host_map()

        st.caption(
            f"Hôte : {len(host_map)} correspondance(s) machine → hôte en base "
            "(section « Correspondances machine → hôte »). Sans "
            "correspondance : nom avant le premier point "
            "(x.alliumfr.Corp.priv → x) ; adresse IP gardée telle quelle "
            "et signalée."
        )

        o1, o2 = st.columns(2)

        skip_info = o1.checkbox(
            "Ignorer les lignes informatives (Risk = None)",
            value=True, key="nessus_skip_info"
        )

        catalog = get_status_catalog(list_name) if list_name else {}
        statuses = sorted({v["status"] for v in catalog.values()})
        default_status = default_new_status(catalog)

        if default_status not in statuses:
            statuses.insert(0, default_status)

        new_status = o2.selectbox(
            "Statut des nouveaux constats", statuses,
            index=statuses.index(default_status),
            key=f"nessus_new_status_{list_name}",
            help="Par défaut : premier statut ouvert de la liste (comme ClickUp)."
        )

        params = {
            "list": list_name,
            "scan_date": scan_date,
            "skip_info": skip_info,
            "new_status": new_status,
            "file": (
                (nessus_file.name, nessus_file.size) if nessus_file else None
            ),
            # Correspondances modifiées après l'analyse -> à refaire.
            "hosts": hash(frozenset(host_map.items()))
        }

        if st.button(
            "Analyser le fichier",
            key="nessus_analyse",
            disabled=not (nessus_file and list_name)
        ):

            try:

                frame = read_nessus_csv(nessus_file)
                now = datetime.now().astimezone()

                plan = build_import_plan(
                    frame, host_map, get_import_candidates(list_name),
                    now, skip_info
                )

            except ScanImportError as error:

                st.session_state.pop("nessus_plan", None)
                st.error(str(error))

            else:

                st.session_state["nessus_plan"] = {
                    "plan": plan, "params": params, "now": now,
                    "rows": len(frame), "hosts": len(host_map)
                }

        pending = st.session_state.get("nessus_plan")

        if not pending:
            return

        stale = pending["params"] != params

        counts = pending["plan"]["counts"]

        st.markdown(
            f"**Analyse :** {pending['rows']:,} ligne(s) dans le CSV, "
            f"{pending['hosts']} correspondance(s) machine → hôte, liste "
            f"« {pending['params']['list']} »."
        )

        unmapped = pending["plan"].get("unmapped_ips") or []

        if unmapped:
            st.warning(
                f"{len(unmapped)} adresse(s) IP sans correspondance (hôte = "
                "l'adresse IP) : " + ", ".join(unmapped[:30])
                + (" ..." if len(unmapped) > 30 else "")
                + ". Ajoutez-les dans « Correspondances machine → hôte » "
                "puis relancez l'analyse."
            )

        st.dataframe(
            pd.DataFrame([
                {"Action": ACTION_LABELS[key], "Lignes": n}
                for key, n in counts.items() if n
            ]),
            use_container_width=True, hide_index=True
        )

        # Pas d'expander ici : Streamlit refuse les expanders imbriqués.
        if st.checkbox("Afficher le détail ligne par ligne", key="nessus_detail"):

            st.dataframe(
                pd.DataFrame([
                    {
                        "Action": ACTION_LABELS[a["action"]],
                        "Host (Nessus)": a["row"]["srv"],
                        "Hôte": a["row"]["host"],
                        "Plugin ID": a["row"]["plugin_id"],
                        "Vulnérabilité": a["row"]["name"],
                        "Port": a["row"]["port"],
                        "CVE": a["row"]["cve"],
                        "Risque": a["row"]["risk"],
                        "Statut actuel": a["status_before"],
                        "Échéance": _day(a["row"]["due_date"])
                        if a["action"] in ("new", "reopen", "refresh") else ""
                    }
                    for a in pending["plan"]["actions"]
                ]),
                use_container_width=True, hide_index=True
            )

        to_write = sum(
            counts[k] for k in ("new", "reopen", "refresh", "accepted")
        )

        if stale:
            st.warning(
                "Les paramètres ou les fichiers ont changé depuis l'analyse : "
                "relancez « Analyser le fichier »."
            )

        b1, b2 = st.columns(2)

        if b1.button(
            f"Confirmer l'import ({to_write} constat(s))",
            key="nessus_apply",
            type="primary",
            disabled=stale or to_write == 0,
            use_container_width=True
        ):

            applied = apply_scan_import(
                pending["plan"], pending["params"]["list"],
                pending["params"]["scan_date"], pending["now"],
                current_user or "VulnWatch", pending["params"]["new_status"]
            )

            st.session_state.pop("nessus_plan", None)

            st.session_state["nessus_import_result"] = (
                "Import terminé : "
                f"{applied.get('new', 0)} nouveau(x), "
                f"{applied.get('reopen', 0)} réouvert(s), "
                f"{applied.get('refresh', 0)} échéance(s) recalculée(s), "
                f"{applied.get('accepted', 0)} accepté(s) mis à jour."
            )

            st.rerun()

        if b2.button(
            "Annuler", key="nessus_cancel", use_container_width=True
        ):

            st.session_state.pop("nessus_plan", None)

            st.rerun()


def _render_host_map(is_admin):
    """
    Correspondances machine détectée par Nessus (adresse IP ou nom) ->
    hôte. Remplace le fichier IP;HOST du script : premier remplissage
    depuis ce fichier, puis complété ici.
    """

    rows = get_host_map_rows()

    result = st.session_state.pop("host_map_result", None)

    with st.expander(
        f"Correspondances machine → hôte ({len(rows)})",
        expanded=result is not None
    ):

        if result:
            st.success(result)

        table = pd.DataFrame(rows, columns=["id", "machine", "hote"])

        if not is_admin:

            st.dataframe(
                table.drop(columns=["id"]).rename(columns={
                    "machine": "Machine (IP ou nom)", "hote": "Hôte"
                }),
                use_container_width=True, hide_index=True
            )

            return

        st.caption(
            "Machine : adresse IP (ou nom) telle que Nessus la détecte. "
            "Utilisée à l'import de scan pour remplir le champ hôte. « + » en "
            "bas du tableau pour ajouter, 🗑 pour supprimer."
        )

        edited = st.data_editor(
            table,
            key="host_map_editor",
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            column_order=["machine", "hote"],
            column_config={
                "machine": st.column_config.TextColumn(
                    "Machine (IP ou nom)", required=True, max_chars=255
                ),
                "hote": st.column_config.TextColumn(
                    "Hôte", required=True, max_chars=255
                )
            }
        )

        if st.button(
            "Enregistrer les correspondances",
            key="host_map_save",
            type="primary"
        ):

            try:

                removed = save_host_map([
                    {
                        "id": None if pd.isna(r["id"]) else int(r["id"]),
                        "machine": r["machine"] if isinstance(r["machine"], str) else "",
                        "hote": r["hote"] if isinstance(r["hote"], str) else ""
                    }
                    for r in edited.to_dict("records")
                ])

            except ValueError as error:

                st.error(str(error))

            else:

                st.session_state.pop("host_map_editor", None)
                st.session_state["host_map_result"] = (
                    "Correspondances enregistrées"
                    + (f" ({removed} supprimée(s))." if removed else ".")
                )
                st.rerun()

        st.markdown("**Importer un fichier de correspondance**")

        f1, f2 = st.columns([3, 2])

        upload = f1.file_uploader(
            "Fichier IP;HOST (« ; » ou « , »)",
            type=["csv", "txt"], key="host_map_file"
        )

        overwrite = f2.checkbox(
            "Remplacer l'hôte des machines déjà en base",
            value=False, key="host_map_overwrite",
            help=(
                "Décoché : seules les nouvelles machines sont ajoutées, les "
                "corrections faites ici sont conservées."
            )
        )

        if f2.button(
            "Importer le fichier", key="host_map_import",
            disabled=upload is None, use_container_width=True
        ):

            try:

                pairs, conflicts = read_host_table(upload)

            except ScanImportError as error:

                st.error(str(error))

            else:

                stats = import_host_map(pairs, overwrite=overwrite)

                message = (
                    f"{len(pairs)} machine(s) dans le fichier : "
                    f"{stats['added']} ajoutée(s), {stats['updated']} "
                    f"mise(s) à jour, {stats['kept']} déjà en base."
                )

                if conflicts:
                    message += (
                        f" {len(conflicts)} machine(s) avec deux hôtes dans le "
                        "fichier, dernière ligne retenue : "
                        + "; ".join(
                            f"{m} : {old} → {new}" for m, old, new in conflicts
                        )
                    )

                st.session_state.pop("host_map_editor", None)
                st.session_state["host_map_result"] = message
                st.rerun()


def render_scan_vulnerabilites(is_admin=False, render_job=None,
                               current_user=None):
    """
    is_admin : IS_ADMIN de app.py. Par défaut False : sans information
    sur le rôle, on reste en lecture seule.
    render_job : app.render_job, pour afficher la progression de la
    migration sous le bouton (facultatif).
    current_user : identifiant VulnWatch, auteur des commentaires
    « Date d'import » de l'import Nessus.
    """

    st.subheader("Scan vulnérabilité")

    st.caption(
        "Constats de scans Nessus et suivi de leur traitement, migrés "
        "depuis l'espace ClickUp « DSI Infra SecOps » via l'API ClickUp."
    )

    state = get_sync_state(SYNC_KEY)
    running = is_job_running(MIGRATION_JOB_KEY)

    summary = get_scan_summary()

    # -----------------------------------------------------
    # Migration ClickUp
    # -----------------------------------------------------

    with st.expander(
        "Migration depuis ClickUp",
        expanded=(summary["total"] == 0)
    ):

        st.caption(
            "Créez un token personnel dans ClickUp (avatar → Settings → "
            "Apps → API Token). Il est stocké en base de l'application, "
            "jamais dans un fichier. Limite ClickUp : 100 requêtes par "
            "minute ; la migration tourne en arrière-plan."
        )

        token_present = bool(get_clickup_token())

        if not is_admin:
            st.caption(
                "🔒 Configuration et migration réservées aux administrateurs."
            )

        c1, c2 = st.columns(2)

        new_token = c1.text_input(
            "Token API ClickUp",
            type="password",
            value="",
            key="clickup_token_field",
            disabled=not is_admin,
            help=(
                "Laisser vide pour conserver le token déjà enregistré. "
                "Le champ se vide après enregistrement."
            )
        )

        new_space = c2.text_input(
            "ID de l'espace ClickUp",
            value=get_clickup_space_id(),
            key="clickup_space_field",
            disabled=not is_admin,
            help=(
                "Dans l'URL ClickUp : .../<équipe>/v/s/<ID de l'espace>/..."
            )
        )

        st.caption(
            "Token actuel : " + ("configuré" if token_present else "non configuré")
        )

        if st.button(
            "Enregistrer la configuration",
            key="clickup_save_cfg",
            disabled=not is_admin
        ):

            set_clickup_token(new_token.strip())
            set_clickup_space_id(new_space.strip())

            st.session_state.pop("clickup_token_field", None)

            st.success("Configuration enregistrée.")

            st.rerun()

        o1, o2, o3, o4 = st.columns(4)

        with_comments = o1.checkbox(
            "Commentaires", value=True, key="clickup_opt_comments",
            disabled=not is_admin
        )
        with_attachments = o2.checkbox(
            "Pièces jointes (liste)", value=True, key="clickup_opt_attach",
            disabled=not is_admin
        )
        with_download = o3.checkbox(
            "Télécharger les fichiers", value=False, key="clickup_opt_download",
            disabled=not is_admin,
            help=(
                "Les fichiers hébergés par ClickUp disparaîtront avec "
                "l'instance : à cocher si des rapports Nessus y sont joints."
            )
        )
        include_archived = o4.checkbox(
            "Inclure l'archivé", value=False, key="clickup_opt_archived",
            disabled=not is_admin
        )

        need_detail = with_attachments or with_download

        if st.button(
            "Tester la connexion et estimer la durée",
            key="clickup_test_btn",
            disabled=(not is_admin) or (not token_present)
        ):

            try:

                with st.spinner("Interrogation de ClickUp..."):

                    info = _test_connection(with_comments, need_detail)

                st.success(
                    f"Espace « {info['space']} » : {len(info['lists'])} "
                    f"listes, environ {info['total_tasks']} tâches ouvertes "
                    f"comptées par ClickUp (les tâches fermées s'ajoutent). "
                    f"Durée estimée : ~{info['estimate_min']:.0f} min."
                )

                st.dataframe(
                    pd.DataFrame(info["lists"])[
                        ["name", "folder_name", "task_count", "archived"]
                    ].rename(columns={
                        "name": "Liste", "folder_name": "Dossier",
                        "task_count": "Tâches (compteur ClickUp)",
                        "archived": "Archivée"
                    }),
                    use_container_width=True, hide_index=True
                )

            except Exception as error:

                st.error(f"Échec : {error}")

        if state:

            status = state.get("status")

            if status == "RUNNING" and not running:
                # Processus arrêté (bouton « Arrêter », redémarrage...)
                # sans avoir pu écrire son statut final.
                icon = "⚪"
                detail = (
                    f"{state.get('detail') or ''} — interrompue, "
                    "relancer pour reprendre."
                )
            else:
                icon = (
                    "🟠" if status == "RUNNING"
                    else "🟢" if status == "OK"
                    else "🔴"
                )
                detail = state.get("detail") or ""

            st.info(
                f"{icon} {_format_ts(state.get('last_run_at'))} — {detail}"
            )

        b1, b2 = st.columns(2)

        if b1.button(
            "Lancer / reprendre la migration",
            key="clickup_launch_btn",
            disabled=(not is_admin) or (not token_present) or running,
            type="primary",
            use_container_width=True
        ):

            # Pas de st.rerun() : render_job() juste en dessous affiche
            # la progression (même logique que app.launch_job).
            if _launch_migration(
                with_comments, with_attachments, with_download,
                include_archived
            ):
                running = True

        elif running:
            b1.caption("Une migration est déjà en cours.")

        if b2.button(
            "Reparcourir toutes les listes",
            key="clickup_reset_btn",
            use_container_width=True,
            disabled=(not is_admin) or running,
            help=(
                "Oublie les listes terminées (aucun constat n'est "
                "supprimé). Les tâches inchangées ne sont pas "
                "re-téléchargées."
            )
        ):

            reset_clickup_migration()

            st.success("Marqueurs de reprise réinitialisés.")

        if render_job is not None:
            render_job(MIGRATION_JOB_KEY, place="_scan")

    # -----------------------------------------------------
    # Utilisateurs (liste déroulante « Assigné »)
    # -----------------------------------------------------

    if summary["total"] > 0 and not get_scan_users():
        # Premier remplissage avec les assignés ClickUp déjà migrés.
        seed_scan_users_from_findings()

    _render_nessus_import(is_admin, current_user)

    _render_host_map(is_admin)

    _render_users(is_admin)

    # -----------------------------------------------------
    # Indicateurs
    # -----------------------------------------------------

    if summary["total"] == 0:

        st.info(
            "Aucun constat migré pour le moment. Configurez le token "
            "ci-dessus puis lancez la migration."
        )

        return

    by_status = pd.DataFrame(summary["by_status"])

    untreated = int(
        by_status.loc[
            ~by_status["status_type"].isin(["done", "closed"]), "n"
        ].sum()
    )

    k1, k2, k3, k4 = st.columns(4)

    k1.metric("Constats", f"{summary['total']:,}")
    k2.metric("À traiter (ouverts)", f"{untreated:,}")
    k3.metric("Traités / fermés", f"{summary['total'] - untreated:,}")
    k4.metric("Hôtes concernés", f"{summary['hosts']:,}")

    left, right = st.columns(2)

    with left:

        st.markdown("##### Par statut")

        st.dataframe(
            by_status.assign(
                Statut=by_status["status"].map(_status_label)
            )[["Statut", "n"]].rename(columns={"n": "Constats"}),
            use_container_width=True, hide_index=True
        )

    with right:

        st.markdown("##### Par liste (site / périmètre)")

        st.dataframe(
            pd.DataFrame(summary["by_list"]).rename(columns={
                "list_name": "Liste", "n": "Constats", "open_n": "Ouverts"
            }),
            use_container_width=True, hide_index=True
        )

    st.divider()

    # -----------------------------------------------------
    # Filtres + tableau
    # -----------------------------------------------------

    options = get_scan_filter_options()

    f1, f2, f3 = st.columns([2, 2, 3])

    sel_lists = f1.multiselect(
        "Liste", options["lists"], key="scan_f_lists"
    )
    sel_status = f2.multiselect(
        "Statut", options["statuses"], key="scan_f_status"
    )
    search = f3.text_input(
        "Rechercher (constat, hôte, CVE, assigné, description)",
        key="scan_f_search"
    )

    only_open = st.checkbox(
        "Uniquement les constats non traités", key="scan_f_open"
    )

    findings = get_scan_findings(
        lists=sel_lists or None,
        statuses=sel_status or None,
        search=search.strip() or None,
        only_untreated=only_open
    )

    if not findings:

        st.info("Aucun constat ne correspond à ces filtres.")

        return

    df = pd.DataFrame(findings)

    display = pd.DataFrame({
        "Constat": df["title"],
        "Vulnérabilité": df["tags_json"].map(_tags),
        "Plugin ID": df["plugin_id"],
        "Hôte": df["host"],
        "Port": df["port"],
        "Statut": df["status"].map(_status_label),
        "Risque": df["risk"],
        "Liste": df["list_name"],
        "Assigné": df["assigned_user"].where(df["assigned_user"].notna(), None),
        "CVE": df["cves"],
        "CVSS": df["cvss"],
        "Dernier scan": df["last_scan"].map(_day),
        "Créé": df["date_created"].map(_day),
        "Mis à jour": df["date_updated"].map(_day),
        "Fermé": df["date_closed"].map(_day),
        "Échéance": df["due_date"].map(_day)
    })

    st.caption(f"{len(display):,} constat(s)")

    users = get_scan_users()
    user_ids = {u["utilisateur"]: u["id"] for u in users}

    if is_admin:

        st.caption(
            "Colonne « Assigné » modifiable : choisissez un utilisateur "
            "dans la liste (gérée dans « Utilisateurs » ci-dessus), puis "
            "« Enregistrer les assignations »."
        )

        # La clé change avec les filtres : l'éditeur repart des données
        # affichées au lieu de réappliquer des modifications à d'autres
        # lignes.
        editor_key = "scan_assign_editor_" + str(abs(hash((
            tuple(sel_lists), tuple(sel_status), search.strip(), only_open,
            tuple(df["task_id"])
        ))))

        edited = st.data_editor(
            display,
            key=editor_key,
            use_container_width=True,
            hide_index=True,
            disabled=[c for c in display.columns if c != "Assigné"],
            column_config={
                "Assigné": st.column_config.SelectboxColumn(
                    "Assigné",
                    options=list(user_ids.keys()),
                    required=False,
                    help="Vide = non assigné"
                )
            }
        )

        changes = {}

        for position, (before, after) in enumerate(
            zip(display["Assigné"], edited["Assigné"])
        ):

            before = before if isinstance(before, str) and before else None
            after = after if isinstance(after, str) and after else None

            if before != after:
                changes[df["task_id"].iloc[position]] = (
                    user_ids.get(after) if after else None
                )

        if st.button(
            f"Enregistrer les assignations ({len(changes)})",
            key="scan_assign_save",
            disabled=not changes,
            type="primary"
        ):

            set_scan_assignments(changes)

            st.session_state.pop(editor_key, None)

            st.success(f"{len(changes)} assignation(s) enregistrée(s).")

            st.rerun()

    else:

        st.dataframe(display, use_container_width=True, hide_index=True)

    export = display.copy()
    export.insert(
        export.columns.get_loc("Assigné") + 1,
        "Mail assigné",
        df["assigned_mail"]
    )

    st.download_button(
        "Exporter la sélection (CSV)",
        export.to_csv(index=False).encode("utf-8-sig"),
        file_name="scan_vulnerabilites.csv",
        mime="text/csv",
        key="scan_export_csv"
    )

    st.divider()

    # -----------------------------------------------------
    # Détail d'un constat
    # -----------------------------------------------------

    st.markdown("#### Détail d'un constat")

    choices = {
        f"{row['title']} — {row['host'] or '?'}:{row['port'] or '?'} "
        f"[{row['task_id']}]": row["task_id"]
        for row in findings[:500]
    }

    picked = st.selectbox(
        "Sélectionner un constat",
        list(choices.keys()),
        key="scan_detail_pick"
    )

    detail = get_scan_finding_detail(choices[picked])

    if detail is None:
        return

    d1, d2, d3, d4 = st.columns(4)

    d1.metric("Statut", detail.get("status") or "—")
    d2.metric("Hôte", detail.get("host") or "—")
    d3.metric("Port", detail.get("port") or "—")
    d4.metric("Risque", detail.get("risk") or "—")

    st.write(
        f"**Liste :** {detail.get('list_name') or '—'}  \n"
        f"**Assigné :** {detail.get('assigned_user') or '—'}"
        f"{' (' + detail['assigned_mail'] + ')' if detail.get('assigned_mail') else ''}  \n"
        f"**Assigné(s) dans ClickUp :** {detail.get('assignee_names') or '—'}  \n"
        f"**Créé :** {_day(detail.get('date_created'))} — "
        f"**Fermé :** {_day(detail.get('date_closed')) or '—'}  \n"
        f"**Vulnérabilité :** {_tags(detail.get('tags_json')) or '—'} — "
        f"**Plugin ID :** {detail.get('plugin_id') or '—'} — "
        f"**CVSS :** {detail.get('cvss') or '—'}  \n"
        f"**Dernier scan :** {_day(detail.get('last_scan')) or '—'} — "
        f"**Échéance :** {_day(detail.get('due_date')) or '—'}  \n"
        f"**Source :** {detail.get('source') or '—'} — "
        f"**Lien ClickUp d'origine :** {detail.get('url') or '—'}"
    )

    if detail.get("description"):

        with st.expander("Description"):
            # st.text : le contenu vient d'outils externes (sortie
            # Nessus, markdown ClickUp) -> aucun rendu HTML/Markdown.
            st.text(detail["description"])

    if detail["cves"]:

        st.markdown("##### CVE citées — croisement VulnWatch")

        context = get_scan_cve_context(detail["cves"])

        st.dataframe(
            pd.DataFrame([
                {
                    "CVE": cve,
                    "Source VulnWatch": context[cve].get("source") or "absente",
                    "Priorité": context[cve].get("priority"),
                    "CVSS": context[cve].get("cvss"),
                    "Publiée (NVD)": _day(context[cve].get("nvd_published")),
                    "Équipements Defender": context[cve].get(
                        "defender_devices", 0
                    )
                }
                for cve in detail["cves"]
            ]),
            use_container_width=True, hide_index=True
        )

    if detail["comments"]:

        st.markdown(f"##### Commentaires ({len(detail['comments'])})")

        for comment in detail["comments"]:

            st.text(
                f"{_day(comment['date'])} — "
                f"{comment['author_name'] or '?'}"
                f"{' (réponse)' if comment['parent_comment_id'] else ''}\n"
                f"{comment['text'] or ''}"
            )

    if detail["attachments"]:

        st.markdown(f"##### Pièces jointes ({len(detail['attachments'])})")

        for attachment in detail["attachments"]:

            local = attachment.get("local_path")

            if local and Path(local).is_file():

                st.download_button(
                    f"Télécharger {attachment['title']}",
                    Path(local).read_bytes(),
                    file_name=attachment["title"] or Path(local).name,
                    key=f"dl_{attachment['attachment_id']}"
                )

            else:

                st.text(
                    f"{attachment['title']} — non téléchargée "
                    f"({attachment.get('download_status') or 'lien ClickUp seul'})"
                )

    with st.expander("Champs ClickUp (valeurs brutes résolues)"):

        st.json(detail["custom_fields"])
