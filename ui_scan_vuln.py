"""
Rubrique "Scan vulnérabilité" de VulnWatch-AI.

À brancher dans app.py :

    from ui_scan_vuln import render_scan_vulnerabilites
    ...
    with tab_scan:
        render_scan_vulnerabilites()

Contenu : migration depuis ClickUp (token, test de connexion, lancement
en arrière-plan avec suivi), indicateurs, filtres, tableau des constats,
détail (commentaires, pièces jointes, champs ClickUp bruts, croisement
CVE avec NVD / CISA KEV / Defender), export CSV.
"""

import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

from database import get_sync_state
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
    get_scan_cve_context
)

# Même principe que le téléchargement historique NVD : un sous-processus
# actif met à jour son statut régulièrement ; sans nouvelle depuis ce
# délai, on le considère mort et on autorise un nouveau lancement.
MIGRATION_STALE_MINUTES = 15

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


def _migration_running(state):

    if not state or state.get("status") != "RUNNING":
        return False

    try:

        last = datetime.fromisoformat(state["last_run_at"])

        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        return (
            datetime.now(timezone.utc) - last
            < timedelta(minutes=MIGRATION_STALE_MINUTES)
        )

    except (ValueError, KeyError, TypeError):

        return False


def _launch_migration(with_comments, with_attachments, with_download,
                      include_archived):

    env = os.environ.copy()

    env["VULNWATCH_CLICKUP_TOKEN"] = get_clickup_token()
    env["VULNWATCH_CLICKUP_SPACE"] = get_clickup_space_id()
    env["VULNWATCH_CLICKUP_COMMENTS"] = "1" if with_comments else "0"
    env["VULNWATCH_CLICKUP_ATTACHMENTS"] = "1" if with_attachments else "0"
    env["VULNWATCH_CLICKUP_DOWNLOAD"] = "1" if with_download else "0"
    env["VULNWATCH_CLICKUP_ARCHIVED"] = "1" if include_archived else "0"

    # Popen (pas run) : processus détaché, l'interface n'attend pas.
    subprocess.Popen(
        [sys.executable, "sync_clickup.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env
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


def render_scan_vulnerabilites():

    st.subheader("Scan vulnérabilité")

    st.caption(
        "Constats de scans Nessus et suivi de leur traitement, migrés "
        "depuis l'espace ClickUp « DSI Infra SecOps » via l'API ClickUp."
    )

    state = get_sync_state(SYNC_KEY)
    running = _migration_running(state)

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

        c1, c2 = st.columns(2)

        new_token = c1.text_input(
            "Token API ClickUp",
            type="password",
            value="",
            key="clickup_token_field",
            help=(
                "Laisser vide pour conserver le token déjà enregistré. "
                "Le champ se vide après enregistrement."
            )
        )

        new_space = c2.text_input(
            "ID de l'espace ClickUp",
            value=get_clickup_space_id(),
            key="clickup_space_field",
            help=(
                "Dans l'URL ClickUp : .../<équipe>/v/s/<ID de l'espace>/..."
            )
        )

        st.caption(
            "Token actuel : " + ("configuré" if token_present else "non configuré")
        )

        if st.button("Enregistrer la configuration", key="clickup_save_cfg"):

            set_clickup_token(new_token.strip())
            set_clickup_space_id(new_space.strip())

            st.session_state.pop("clickup_token_field", None)

            st.success("Configuration enregistrée.")

            st.rerun()

        o1, o2, o3, o4 = st.columns(4)

        with_comments = o1.checkbox(
            "Commentaires", value=True, key="clickup_opt_comments"
        )
        with_attachments = o2.checkbox(
            "Pièces jointes (liste)", value=True, key="clickup_opt_attach"
        )
        with_download = o3.checkbox(
            "Télécharger les fichiers", value=False, key="clickup_opt_download",
            help=(
                "Les fichiers hébergés par ClickUp disparaîtront avec "
                "l'instance : à cocher si des rapports Nessus y sont joints."
            )
        )
        include_archived = o4.checkbox(
            "Inclure l'archivé", value=False, key="clickup_opt_archived"
        )

        need_detail = with_attachments or with_download

        if st.button(
            "Tester la connexion et estimer la durée",
            key="clickup_test_btn",
            disabled=not token_present
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

            icon = (
                "🟠" if state.get("status") == "RUNNING"
                else "🟢" if state.get("status") == "OK"
                else "🔴"
            )

            st.info(
                f"{icon} {_format_ts(state.get('last_run_at'))} — "
                f"{state.get('detail') or ''}"
            )

        b1, b2 = st.columns(2)

        if b1.button(
            "Lancer / reprendre la migration",
            key="clickup_launch_btn",
            disabled=(not token_present) or running,
            type="primary",
            use_container_width=True
        ):

            _launch_migration(
                with_comments, with_attachments, with_download,
                include_archived
            )

            st.success(
                "Migration lancée en arrière-plan. Rafraîchissez la page "
                "pour suivre la progression ; vous pouvez la fermer, la "
                "reprise est automatique."
            )

        if running:
            b1.caption("Une migration est déjà en cours.")

        if b2.button(
            "Reparcourir toutes les listes",
            key="clickup_reset_btn",
            use_container_width=True,
            help=(
                "Oublie les listes terminées (aucun constat n'est "
                "supprimé). Les tâches inchangées ne sont pas "
                "re-téléchargées."
            )
        ):

            reset_clickup_migration()

            st.success("Marqueurs de reprise réinitialisés.")

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
        "Hôte": df["host"],
        "Port": df["port"],
        "Statut": df["status"].map(_status_label),
        "Risque": df["risk"],
        "Liste": df["list_name"],
        "Assigné": df["assignee_names"],
        "CVE": df["cves"],
        "Créé": df["date_created"].map(_day),
        "Mis à jour": df["date_updated"].map(_day),
        "Fermé": df["date_closed"].map(_day),
        "Échéance": df["due_date"].map(_day)
    })

    st.caption(f"{len(display):,} constat(s)")

    st.dataframe(display, use_container_width=True, hide_index=True)

    st.download_button(
        "Exporter la sélection (CSV)",
        display.to_csv(index=False).encode("utf-8-sig"),
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
        f"**Assigné :** {detail.get('assignee_names') or '—'}  \n"
        f"**Créé :** {_day(detail.get('date_created'))} — "
        f"**Fermé :** {_day(detail.get('date_closed')) or '—'}  \n"
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
