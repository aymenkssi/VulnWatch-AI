import json
import os
from datetime import datetime, timezone

import requests


# =========================================================
# CONFIGURATION
# =========================================================

# Ollama runs 100% locally: no API key, no external network call.
# Install: https://ollama.com  |  Model pull: `ollama pull qwen2.5:7b`

OLLAMA_URL = os.getenv(
    "VULNWATCH_OLLAMA_URL",
    "http://localhost:11434"
)

# Default model chosen for machines without a dedicated GPU:
# Qwen2.5 7B (Q4 quantization pulled by default) runs on CPU with
# ~8-16 GB RAM and has strong French output. Override with
# VULNWATCH_AI_MODEL if you have more VRAM (e.g. "qwen2.5:14b").
AI_MODEL = os.getenv(
    "VULNWATCH_AI_MODEL",
    "qwen2.5:7b"
)

REQUEST_TIMEOUT = (
    10,
    float(os.getenv("VULNWATCH_AI_TIMEOUT", "120"))
)


# =========================================================
# AVAILABILITY CHECK
# =========================================================

def is_ollama_available():
    """
    Quick check that a local Ollama server is reachable.
    Does not guarantee the configured model is pulled.
    """

    try:

        response = requests.get(
            f"{OLLAMA_URL}/api/tags",
            timeout=(3, 5)
        )

        return response.status_code == 200

    except requests.RequestException:

        return False


# =========================================================
# PROMPT
# =========================================================

def _format_exposure(exposure):

    if not exposure or exposure.get("affected_devices", 0) == 0:

        return (
            "Aucune exposition interne détectée dans Microsoft Defender "
            "pour cette CVE (aucun device concerné à ce jour)."
        )

    lines = [
        f"- Devices internes exposés : {exposure['affected_devices']}",
        f"- Produits/logiciels concernés : {exposure['affected_products']}",
    ]

    if exposure.get("os_platforms"):
        lines.append(
            "- Plateformes OS concernées : "
            + ", ".join(exposure["os_platforms"])
        )

    if exposure.get("defender_severities"):
        lines.append(
            "- Sévérité Defender observée : "
            + ", ".join(exposure["defender_severities"])
        )

    if exposure.get("exploitability_levels"):
        lines.append(
            "- Niveau d'exploitabilité (Defender) : "
            + ", ".join(exposure["exploitability_levels"])
        )

    lines.append(
        "- Devices avec mise à jour de sécurité disponible : "
        f"{exposure['devices_with_update_available']} / "
        f"{exposure['affected_devices']}"
    )

    if exposure.get("recommended_updates"):
        lines.append(
            "- Mise(s) à jour recommandée(s) par Defender : "
            + ", ".join(exposure["recommended_updates"])
        )

    feasibility_labels = {
        "FEASIBLE": (
            "FUSIBLE — un correctif éditeur est disponible et couvre "
            "TOUS les devices exposés : la remédiation attendue est "
            "d'appliquer cette mise à jour."
        ),
        "PARTIAL": (
            "PARTIELLEMENT FUSIBLE — un correctif existe mais ne "
            "couvre qu'une partie des devices exposés : l'appliquer là "
            "où il est disponible, et prévoir une atténuation "
            "temporaire pour les devices restants."
        ),
        "NOT_FEASIBLE": (
            "NON FUSIBLE — aucun correctif éditeur n'est disponible "
            "pour AUCUN des devices exposés à ce jour (cas typique : "
            "composant tiers, ex. une lib Apache embarquée dans une "
            "solution déjà à jour côté éditeur, qui n'a pas encore "
            "publié de patch). La remédiation ne peut PAS être \"mettre "
            "à jour\" : il faut proposer une ou plusieurs mesures "
            "d'atténuation concrètes en attendant (isolement/"
            "segmentation réseau, restriction d'accès, WAF/reverse "
            "proxy, désactivation du module ou de la fonctionnalité "
            "vulnérable si possible, renforcement de la surveillance)."
        )
    }

    if exposure.get("patch_feasibility") in feasibility_labels:
        lines.append(
            "- Faisabilité du correctif : "
            + feasibility_labels[exposure["patch_feasibility"]]
        )

    if exposure.get("sample_device_names"):
        lines.append(
            "- Exemples de devices concernés : "
            + ", ".join(exposure["sample_device_names"])
        )

    return "\n".join(lines)


def build_prompt(vulnerability, exposure):
    """
    vulnerability: a sqlite3.Row or dict with at least
        cve_id, vulnerability_name, description / nvd_description,
        cvss_v3_score, priority, risk_score, known_ransomware
    exposure: dict returned by database.get_exposure_context()
    """

    description = (
        vulnerability.get("nvd_description")
        or vulnerability.get("description")
        or "Pas de description disponible."
    )

    cvss = (
        vulnerability.get("cvss_v3_score")
        or vulnerability.get("cvss_v4_score")
    )

    exposure_block = _format_exposure(exposure)

    return f"""Tu es un analyste SOC senior. Analyse la vulnérabilité suivante \
pour un(e) administrateur systèmes/sécurité qui doit prioriser sa remédiation. \
Réponds UNIQUEMENT en JSON valide, en français, avec exactement ces clés :

{{
  "resume": "résumé de la vulnérabilité en 2-3 phrases, clair pour un non-expert",
  "impact": "impact concret pour CETTE organisation, en t'appuyant sur l'exposition interne donnée ci-dessous",
  "recommandation": "action de remédiation concrète et priorisée, 1-3 phrases",
  "confiance": "faible, moyenne ou élevée (ta confiance dans cette analyse)"
}}

Ne mets aucun texte hors du JSON.

IMPORTANT pour "recommandation" : n'analyse JAMAIS la CVE isolément — \
appuie-toi sur la "Faisabilité du correctif" donnée dans l'exposition \
interne ci-dessous. Si elle est FUSIBLE, recommande d'appliquer la mise \
à jour indiquée. Si elle est NON FUSIBLE ou PARTIELLEMENT FUSIBLE (par \
exemple : un composant tiers, comme une bibliothèque Apache embarquée \
dans une solution dont l'éditeur n'a pas encore publié de correctif, \
même si la solution elle-même est à jour), ne recommande PAS simplement \
"mettre à jour" — propose une ou plusieurs mesures d'atténuation \
concrètes et réalistes en attendant un correctif.

--- DONNÉES DE LA VULNÉRABILITÉ ---
CVE : {vulnerability.get("cve_id")}
Nom : {vulnerability.get("vulnerability_name") or "N/A"}
Éditeur / Produit : {vulnerability.get("vendor") or "N/A"} / {vulnerability.get("product") or "N/A"}
Description : {description}
Score CVSS : {cvss if cvss is not None else "inconnu"}
Priorité VulnWatch : {vulnerability.get("priority") or "UNKNOWN"} (score {vulnerability.get("risk_score")})
Exploitation ransomware connue : {vulnerability.get("known_ransomware") or "Unknown"}

--- EXPOSITION INTERNE (Microsoft Defender) ---
{exposure_block}
"""


# =========================================================
# OLLAMA CALL
# =========================================================

def _call_ollama(prompt):

    response = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": AI_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2
            }
        },
        timeout=REQUEST_TIMEOUT
    )

    response.raise_for_status()

    payload = response.json()

    raw_text = payload.get("response", "")

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Réponse du modèle non-JSON : {error}"
        ) from error

    return parsed


# =========================================================
# PUBLIC ENTRY POINT
# =========================================================

def generate_ai_enrichment(vulnerability, exposure):
    """
    Returns a dict ready for database.update_ai_enrichment(), or raises
    on any failure (network, timeout, malformed model output) so the
    caller can record it via database.update_ai_status().
    """

    prompt = build_prompt(vulnerability, exposure)

    parsed = _call_ollama(prompt)

    for required_key in ("resume", "impact", "recommandation", "confiance"):
        if required_key not in parsed:
            raise RuntimeError(
                f"Clé manquante dans la réponse du modèle : {required_key}"
            )

    return {
        "ai_summary": parsed.get("resume"),
        "ai_impact": parsed.get("impact"),
        "ai_recommendation": parsed.get("recommandation"),
        "ai_confidence": parsed.get("confiance"),
        "ai_model": AI_MODEL,
        "ai_generated_at": datetime.now(timezone.utc).isoformat()
    }


# =========================================================
# NOTIFICATION EMAILS (alerte propriétaire de serveur)
# =========================================================

def _format_vulnerability_block(vulnerability, exposure):

    description = (
        vulnerability.get("nvd_description")
        or vulnerability.get("description")
        or "Pas de description disponible."
    )

    cvss = (
        vulnerability.get("cvss_v3_score")
        or vulnerability.get("cvss_v4_score")
    )

    ai_recommendation = vulnerability.get("ai_recommendation")

    return f"""CVE : {vulnerability.get("cve_id")}
Nom : {vulnerability.get("vulnerability_name") or "N/A"}
Éditeur / Produit : {vulnerability.get("vendor") or "N/A"} / {vulnerability.get("product") or "N/A"}
Description : {description}
Score CVSS : {cvss if cvss is not None else "inconnu"}
Priorité VulnWatch : {vulnerability.get("priority") or "UNKNOWN"}
Exploitation ransomware connue : {vulnerability.get("known_ransomware") or "Unknown"}
Date limite de remédiation (CISA) : {vulnerability.get("due_date") or "N/A"}
Recommandation IA déjà générée pour cette CVE : {ai_recommendation or "Aucune"}
Exposition interne (Defender) : {_format_exposure(exposure)}"""


def _build_email_prompt(vulnerabilities, device_name, is_reminder, reminder_count):
    """
    vulnerabilities : liste de dicts {"vulnerability": <row>, "exposure": <ctx>},
    TOUTES les CVE CISA KEV actuellement regroupées pour ce serveur dans
    ce même e-mail (nouvelle "philosophie" : un e-mail par serveur,
    plutôt qu'un e-mail par CVE).
    """

    top_priority = max(
        (item["vulnerability"].get("priority") or "UNKNOWN")
        for item in vulnerabilities
    ) if vulnerabilities else "UNKNOWN"

    blocks = "\n\n".join(
        f"[Vulnérabilité {index + 1}/{len(vulnerabilities)}]\n"
        + _format_vulnerability_block(item["vulnerability"], item["exposure"])
        for index, item in enumerate(vulnerabilities)
    )

    context_note = (
        f"""Ceci est une RELANCE n°{reminder_count} : un premier e-mail a déjà \
été envoyé pour ce serveur, et {"cette vulnérabilité" if len(vulnerabilities) == 1 else "ces vulnérabilités"} \
sont TOUJOURS présentes. Le ton doit être plus insistant sur l'urgence de la \
remédiation, sans être agressif."""
        if is_reminder
        else
        """Ceci est le PREMIER e-mail envoyé au propriétaire pour ce serveur : \
au moins une des vulnérabilités listées ci-dessous a une criticité suffisante \
pour déclencher cet envoi ; les autres vulnérabilités listées (moins \
critiques) sont regroupées dans le même e-mail plutôt que d'envoyer un \
message séparé pour chacune."""
    )

    return f"""Tu es un analyste SOC qui rédige un e-mail professionnel en \
français, destiné au propriétaire technique d'un serveur, pour l'alerter \
que {"une vulnérabilité" if len(vulnerabilities) == 1 else f"{len(vulnerabilities)} vulnérabilités"} \
du catalogue CISA KEV (activement exploitée{"" if len(vulnerabilities) == 1 else "s"}) \
{"est présente" if len(vulnerabilities) == 1 else "sont présentes"} sur SON serveur. \
Réponds UNIQUEMENT en JSON valide avec exactement ces clés :

{{
  "sujet": "objet de l'e-mail, concis, incluant le nom du serveur et le nombre de vulnérabilités (ou son identifiant CVE si une seule)",
  "corps": "corps de l'e-mail complet (formule d'appel, contexte, liste claire des vulnérabilités AVEC pour chacune une action recommandée précise, formule de politesse), sans balises HTML, texte brut uniquement"
}}

Ne mets aucun texte hors du JSON.

IMPORTANT pour l'action recommandée de CHAQUE vulnérabilité : n'analyse \
jamais une CVE isolément — appuie-toi sur la "Faisabilité du correctif" \
donnée dans son exposition interne (Defender) ci-dessous. Si elle est \
FUSIBLE, recommande clairement d'appliquer la mise à jour indiquée. Si \
elle est NON FUSIBLE ou PARTIELLEMENT FUSIBLE (par exemple : un composant \
tiers, comme une bibliothèque Apache embarquée dans une solution dont \
l'éditeur n'a pas encore publié de correctif, même si la solution \
elle-même est par ailleurs à jour), n'écris PAS simplement "mettez à \
jour" — propose une ou plusieurs mesures d'atténuation concrètes et \
réalistes à appliquer en attendant un correctif (isolement/segmentation \
réseau, restriction d'accès, WAF/reverse proxy, désactivation du module \
ou de la fonctionnalité vulnérable si possible, renforcement de la \
surveillance). Chaque vulnérabilité du groupe peut avoir une faisabilité \
différente : traite-les individuellement dans le corps de l'e-mail.

{context_note}

--- SERVEUR CONCERNÉ ---
Nom du serveur : {device_name}
Priorité la plus élevée du groupe : {top_priority}
Nombre de vulnérabilités regroupées dans cet e-mail : {len(vulnerabilities)}

--- VULNÉRABILITÉS ---
{blocks}
"""


def _fallback_email(vulnerabilities, device_name, is_reminder, reminder_count):
    """
    Modèle de secours utilisé si Ollama est indisponible ou renvoie
    une erreur, pour ne jamais bloquer l'envoi de la notification.

    vulnerabilities : liste de dicts {"vulnerability": <row>, "exposure": <ctx>}.
    """

    cve_ids = [item["vulnerability"].get("cve_id") for item in vulnerabilities]

    if len(vulnerabilities) == 1:
        vuln = vulnerabilities[0]["vulnerability"]
        subject_subject = vuln.get("cve_id")
    else:
        subject_subject = f"{len(vulnerabilities)} vulnérabilités"

    # Sans IA disponible, on ne peut pas rédiger une recommandation
    # nuancée par CVE, mais on peut au moins refléter la faisabilité du
    # correctif (voir database.get_exposure_context) plutôt que de
    # toujours dire "mettez à jour" : une CVE dans un composant tiers
    # sans correctif disponible (ex: lib Apache embarquée non patchée
    # par son éditeur) doit pointer vers une atténuation, pas un patch
    # qui n'existe pas.
    feasibility_actions = {
        "FEASIBLE": lambda updates: (
            "Action : appliquer la mise à jour disponible"
            + (f" ({', '.join(updates)})" if updates else "") + "."
        ),
        "PARTIAL": lambda updates: (
            "Action : appliquer la mise à jour là où elle est "
            "disponible" + (f" ({', '.join(updates)})" if updates else "")
            + ", et mettre en place une atténuation (segmentation "
            "réseau, restriction d'accès, WAF) pour les autres devices."
        ),
        "NOT_FEASIBLE": lambda updates: (
            "Action : aucun correctif éditeur disponible à ce jour "
            "— mettre en place une atténuation en attendant (isolement/"
            "segmentation réseau, restriction d'accès, WAF/reverse "
            "proxy, désactivation du module vulnérable si possible, "
            "surveillance renforcée)."
        )
    }

    lines = []

    for item in vulnerabilities:

        vuln = item["vulnerability"]
        exposure = item.get("exposure") or {}

        action_builder = feasibility_actions.get(
            exposure.get("patch_feasibility")
        )

        action = (
            action_builder(exposure.get("recommended_updates"))
            if action_builder
            else "Action : évaluer la disponibilité d'un correctif et, "
                 "à défaut, une mesure d'atténuation."
        )

        lines.append(
            f"- {vuln.get('cve_id')} ({vuln.get('vulnerability_name') or 'N/A'}) "
            f"— priorité {vuln.get('priority') or 'INCONNUE'} "
            f"— date limite CISA : {vuln.get('due_date') or 'non communiquée'}\n"
            f"  {action}"
        )

    listing = "\n".join(lines)

    if is_reminder:

        subject = (
            f"[RELANCE {reminder_count}] {subject_subject} toujours "
            f"actif{'s' if len(vulnerabilities) > 1 else ''} sur {device_name}"
        )

        body = (
            f"Bonjour,\n\n"
            f"Il s'agit d'une relance : "
            f"{'la vulnérabilité suivante est' if len(vulnerabilities) == 1 else 'les vulnérabilités suivantes sont'} "
            f"toujours détectée{'s' if len(vulnerabilities) > 1 else ''} sur le "
            f"serveur {device_name} :\n\n"
            f"{listing}\n\n"
            f"Ces CVE font partie du catalogue CISA KEV (exploitation active "
            f"connue) et doivent être traitées en priorité.\n\n"
            f"Merci de traiter ces vulnérabilités dès que possible et de "
            f"confirmer leur remédiation.\n\n"
            f"— VulnWatch AI"
        )

    else:

        subject = (
            f"[VulnWatch AI] {subject_subject} détecté"
            f"{'s' if len(vulnerabilities) > 1 else ''} sur {device_name}"
        )

        body = (
            f"Bonjour,\n\n"
            f"{'Une vulnérabilité' if len(vulnerabilities) == 1 else f'{len(vulnerabilities)} vulnérabilités'} "
            f"du catalogue CISA KEV "
            f"{'a été détectée' if len(vulnerabilities) == 1 else 'ont été détectées'} "
            f"sur le serveur dont vous êtes propriétaire ({device_name}) :\n\n"
            f"{listing}\n\n"
            f"Merci de planifier la remédiation de ces vulnérabilités. "
            f"Un rappel automatique sera envoyé si elles sont toujours "
            f"présentes après le délai prévu pour leur niveau de criticité.\n\n"
            f"— VulnWatch AI"
        )

    return {"sujet": subject, "corps": body}


def generate_notification_email(
    vulnerabilities,
    device_name,
    is_reminder=False,
    reminder_count=0
):
    """
    vulnerabilities : liste de dicts {"vulnerability": <row depuis
    vulnerabilities>, "exposure": <get_exposure_context(...)>} — TOUTES
    les CVE CISA KEV actuellement regroupées pour ce serveur dans un
    seul e-mail (nouvelle "philosophie" : un e-mail par serveur).

    Returns {"sujet": ..., "corps": ...} for the owner notification
    email. Uses the local LLM when available, and falls back to a
    plain template otherwise so a down/missing Ollama never blocks
    sending the notification itself.
    """

    if not vulnerabilities:
        raise ValueError("Aucune vulnérabilité à notifier.")

    if not is_ollama_available():
        return _fallback_email(
            vulnerabilities, device_name, is_reminder, reminder_count
        )

    prompt = _build_email_prompt(
        vulnerabilities, device_name, is_reminder, reminder_count
    )

    try:

        parsed = _call_ollama(prompt)

        if "sujet" not in parsed or "corps" not in parsed:
            raise RuntimeError("Clés 'sujet'/'corps' manquantes")

        return {
            "sujet": parsed["sujet"],
            "corps": parsed["corps"]
        }

    except Exception:

        return _fallback_email(
            vulnerabilities, device_name, is_reminder, reminder_count
        )


# =========================================================
# ALERTES DE VEILLE (liste de diffusion, pas liée à un propriétaire)
# =========================================================
#
# Contexte différent des e-mails de notification par serveur
# ci-dessus : ici la CVE peut être toute fraîche (ex: un 0-day type
# "PHP2Shell" annoncé par un fournisseur) et pas forcément déjà dans
# la table `vulnerabilities` (CISA KEV / NVD) — seule la détection
# Defender (table defender_vulnerabilities) est garantie. Le
# `detection` passé ici vient de database.get_recent_defender_detections()
# et `devices` de database.get_devices_for_cve().

def _build_watch_alert_prompt(detection, devices):

    cve_id = detection.get("cve_id")

    severity = (
        detection.get("cisa_priority")
        or detection.get("defender_severity")
        or "INCONNUE"
    )

    cvss = (
        detection.get("nvd_cvss_v3_score")
        or detection.get("defender_cvss_score")
    )

    device_lines = "\n".join(
        f"- {device.get('device_name') or device.get('device_id')} "
        f"({device.get('os_platform') or 'OS inconnu'}, "
        f"{device.get('software_name') or 'logiciel inconnu'} "
        f"{device.get('software_version') or ''})"
        for device in devices[:50]
    )

    if len(devices) > 50:
        device_lines += f"\n... et {len(devices) - 50} autre(s) équipement(s)."

    cisa_note = (
        f"Cette CVE est référencée au catalogue CISA KEV "
        f"(exploitation active connue), priorité {detection.get('cisa_priority')}, "
        f"date limite de remédiation CISA : {detection.get('cisa_due_date') or 'N/A'}."
        if detection.get("cisa_source") == "CISA KEV"
        else
        "Cette CVE n'est PAS (encore) référencée au catalogue CISA KEV : "
        "il s'agit d'une détection issue directement du moteur Microsoft "
        "Defender XDR, à traiter en veille proactive avant toute "
        "confirmation d'exploitation active."
    )

    return f"""Tu es un analyste SOC qui rédige une alerte de veille par \
e-mail, en français, destinée à une liste de diffusion interne (équipe \
sécurité / management), pour signaler qu'une vulnérabilité a été détectée \
dans l'environnement par Microsoft Defender XDR. Réponds UNIQUEMENT en \
JSON valide avec exactement ces clés :

{{
  "sujet": "objet de l'e-mail, concis, incluant l'identifiant CVE et sa criticité",
  "corps": "corps de l'e-mail complet (contexte, criticité, actifs touchés, action attendue, formule de politesse), sans balises HTML, texte brut uniquement"
}}

Ne mets aucun texte hors du JSON. Le corps doit clairement faire apparaître :
1) la vulnérabilité (CVE, nom si connu, description courte),
2) la criticité (priorité CISA et/ou sévérité Defender, score CVSS),
3) la liste des actifs touchés dans notre environnement.

{cisa_note}

--- VULNÉRABILITÉ ---
CVE : {cve_id}
Nom (si connu) : {detection.get("vulnerability_name") or "N/A"}
Éditeur / Produit (Defender) : {detection.get("software_vendor") or "N/A"} / {detection.get("software_name") or "N/A"}
Priorité CISA : {detection.get("cisa_priority") or "N/A"}
Sévérité Defender : {detection.get("defender_severity") or "N/A"}
Score CVSS : {cvss if cvss is not None else "inconnu"}
Niveau d'exploitabilité (Defender) : {detection.get("exploitability_level") or "N/A"}
Mise à jour recommandée (Defender) : {detection.get("recommended_security_update") or "Aucune / inconnue"}
Première détection dans l'environnement : {detection.get("first_seen") or "N/A"}

--- ACTIFS TOUCHÉS ({len(devices)}) ---
{device_lines or "Aucun équipement listé."}
"""


def _fallback_watch_alert(detection, devices):
    """
    Modèle de secours si Ollama est indisponible, pour ne jamais
    bloquer l'envoi d'une alerte de veille.
    """

    cve_id = detection.get("cve_id")

    severity = (
        detection.get("cisa_priority")
        or detection.get("defender_severity")
        or "INCONNUE"
    )

    cvss = (
        detection.get("nvd_cvss_v3_score")
        or detection.get("defender_cvss_score")
    )

    subject = f"[VEILLE VulnWatch AI] {cve_id} — criticité {severity} — {len(devices)} actif(s) touché(s)"

    device_lines = "\n".join(
        f"- {device.get('device_name') or device.get('device_id')} "
        f"({device.get('os_platform') or 'OS inconnu'}, "
        f"{device.get('software_name') or 'logiciel inconnu'} "
        f"{device.get('software_version') or ''})"
        for device in devices[:50]
    )

    if len(devices) > 50:
        device_lines += f"\n... et {len(devices) - 50} autre(s) équipement(s)."

    cisa_line = (
        "Cette CVE est référencée au catalogue CISA KEV (exploitation "
        f"active connue), date limite CISA : {detection.get('cisa_due_date') or 'N/A'}."
        if detection.get("cisa_source") == "CISA KEV"
        else
        "Cette CVE n'est pas (encore) référencée au catalogue CISA KEV : "
        "détection issue directement de Microsoft Defender XDR."
    )

    body = (
        f"Bonjour,\n\n"
        f"Une vulnérabilité a été détectée dans l'environnement par "
        f"Microsoft Defender XDR :\n\n"
        f"- CVE : {cve_id}\n"
        f"- Nom : {detection.get('vulnerability_name') or 'N/A'}\n"
        f"- Produit concerné : {detection.get('software_vendor') or 'N/A'} / "
        f"{detection.get('software_name') or 'N/A'}\n"
        f"- Criticité : {severity}"
        + (f" (CVSS {cvss})" if cvss is not None else "") + "\n"
        f"- {cisa_line}\n\n"
        f"Actifs touchés ({len(devices)}) :\n"
        f"{device_lines or 'Aucun équipement listé.'}\n\n"
        f"Merci de prendre connaissance de cette alerte et de prioriser "
        f"son traitement selon la criticité indiquée.\n\n"
        f"— VulnWatch AI"
    )

    return {"sujet": subject, "corps": body}


def generate_watch_alert_email(detection, devices):
    """
    detection : dict issu de database.get_recent_defender_detections().
    devices : liste de dicts issue de database.get_devices_for_cve().

    Returns {"sujet": ..., "corps": ...}. Utilise le LLM local quand
    disponible, et retombe sur un modèle déterministe sinon.
    """

    if not is_ollama_available():
        return _fallback_watch_alert(detection, devices)

    prompt = _build_watch_alert_prompt(detection, devices)

    try:

        parsed = _call_ollama(prompt)

        if "sujet" not in parsed or "corps" not in parsed:
            raise RuntimeError("Clés 'sujet'/'corps' manquantes")

        return {
            "sujet": parsed["sujet"],
            "corps": parsed["corps"]
        }

    except Exception:

        return _fallback_watch_alert(detection, devices)
