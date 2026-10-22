# VulnWatch AI

Plateforme de veille et de priorisation des vulnérabilités. Elle croise les
CVE activement exploitées (CISA KEV) et le flux NVD avec l'inventaire réel du
parc (Microsoft Defender for Endpoint), puis enrichit les résultats grâce à une
IA locale (Ollama) et alerte les propriétaires des machines par e-mail.

## Architecture

```
collectors/          Récupération des données externes
  cisa.py            Catalogue CISA KEV (CVE exploitées)
  nvd.py             API NVD 2.0 (CVSS, CWE, références, flux récent)
  defender.py        Export SoftwareVulnerabilities de Defender (via Azure CLI)
  hexiosec.py        Surface d'attaque externe (Hexiosec ASM)
services/
  risk_engine.py     Score de risque déterministe (KEV, ransomware, CVSS, ancienneté…)
  ai_engine.py       Enrichissement et rédaction d'e-mails via Ollama (qwen2.5:7b par défaut)
  mailer.py          Envoi SMTP
database.py          Schéma SQLite (data/vulnwatch.db) et accès aux données
app.py               Interface Streamlit (tableau de bord, serveurs, KEV, CVE NVD,
                     investigation, notifications, surface d'attaque, veille)
```

### Scripts de synchronisation

| Script | Rôle |
|---|---|
| `sync.py` | Importe le catalogue CISA KEV et calcule le score de risque |
| `enrich.py` | Enrichit les CVE avec les données NVD |
| `sync_nvd_feed.py` | Flux NVD quotidien (CVE publiées et modifiées, reprise depuis la dernière fenêtre réussie) ; alerte les destinataires de veille si une nouvelle CVE touche le parc |
| `nvd_audit.py` | État de la base NVD : compare jour par jour avec nvd.nist.gov et rattrape les CVE manquantes (onglet Veille) |
| `sync_software_inventory.py` | Importe l'inventaire logiciel de chaque machine (API Defender ou CSV) puis calcule les équipements touchés selon NVD |
| `nvd_match.py` | Recalcule les équipements touchés selon NVD (inventaire logiciel × produits vulnérables CPE de NVD, `services/inventory_matcher.py`) |
| `nvd_cpe_sync.py` | Télécharge depuis l'API NVD les produits vulnérables (CPE) des CVE déjà en base |
| `nvd_import_files.py` | Importe des fichiers NVD (`.json.gz`) envoyés depuis l'onglet Veille |
| `sync_nvd_backfill.py` | Téléchargement historique NVD par fenêtres de 119 jours (reprise sur curseur) |
| `sync_defender.py` | Importe l'export de vulnérabilités Defender |
| `build_exposure.py` | Construit la table d'exposition CISA × Defender |
| `sync_asset_owners.py` | Associe les machines à leurs propriétaires (Defender + Microsoft Graph) |
| `sync_hexiosec.py` | Synchronise les risques et actifs Hexiosec ASM |
| `ai_enrich.py` | Enrichissement IA des CVE exposées |
| `notify.py` | Notifications et relances e-mail aux propriétaires |

L'application Streamlit lance automatiquement la plupart de ces scripts en
arrière-plan lorsque les données sont périmées. Les boutons « Synchroniser … »
les lancent aussi en arrière-plan (`services/jobs.py`) : l'interface reste
utilisable et affiche une barre de progression. L'état et le journal de chaque
synchro sont écrits dans `data/jobs/`.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Prérequis facultatifs :

- **Ollama** avec un modèle (`ollama pull qwen2.5:7b`) pour l'enrichissement IA ;
  sans Ollama, des modèles d'e-mail de secours sont utilisés.
- **Azure CLI** (`az login`) avec les droits Defender / Graph pour
  `sync_defender.py` et `sync_asset_owners.py`.

## Configuration

Variables d'environnement (fichier `.env` possible, non versionné) :

| Variable | Défaut | Description |
|---|---|---|
| `VULNWATCH_ADMIN_USER` | `admin` | Identifiant administrateur initial |
| `VULNWATCH_ADMIN_PASSWORD` | généré | Mot de passe initial (affiché une seule fois s'il est généré) |
| `VULNWATCH_SESSION_DAYS` | `30` | Durée de la connexion conservée dans le navigateur (jours), jusqu'à « Se déconnecter » |
| `VULNWATCH_AZURE_TENANT_ID` / `VULNWATCH_AZURE_CLIENT_ID` / `VULNWATCH_AZURE_CLIENT_SECRET` | — | Application Entra ID pour Defender et Graph (prioritaires sur la configuration de l'interface) |
| `VULNWATCH_NVD_API_KEY` | — | Clé API NVD (aussi configurable dans l'interface) |
| `VULNWATCH_NVD_DELAY` | `6` | Délai (s) entre deux appels NVD |
| `VULNWATCH_MAX_CVES` | `10` | CVE enrichies par passage NVD |
| `VULNWATCH_OLLAMA_URL` | `http://localhost:11434` | URL d'Ollama |
| `VULNWATCH_AI_MODEL` | `qwen2.5:7b` | Modèle Ollama |
| `VULNWATCH_AI_MAX_CVES` | `10` | CVE enrichies par passage IA |
| `VULNWATCH_AI_DELAY` | `1` | Délai (s) entre deux appels IA |
| `VULNWATCH_AI_TIMEOUT` | `120` | Timeout (s) d'un appel Ollama |

Les paramètres SMTP, Hexiosec et les délais de notification se règlent dans
l'interface et sont stockés dans la base SQLite.

### Comptes utilisateurs

Barre latérale > « Utilisateurs » (administrateurs) :

- **Administrateur** : tout (configuration, imports, synchronisations, comptes) ;
- **Lecteur** : consultation de tous les onglets, recherche et bouton
  « Rafraîchir les données » ; les boutons de configuration, d'import, de
  synchronisation et d'envoi d'e-mails sont désactivés.

À la création, l'option « Changer le mot de passe à la première connexion »
(cochée par défaut) impose un mot de passe personnel avant d'accéder à
l'application. Politique de mot de passe : au moins 15 caractères, un chiffre,
une lettre et un caractère spécial (exigences affichées, respectées ou non,
pendant la saisie). Le compte administrateur existant est repris
automatiquement. Le dernier administrateur actif ne peut être ni désactivé, ni
rétrogradé, ni supprimé.

### Accès à Microsoft Defender et Graph

Les synchros Defender (vulnérabilités, inventaire logiciel, propriétaires)
utilisent de préférence une **application Entra ID** (barre latérale >
« Application Azure », bouton « Tester »), sinon le compte connecté à Azure CLI
(`az login`). Permissions **Application** à accorder, avec consentement
administrateur :

| API | Permission | Usage |
|---|---|---|
| WindowsDefenderATP | `Vulnerability.Read.All` | Export des vulnérabilités |
| WindowsDefenderATP | `Software.Read.All` | Export de l'inventaire logiciel |
| WindowsDefenderATP | `User.Read.All` | Utilisateurs connectés aux machines |
| Microsoft Graph | `User.Read.All` | Nom et e-mail des propriétaires |

## Données

`data/` (base SQLite, exports Defender) et `imports/` (inventaires CSV) sont
exclus du dépôt : ils contiennent des données réelles du parc (noms de postes,
versions logicielles installées) qui ne doivent pas être publiées.
