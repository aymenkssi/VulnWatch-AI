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
| `sync_software_inventory.py` | Importe l'inventaire logiciel de chaque machine (API Defender ou CSV) puis calcule les équipements touchés selon NVD ; en mode delta, ne retélécharge que les machines modifiées (`services/inventory_delta.py`) |
| `scheduled_sync.py` | Lance les synchros dues sans navigateur (Planificateur de tâches Windows, `services/scheduler.py`) |
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
arrière-plan lorsque les données sont périmées (`services/scheduler.py`), et
`scheduled_sync.py` fait de même sans navigateur ouvert. Les boutons « Synchroniser … »
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
| WindowsDefenderATP | `AdvancedQuery.Read.All` | Inventaire logiciel complet (Advanced Hunting, par lots de machines) |
| WindowsDefenderATP | `Software.Read.All` | Export de l'inventaire logiciel (secours) |
| WindowsDefenderATP | `User.Read.All` | Utilisateurs connectés aux machines |
| Microsoft Graph | `User.Read.All` | Nom et e-mail des propriétaires |

### Inventaire logiciel : delta et historique des changements

Onglet Veille > « Équipements touchés selon NVD » :

- **Vérifier les changements (delta)** : une requête Advanced Hunting légère
  (une ligne par machine) donne l'empreinte SHA-256 de la liste des logiciels
  de chaque machine. Seules les machines dont l'empreinte a changé depuis le
  dernier import, et les nouvelles, sont retéléchargées ; les machines
  disparues de Defender sont retirées ;
- **Import complet depuis Defender** : tout l'inventaire est retéléchargé
  (filet de sécurité) ;
- fréquences réglables : delta toutes les 1 à 24 h (6 h par défaut), import
  complet chaque jour à tous les 30 jours (7 par défaut). Automatique
  uniquement si le dernier import venait de Defender (pas d'un CSV).

Chaque changement (logiciel ajouté, supprimé, version modifiée, machine
apparue ou retirée) est enregistré avec les CVE NVD qu'il introduit ou
corrige : onglet Inventaire > « Changements ». Si un changement introduit une
CVE critique, un e-mail récapitulatif part à la liste de diffusion de veille.
Le premier import sert de référence (aucun changement enregistré).

### Synchros sans navigateur (Planificateur de tâches Windows)

Sans tâche planifiée, les synchros automatiques ne partent que lorsqu'une
page de l'application est ouverte. `scheduled_sync.py` lance les synchros
dues puis attend leur fin. En PowerShell administrateur :

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\VulnWatch-AI\.venv\Scripts\python.exe" `
           -Argument "scheduled_sync.py" -WorkingDirectory "C:\VulnWatch-AI"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
           -RepetitionInterval (New-TimeSpan -Minutes 15)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
           -ExecutionTimeLimit (New-TimeSpan -Hours 12)
Register-ScheduledTask -TaskName "VulnWatch AI - synchros" -Action $action `
           -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest
```

Avec le compte SYSTEM, utilisez l'application Azure (la connexion Azure CLI
d'un utilisateur n'est pas disponible pour ce compte). L'interface et la
tâche planifiée peuvent tourner ensemble : une synchro déjà en cours n'est
jamais relancée.

## Données

`data/` (base SQLite, exports Defender) et `imports/` (inventaires CSV) sont
exclus du dépôt : ils contiennent des données réelles du parc (noms de postes,
versions logicielles installées) qui ne doivent pas être publiées.
