"""
Découverte automatique des correspondances machine (adresse IP) -> hôte,
pour remplir la table « Correspondances machine → hôte » sans saisie.

Trois sources, de la plus fiable à la plus large :

  1. Microsoft Defender (Advanced Hunting, table DeviceNetworkInfo) :
     adresses IP de chaque machine gérée par Defender, sur les N derniers
     jours. Permission déjà requise par l'appli : AdvancedQuery.Read.All.
     Pour une adresse vue sur plusieurs machines (DHCP), la plus récente
     est retenue et l'ambiguïté est signalée.

  2. Le CSV Nessus lui-même : les plugins d'information (Risk = None)
     contiennent souvent le nom de la machine scannée :
       - 12053 « Host Fully Qualified Domain Name (FQDN) Resolution »
         (« 10.1.2.3 resolves as srv01.domaine.local. ») ;
       - 10150 « Windows NetBIOS / SMB Remote Host Information
         Disclosure » (« SRV01 = Computer name ») ;
       - 55472 « Device Hostname » (« Hostname : srv01 »).
     À condition d'exporter le scan AVEC les résultats informatifs.

  3. DNS inverse (PTR) depuis le serveur VulnWatch : utile pour les
     équipements absents de Defender (switchs, iLO, imprimantes...),
     si la zone inverse est renseignée dans le DNS.

Ce module ne fait que proposer : l'enregistrement se fait après
validation dans l'interface (scan_store.import_host_map, sans écraser
les correspondances existantes par défaut).
"""

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait


DEFENDER_LOOKBACK_DAYS = 14

# Adresses demandées par requête (liste « in ») : reste loin des limites
# de taille d'une requête Advanced Hunting.
DEFENDER_ADDRESS_BATCH = 300

# Adresses IPv4 vues par Defender sur chaque machine, dernière machine
# vue par adresse. IPv6, boucle locale et APIPA exclues.
DEFENDER_QUERY = """
DeviceNetworkInfo
| where Timestamp > ago({days}d)
| mv-expand IP = parse_json(IPAddresses)
| extend Address = tostring(IP.IPAddress)
| where Address matches regex @"^\\d{{1,3}}(\\.\\d{{1,3}}){{3}}$"
| where not(Address startswith "127.") and not(Address startswith "169.254.")
{address_filter}| summarize arg_max(Timestamp, DeviceName), Devices = dcount(DeviceName) by Address
| project Address, DeviceName, Devices, LastSeen = Timestamp
"""

NESSUS_PLUGIN_FQDN = "12053"
NESSUS_PLUGIN_NETBIOS = "10150"
NESSUS_PLUGIN_HOSTNAME = "55472"


def short_name(name, upper=True):
    """« liebkp01.alliumfr.corp.priv. » -> « LIEBKP01 »."""

    name = str(name or "").strip().rstrip(".")

    if not name:
        return ""

    try:
        ipaddress.ip_address(name)
        return ""          # une IP n'est pas un nom d'hôte
    except ValueError:
        pass

    name = name.split(".")[0]

    return name.upper() if upper else name


def _is_ipv4(value):

    try:
        return isinstance(ipaddress.ip_address(str(value).strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


# =========================================================
# 1. MICROSOFT DEFENDER
# =========================================================

def defender_query(days, addresses=None):
    """
    Requête KQL. `addresses` : ne chercher que ces IP (sinon toutes les
    adresses du parc).
    """

    days = max(1, min(int(days), 30))   # Advanced Hunting : 30 jours max

    address_filter = ""

    if addresses:
        quoted = ", ".join(f'"{a}"' for a in addresses)
        address_filter = f"| where Address in (dynamic([{quoted}]))\n"

    return DEFENDER_QUERY.format(days=days, address_filter=address_filter)


def discover_from_defender(days=DEFENDER_LOOKBACK_DAYS, upper=True,
                           run_query=None, addresses=None):
    """
    Retourne une liste de propositions {machine, hote, source, detail}.
    `addresses` : ne chercher que ces IP (par exemple celles sans
    correspondance de la dernière analyse) ; None = tout le parc.
    `run_query` : pour les tests ; par défaut, l'Advanced Hunting de
    collectors.defender (application Entra ID, sinon Azure CLI).
    """

    if run_query is None:
        from collectors.defender import run_hunting_query as run_query

    if addresses is not None:

        # Seules des IPv4 valides entrent dans la requête (aucune autre
        # saisie n'est injectée dans le KQL).
        addresses = [a for a in dict.fromkeys(str(a).strip() for a in addresses) if _is_ipv4(a)]

        if not addresses:
            return []

        rows = []

        for start in range(0, len(addresses), DEFENDER_ADDRESS_BATCH):
            rows.extend(run_query(defender_query(
                days, addresses[start:start + DEFENDER_ADDRESS_BATCH]
            )))

    else:

        rows = run_query(defender_query(days))

    proposals = []

    for row in rows:

        address = str(row.get("Address") or "").strip()
        host = short_name(row.get("DeviceName"), upper)

        if not _is_ipv4(address) or not host:
            continue

        devices = int(row.get("Devices") or 1)

        detail = f"vue le {str(row.get('LastSeen') or '')[:10]}"

        if devices > 1:
            detail += (
                f" ; adresse portée par {devices} machines sur la période "
                "(DHCP ?) : la plus récente est retenue"
            )

        proposals.append({
            "machine": address,
            "hote": host,
            "source": "Defender",
            "detail": detail
        })

    return proposals


# =========================================================
# 2. CSV NESSUS (plugins d'information)
# =========================================================

_FQDN_RE = re.compile(r"resolves as\s+([A-Za-z0-9._-]+)", re.IGNORECASE)
_NETBIOS_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*=\s*Computer name", re.IGNORECASE | re.MULTILINE)
_HOSTNAME_RE = re.compile(r"Hostname\s*:\s*([A-Za-z0-9._-]+)", re.IGNORECASE)


def discover_from_nessus(frame, upper=True, addresses=None):
    """
    Noms de machine trouvés dans les résultats informatifs d'un export
    CSV Nessus (DataFrame de scan_import.read_nessus_csv). Un seul nom
    par adresse : FQDN, sinon NetBIOS, sinon « Device Hostname ».
    `addresses` : ne garder que ces IP ; None = toutes.
    """

    wanted = (
        {str(a).strip() for a in addresses} if addresses is not None else None
    )

    if frame is None or "Plugin Output" not in frame.columns:
        return []

    found = {}
    priority = {NESSUS_PLUGIN_FQDN: 0, NESSUS_PLUGIN_NETBIOS: 1, NESSUS_PLUGIN_HOSTNAME: 2}
    patterns = {
        NESSUS_PLUGIN_FQDN: _FQDN_RE,
        NESSUS_PLUGIN_NETBIOS: _NETBIOS_RE,
        NESSUS_PLUGIN_HOSTNAME: _HOSTNAME_RE
    }
    labels = {
        NESSUS_PLUGIN_FQDN: "Nessus 12053 (FQDN)",
        NESSUS_PLUGIN_NETBIOS: "Nessus 10150 (NetBIOS)",
        NESSUS_PLUGIN_HOSTNAME: "Nessus 55472 (Device Hostname)"
    }

    for _, line in frame.iterrows():

        plugin = str(line.get("Plugin ID") or "").strip()

        if plugin not in patterns:
            continue

        address = str(line.get("Host") or "").strip()

        if not _is_ipv4(address) or (wanted is not None and address not in wanted):
            continue

        match = patterns[plugin].search(str(line.get("Plugin Output") or ""))

        if not match:
            continue

        host = short_name(match.group(1), upper)

        if not host:
            continue

        current = found.get(address)

        if current is None or priority[plugin] < current[0]:
            found[address] = (priority[plugin], host, labels[plugin], match.group(1))

    return [
        {"machine": address, "hote": host, "source": "CSV Nessus",
         "detail": f"{label} : {raw}"}
        for address, (_, host, label, raw) in sorted(found.items())
    ]


# =========================================================
# 3. DNS INVERSE
# =========================================================

def discover_from_dns(addresses, upper=True, workers=16, timeout=20.0,
                      resolver=None):
    """
    Résolution inverse (PTR) des adresses données, en parallèle, avec un
    délai global. Retourne (propositions, adresses non résolues).
    `resolver` : pour les tests ; par défaut socket.gethostbyaddr.
    """

    resolver = resolver or (lambda ip: socket.gethostbyaddr(ip)[0])

    addresses = [a for a in dict.fromkeys(str(a).strip() for a in addresses) if _is_ipv4(a)]

    if not addresses:
        return [], []

    proposals = []
    unresolved = []

    pool = ThreadPoolExecutor(max_workers=min(workers, len(addresses)))

    try:

        futures = {pool.submit(resolver, ip): ip for ip in addresses}

        done, pending = wait(futures, timeout=timeout)

        for future in done:

            ip = futures[future]

            try:
                name = future.result()
            except (OSError, UnicodeError):
                unresolved.append(ip)
                continue

            host = short_name(name, upper)

            if host:
                proposals.append({
                    "machine": ip, "hote": host, "source": "DNS inverse",
                    "detail": str(name).rstrip(".")
                })
            else:
                unresolved.append(ip)

        unresolved.extend(futures[f] for f in pending)

    finally:
        # Les résolutions bloquées ne retiennent pas l'interface.
        pool.shutdown(wait=False, cancel_futures=True)

    return sorted(proposals, key=lambda p: _ip_key(p["machine"])), sorted(unresolved, key=_ip_key)


def _ip_key(value):

    try:
        return (0, int(ipaddress.ip_address(value)))
    except ValueError:
        return (1, str(value))


# =========================================================
# FUSION AVEC LA BASE
# =========================================================

def compare_with_existing(proposals, host_map):
    """
    Ajoute à chaque proposition son état par rapport à la base
    (`host_map` : {machine en minuscules: hôte}) :
      - « nouvelle »   : machine absente de la table ;
      - « identique »  : même hôte déjà enregistré ;
      - « différente » : un autre hôte est enregistré (non remplacé par
        défaut).
    Une machine proposée par plusieurs sources ne garde que la première
    (ordre des sources donné par l'appelant).
    """

    seen = set()
    result = []

    for proposal in proposals:

        key = proposal["machine"].lower()

        if key in seen:
            continue

        seen.add(key)

        current = host_map.get(key)

        if current is None:
            state = "nouvelle"
        elif current.lower() == proposal["hote"].lower():
            state = "identique"
        else:
            state = "différente"

        result.append({**proposal, "actuel": current, "etat": state})

    return sorted(result, key=lambda p: ({"nouvelle": 0, "différente": 1, "identique": 2}[p["etat"]], _ip_key(p["machine"])))
