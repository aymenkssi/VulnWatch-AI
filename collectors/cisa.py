import requests

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def fetch_cisa_kev():
    print("Downloading CISA KEV...")

    response = requests.get(
        CISA_KEV_URL,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])

    return vulnerabilities
