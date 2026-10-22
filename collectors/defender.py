import os
import subprocess
import requests


DEFENDER_API_URL = (
    "https://api.security.microsoft.com"
    "/api/machines/SoftwareVulnerabilitiesExport"
)


AZ_PATHS = [
    r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
    r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az",
    r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.exe",
    r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
    r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az",
    r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.exe",
]


def find_az():

    for path in AZ_PATHS:

        if os.path.isfile(path):
            return path

    for command in ["az.cmd", "az.exe", "az"]:

        result = subprocess.run(
            ["where.exe", command],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:

            path = result.stdout.strip().splitlines()[0]

            if path:
                return path

    raise FileNotFoundError(
        "Azure CLI not found."
    )


def get_access_token():

    az = find_az()

    result = subprocess.run(
        [
            az,
            "account",
            "get-access-token",
            "--resource",
            "https://api.securitycenter.microsoft.com",
            "--query",
            "accessToken",
            "-o",
            "tsv"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    token = result.stdout.strip()

    if not token:
        raise RuntimeError(
            "Azure CLI returned an empty token."
        )

    return token


def request_export(
    sas_valid_hours=6
):

    token = get_access_token()

    headers = {
        "Authorization": f"Bearer {token}"
    }

    params = {
        "sasValidHours": sas_valid_hours
    }

    response = requests.get(
        DEFENDER_API_URL,
        headers=headers,
        params=params,
        timeout=120
    )

    response.raise_for_status()

    data = response.json()

    export_files = data.get(
        "exportFiles",
        []
    )

    generated_time = data.get(
        "generatedTime"
    )

    if not export_files:

        raise RuntimeError(
            "Defender returned no export files."
        )

    return {
        "generated_time": generated_time,
        "export_files": export_files
    }


def download_export_file(
    url,
    destination
):

    response = requests.get(
        url,
        stream=True,
        timeout=300
    )

    response.raise_for_status()

    with open(
        destination,
        "wb"
    ) as output:

        for chunk in response.iter_content(
            chunk_size=1024 * 1024
        ):

            if chunk:
                output.write(chunk)

    return destination
