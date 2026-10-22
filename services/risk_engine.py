from datetime import datetime, timezone


def parse_date(value):
    """Convert an ISO/date string to a timezone-aware datetime."""

    if not value:
        return None

    try:
        value = value.strip()

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        dt = datetime.fromisoformat(value)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt

    except (ValueError, TypeError):
        return None


def calculate_risk(vulnerability):
    """
    Calculate VulnWatch contextual risk score.

    This score is intentionally deterministic.
    It is NOT the NVD CVSS score.
    """

    score = 0
    reasons = []

    # -----------------------------------------------------
    # CISA KEV
    # -----------------------------------------------------

    source = str(
        vulnerability.get("source", "")
    ).upper()

    if "CISA" in source or vulnerability.get("cveID"):
        score += 30

        reasons.append(
            "Known exploited vulnerability (CISA KEV)"
        )


    # -----------------------------------------------------
    # Ransomware
    # -----------------------------------------------------

    ransomware = str(
        vulnerability.get(
            "knownRansomwareCampaignUse",
            ""
        )
    ).lower()

    if ransomware == "known":

        score += 20

        reasons.append(
            "Known ransomware campaign use"
        )


    # -----------------------------------------------------
    # CVSS
    # -----------------------------------------------------

    cvss = vulnerability.get(
        "cvss_v3_score"
    )

    if cvss is None:

        cvss = vulnerability.get(
            "cvss_v4_score"
        )

    try:
        cvss = float(cvss)
    except (TypeError, ValueError):
        cvss = None


    if cvss is not None:

        if cvss >= 9.0:

            score += 20

            reasons.append(
                f"Critical CVSS score ({cvss})"
            )

        elif cvss >= 7.0:

            score += 15

            reasons.append(
                f"High CVSS score ({cvss})"
            )

        elif cvss >= 4.0:

            score += 8

            reasons.append(
                f"Medium CVSS score ({cvss})"
            )


    # -----------------------------------------------------
    # Age
    # -----------------------------------------------------

    published = vulnerability.get(
        "nvd_published"
    )

    if published:

        published_date = parse_date(
            published
        )

        if published_date:

            now = datetime.now(
                timezone.utc
            )

            age_days = (
                now - published_date
            ).days

            if age_days > 180:

                score += 5

                reasons.append(
                    f"Vulnerability older than "
                    f"180 days ({age_days} days)"
                )


    # -----------------------------------------------------
    # Exploit / threat intelligence
    # -----------------------------------------------------

    # Reserved for future NVD / threat-intelligence
    # enrichment.

    exploit_available = vulnerability.get(
        "exploit_available",
        False
    )

    if exploit_available:

        score += 10

        reasons.append(
            "Public exploit available"
        )


    # -----------------------------------------------------
    # Cap
    # -----------------------------------------------------

    score = min(score, 100)


    # -----------------------------------------------------
    # Priority
    # -----------------------------------------------------

    if score >= 80:

        priority = "CRITICAL"

    elif score >= 60:

        priority = "HIGH"

    elif score >= 40:

        priority = "MEDIUM"

    else:

        priority = "LOW"


    return score, priority, reasons
