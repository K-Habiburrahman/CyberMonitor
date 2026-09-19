# Risk score assigned to individual alert severities.
SEVERITY_SCORES = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 40,
    "CRITICAL": 60,
}


def calculate_risk(alerts):
    """
    Calculate a combined risk score from security alerts.

    Returns a value between 0 and 100.
    """

    if not alerts:
        return 0

    score = 0

    for alert in alerts:

        severity = alert.get("severity", "LOW").upper()

        score += SEVERITY_SCORES.get(
            severity,
            SEVERITY_SCORES["LOW"]
        )

    # Maximum risk score is 100.
    return min(score, 100)


def get_risk_level(score):
    """
    Convert numerical risk score into a readable level.
    """

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "SAFE"