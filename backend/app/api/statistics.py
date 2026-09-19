from fastapi import APIRouter

from ..database import get_connection


router = APIRouter(
    prefix="/api/statistics",
    tags=["Statistics"]
)


@router.get("/")
def get_statistics():

    connection = get_connection()

    cursor = connection.cursor()

    # Total events
    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
    """)

    total_events = cursor.fetchone()[0]

    # Total alerts
    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE risk_score > 0
    """)

    total_alerts = cursor.fetchone()[0]

    # High risk
    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE risk_score >= 70
    """)

    high_risk = cursor.fetchone()[0]

    # Medium risk
    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE risk_score >= 40
        AND risk_score < 70
    """)

    medium_risk = cursor.fetchone()[0]

    # Low risk
    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE risk_score > 0
        AND risk_score < 40
    """)

    low_risk = cursor.fetchone()[0]

    connection.close()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk
    }
