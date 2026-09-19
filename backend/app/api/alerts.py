from fastapi import APIRouter

from ..database import get_connection


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"]
)


@router.get("/")
def get_alerts(limit: int = 50):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM security_events
        WHERE risk_score > 0
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    alerts = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return {
        "count": len(alerts),
        "alerts": alerts
    }
