from fastapi import APIRouter
from ..database import get_connection

router = APIRouter(prefix="/api/threats", tags=["Threats"])


@router.get("/")
def get_threats(limit: int = 50):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM security_events
        WHERE risk_score >= 70
        ORDER BY id DESC
        LIMIT ?
    """,
        (limit,),
    )

    threats = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return {"count": len(threats), "threats": threats}
