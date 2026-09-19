from fastapi import APIRouter

from ..database import get_connection


router = APIRouter(
    prefix="/api/events",
    tags=["Events"]
)


@router.get("/")
def get_events(limit: int = 50):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    events = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return {
        "count": len(events),
        "events": events
    }
