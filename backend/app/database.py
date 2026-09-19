import sqlite3
from pathlib import Path


# cybermonitor.db is inside agent/
DATABASE_PATH = (
    Path(__file__).resolve().parents[2]
    / "agent"
    / "cybermonitor.db"
)


def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection
