import sqlite3
from datetime import datetime


DATABASE_PATH = "cybermonitor.db"


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            process_name TEXT,
            pid INTEGER,
            rule TEXT,
            message TEXT,
            file_path TEXT,
            remote_ip TEXT,
            remote_port INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_status (
            id INTEGER PRIMARY KEY,
            process_monitoring INTEGER,
            network_monitoring INTEGER,
            file_monitoring INTEGER,
            port_scanning INTEGER,
            database_status INTEGER,
            last_heartbeat TEXT
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO agent_status
        VALUES (1, 0, 0, 0, 0, 0, NULL)
    """)

    connection.commit()
    connection.close()


def update_agent_status(
    process_monitoring,
    network_monitoring,
    file_monitoring,
    port_scanning,
    database_status
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE agent_status
        SET process_monitoring = ?,
            network_monitoring = ?,
            file_monitoring = ?,
            port_scanning = ?,
            database_status = ?,
            last_heartbeat = ?
        WHERE id = 1
    """, (
        process_monitoring,
        network_monitoring,
        file_monitoring,
        port_scanning,
        database_status,
        datetime.now().isoformat()
    ))

    connection.commit()
    connection.close()


def get_agent_status():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM agent_status
        WHERE id = 1
    """)

    status = cursor.fetchone()

    connection.close()

    return status


def save_event(
    event_type,
    severity=None,
    risk_score=0,
    risk_level="SAFE",
    process_name=None,
    pid=None,
    rule=None,
    message=None,
    file_path=None,
    remote_ip=None,
    remote_port=None
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events (
            timestamp,
            event_type,
            severity,
            risk_score,
            risk_level,
            process_name,
            pid,
            rule,
            message,
            file_path,
            remote_ip,
            remote_port
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        event_type,
        severity,
        risk_score,
        risk_level,
        process_name,
        pid,
        rule,
        message,
        file_path,
        remote_ip,
        remote_port
    ))

    connection.commit()
    connection.close()


def get_recent_events(limit=50):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    events = cursor.fetchall()

    connection.close()

    return events
