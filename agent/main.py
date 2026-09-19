import os
import time
import threading
import signal
import sys

from collectors.file_monitor import (
    get_file_snapshot,
    detect_file_changes
)

from collectors.process_monitor import (
    get_running_processes
)

from collectors.network_monitor import (
    get_network_connections
)

from collectors.port_scanner import (
    get_listening_ports
)

from detection.threat_detector import (
    analyze_process,
    analyze_network
)

from detection.risk_engine import (
    calculate_risk,
    get_risk_level
)

from storage.database import (
    initialize_database,
    save_event
)


# ============================================================
# CONFIGURATION
# ============================================================

SCAN_INTERVAL = 5


# ============================================================
# SHUTDOWN CONTROL
# ============================================================

shutdown_event = threading.Event()


# ============================================================
# SIGNAL HANDLER
# ============================================================

def handle_shutdown_signal(signum, frame):

    if shutdown_event.is_set():
        return

    print("\n\n[SHUTDOWN] Ctrl+C received.")
    print("[SHUTDOWN] Stopping CyberMonitor...")

    shutdown_event.set()


# ============================================================
# PORT IDENTIFIER
# ============================================================

def get_port_id(port):

    """
    Create a unique identifier for a listening port.
    """

    return (
        port.get("protocol"),
        port.get("local_ip"),
        port.get("port"),
        port.get("pid")
    )


# ============================================================
# DISPLAY PORT
# ============================================================

def display_port(port):

    print(
        f"\n[LISTENING PORT] "
        f"{port.get('local_ip')}:{port.get('port')}"
    )

    print(
        f"  Protocol : {port.get('protocol')}"
    )

    print(
        f"  State    : {port.get('state')}"
    )

    print(
        f"  Process  : {port.get('process_name')}"
    )

    print(
        f"  PID      : {port.get('pid')}"
    )

    print(
        f"  Service  : {port.get('service')}"
    )

    print(
        f"  Risk     : {port.get('risk_level')}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # REGISTER CTRL+C HANDLER
    # ========================================================

    signal.signal(
        signal.SIGINT,
        handle_shutdown_signal
    )

    if hasattr(signal, "SIGTERM"):

        signal.signal(
            signal.SIGTERM,
            handle_shutdown_signal
        )


    # ========================================================
    # DATABASE INITIALIZATION
    # ========================================================

    initialize_database()

    print("=" * 60)
    print("        CyberMonitor Security Agent")
    print("=" * 60)

    print("\nMonitoring started...")

    print(
        f"Scan interval: {SCAN_INTERVAL} seconds"
    )

    print(
        "Database: cybermonitor.db\n"
    )


    # ========================================================
    # INITIAL STATE
    # ========================================================

    previous_processes = {}

    previous_connections = set()

    previous_files = get_file_snapshot()

    # --------------------------------------------------------
    # PORT STATE
    # --------------------------------------------------------

    print("[PORT SCANNER] Initializing...")

    try:

        initial_ports = get_listening_ports()

        previous_ports = {
            get_port_id(port): port
            for port in initial_ports
        }

        print(
            f"[PORT SCANNER] "
            f"{len(previous_ports)} listening port(s) found."
        )

    except Exception as error:

        print(
            "[PORT SCANNER ERROR]",
            error
        )

        previous_ports = {}


    # ========================================================
    # MAIN MONITORING LOOP
    # ========================================================

    try:

        while not shutdown_event.is_set():

            try:

                # ==================================================
                # PROCESS MONITORING
                # ==================================================

                processes = get_running_processes()

                process_map = {
                    process["pid"]: process
                    for process in processes
                }

                for pid, process in process_map.items():

                    if shutdown_event.is_set():
                        break

                    # Detect newly started process.
                    if pid not in previous_processes:

                        print(
                            f"\n[NEW PROCESS] "
                            f"{process['name']} "
                            f"(PID: {pid})"
                        )

                        threat = analyze_process(
                            process
                        )

                        if threat:

                            score = calculate_risk(
                                threat["alerts"]
                            )

                            level = get_risk_level(
                                score
                            )

                            print(
                                f"[PROCESS ALERT] "
                                f"{process['name']} "
                                f"| Risk: {score}/100 "
                                f"| Level: {level}"
                            )

                            for alert in threat["alerts"]:

                                print(
                                    f"  {alert['severity']} | "
                                    f"{alert['rule']} | "
                                    f"{alert['message']}"
                                )

                                save_event(
                                    event_type="PROCESS_ALERT",
                                    severity=alert["severity"],
                                    risk_score=score,
                                    risk_level=level,
                                    process_name=process["name"],
                                    pid=process["pid"],
                                    rule=alert["rule"],
                                    message=alert["message"]
                                )


                # ==================================================
                # NETWORK MONITORING
                # ==================================================

                if shutdown_event.is_set():
                    break

                connections = (
                    get_network_connections()
                )

                current_connections = set()

                for connection in connections:

                    if shutdown_event.is_set():
                        break

                    connection_id = (
                        connection["pid"],
                        connection["local_ip"],
                        connection["local_port"],
                        connection["remote_ip"],
                        connection["remote_port"]
                    )

                    current_connections.add(
                        connection_id
                    )

                    # Detect new connection.
                    if (
                        connection_id
                        not in previous_connections
                    ):

                        print(
                            f"\n[NEW CONNECTION] "
                            f"{connection['process_name']} "
                            f"→ "
                            f"{connection['remote_ip']}:"
                            f"{connection['remote_port']}"
                        )

                        threat = analyze_network(
                            connection
                        )

                        if threat:

                            score = calculate_risk(
                                threat["alerts"]
                            )

                            level = get_risk_level(
                                score
                            )

                            print(
                                f"[NETWORK ALERT] "
                                f"{connection['process_name']} "
                                f"| Risk: {score}/100 "
                                f"| Level: {level}"
                            )

                            for alert in threat["alerts"]:

                                print(
                                    f"  {alert['severity']} | "
                                    f"{alert['rule']} | "
                                    f"{alert['message']}"
                                )

                                save_event(
                                    event_type="NETWORK_ALERT",
                                    severity=alert["severity"],
                                    risk_score=score,
                                    risk_level=level,
                                    process_name=connection[
                                        "process_name"
                                    ],
                                    pid=connection["pid"],
                                    rule=alert["rule"],
                                    message=alert["message"],
                                    remote_ip=connection[
                                        "remote_ip"
                                    ],
                                    remote_port=connection[
                                        "remote_port"
                                    ]
                                )


                # ==================================================
                # FILE MONITORING
                # ==================================================

                if shutdown_event.is_set():
                    break

                current_files = get_file_snapshot()

                file_events = detect_file_changes(
                    previous_files,
                    current_files
                )

                for event in file_events:

                    if shutdown_event.is_set():
                        break

                    file_path = event.get("path")

                    print(
                        f"\n[FILE {event['type']}] "
                        f"{file_path}"
                    )


                    # ==================================================
                    # RENAMED
                    # ==================================================

                    if event["type"] == "RENAMED":

                        old_path = event.get(
                            "old_path"
                        )

                        print(
                            f"[FILE RENAMED] "
                            f"{old_path} → {file_path}"
                        )

                        save_event(
                            event_type="FILE_RENAMED",
                            severity="LOW",
                            risk_score=0,
                            risk_level="SAFE",
                            file_path=file_path,
                            process_name=None,
                            pid=None,
                            rule=None,
                            message=(
                                f"File renamed: "
                                f"{old_path} → "
                                f"{file_path}"
                            )
                        )

                        continue


                    # ==================================================
                    # CREATED / DELETED / MODIFIED
                    # ==================================================

                    if event["suspicious"]:

                        print(
                            f"[FILE ALERT] "
                            f"Suspicious file type: "
                            f"{event['extension']}"
                        )

                        save_event(
                            event_type=(
                                f"FILE_{event['type']}"
                            ),
                            severity="HIGH",
                            risk_score=40,
                            risk_level="HIGH",
                            file_path=file_path,
                            process_name=None,
                            pid=None,
                            rule=(
                                "SUSPICIOUS_FILE_EXTENSION"
                            ),
                            message=(
                                f"Suspicious file type: "
                                f"{event['extension']}"
                            )
                        )

                    else:

                        save_event(
                            event_type=(
                                f"FILE_{event['type']}"
                            ),
                            severity="LOW",
                            risk_score=0,
                            risk_level="SAFE",
                            file_path=file_path,
                            process_name=None,
                            pid=None,
                            rule=None,
                            message=(
                                f"File "
                                f"{event['type'].lower()}: "
                                f"{file_path}"
                            )
                        )


                # ==================================================
                # PORT MONITORING
                # ==================================================

                if shutdown_event.is_set():
                    break

                try:

                    current_port_list = (
                        get_listening_ports()
                    )

                    current_ports = {
                        get_port_id(port): port
                        for port in current_port_list
                    }


                    # ------------------------------------------------
                    # NEW LISTENING PORT
                    # ------------------------------------------------

                    new_ports = (
                        set(current_ports.keys())
                        - set(previous_ports.keys())
                    )

                    for port_id in new_ports:

                        if shutdown_event.is_set():
                            break

                        port = current_ports[port_id]

                        print(
                            "\n" + "=" * 60
                        )

                        print(
                            "[NEW LISTENING PORT]"
                        )

                        print(
                            "=" * 60
                        )

                        display_port(port)


                        # --------------------------------------------
                        # Convert port risk to numeric risk score
                        # --------------------------------------------

                        risk_level = port.get(
                            "risk_level",
                            "UNKNOWN"
                        )

                        if risk_level == "HIGH":

                            risk_score = 70
                            severity = "HIGH"

                        elif risk_level == "MEDIUM":

                            risk_score = 40
                            severity = "MEDIUM"

                        elif risk_level == "LOW":

                            risk_score = 10
                            severity = "LOW"

                        else:

                            risk_score = 0
                            severity = "LOW"


                        # --------------------------------------------
                        # Save event
                        # --------------------------------------------

                        save_event(
                            event_type="PORT_OPENED",
                            severity=severity,
                            risk_score=risk_score,
                            risk_level=risk_level,
                            process_name=port.get(
                                "process_name"
                            ),
                            pid=port.get(
                                "pid"
                            ),
                            rule="NEW_LISTENING_PORT",
                            message=(
                                f"New listening TCP port: "
                                f"{port.get('port')} "
                                f"on {port.get('local_ip')}"
                            )
                        )


                    # ------------------------------------------------
                    # CLOSED LISTENING PORT
                    # ------------------------------------------------

                    closed_ports = (
                        set(previous_ports.keys())
                        - set(current_ports.keys())
                    )

                    for port_id in closed_ports:

                        if shutdown_event.is_set():
                            break

                        port = previous_ports[port_id]

                        print(
                            "\n[LISTENING PORT CLOSED] "
                            f"{port.get('local_ip')}:"
                            f"{port.get('port')} "
                            f"({port.get('process_name')})"
                        )

                        save_event(
                            event_type="PORT_CLOSED",
                            severity="LOW",
                            risk_score=0,
                            risk_level="SAFE",
                            process_name=port.get(
                                "process_name"
                            ),
                            pid=port.get(
                                "pid"
                            ),
                            rule="LISTENING_PORT_CLOSED",
                            message=(
                                f"Listening TCP port closed: "
                                f"{port.get('port')}"
                            )
                        )


                    # ------------------------------------------------
                    # UPDATE PORT STATE
                    # ------------------------------------------------

                    previous_ports = current_ports

                except Exception as error:

                    print(
                        "[PORT SCANNER ERROR]",
                        error
                    )


                # ==================================================
                # UPDATE STATE
                # ==================================================

                previous_processes = process_map

                previous_connections = (
                    current_connections
                )

                previous_files = current_files


                # ==================================================
                # WAIT
                # ==================================================

                shutdown_event.wait(
                    SCAN_INTERVAL
                )


            except Exception as error:

                if shutdown_event.is_set():
                    break

                print(
                    "\n[MONITORING ERROR]",
                    error
                )

                shutdown_event.wait(
                    SCAN_INTERVAL
                )


    finally:

        # ========================================================
        # SHUTDOWN
        # ========================================================

        shutdown_event.set()

        print(
            "\n[SHUTDOWN] CyberMonitor stopped."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()

    sys.exit(0)
