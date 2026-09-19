import socket
import psutil


# ============================================================
# PORT SCANNER
# ============================================================

def get_listening_ports():
    """
    Get TCP listening and UDP bound ports currently
    active on this machine.

    Returns:
        list[dict]
    """

    results = []

    try:
        # ----------------------------------------------------
        # Get both TCP and UDP connections
        # ----------------------------------------------------
        connections = psutil.net_connections(kind="inet")

        for connection in connections:

            # ------------------------------------------------
            # Determine protocol
            # ------------------------------------------------
            if connection.type == socket.SOCK_STREAM:
                protocol = "TCP"

                # TCP must actually be listening
                if connection.status != psutil.CONN_LISTEN:
                    continue

                state = "LISTENING"

            elif connection.type == socket.SOCK_DGRAM:
                protocol = "UDP"

                # UDP has no LISTEN state.
                # A local address means the socket is bound.
                if not connection.laddr:
                    continue

                state = "BOUND"

            else:
                continue

            # ------------------------------------------------
            # Process information
            # ------------------------------------------------
            pid = connection.pid

            process_name = "Unknown"
            process_exe = None

            if pid:

                try:
                    process = psutil.Process(pid)

                    try:
                        process_name = process.name()

                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied
                    ):
                        pass

                    try:
                        process_exe = process.exe()

                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied
                    ):
                        pass

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):
                    pass

            # ------------------------------------------------
            # Local address
            # ------------------------------------------------
            local_ip = None
            local_port = None

            if connection.laddr:

                local_ip = connection.laddr.ip
                local_port = connection.laddr.port

            # ------------------------------------------------
            # Service name
            # ------------------------------------------------
            service = "Unknown"

            if local_port:

                service_protocol = (
                    "tcp"
                    if protocol == "TCP"
                    else "udp"
                )

                try:

                    service = socket.getservbyport(
                        local_port,
                        service_protocol
                    )

                except (
                    OSError,
                    socket.error
                ):

                    service = "Unknown"

            # ------------------------------------------------
            # Risk classification
            # ------------------------------------------------
            risk_level = get_port_risk(
                local_port,
                protocol
            )

            # ------------------------------------------------
            # Result
            # ------------------------------------------------
            result = {

                "port": local_port,

                "protocol": protocol,

                "state": state,

                "local_ip": local_ip,

                "pid": pid,

                "process_name": process_name,

                "process_exe": process_exe,

                "service": service,

                "risk_level": risk_level,
            }

            results.append(result)

    except psutil.AccessDenied:

        print("[PORT SCANNER] Access denied.")

        print(
            "[PORT SCANNER] Try running CyberMonitor "
            "as Administrator."
        )

    except Exception as error:

        print(
            "[PORT SCANNER ERROR]",
            error
        )

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------
    unique_ports = {}

    for item in results:

        key = (
            item["protocol"],
            item["local_ip"],
            item["port"],
            item["pid"]
        )

        unique_ports[key] = item

    results = list(unique_ports.values())

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------
    results.sort(
        key=lambda item: (
            item["port"] is None,
            item["port"] or 0,
            item["protocol"]
        )
    )

    return results


# ============================================================
# PORT RISK ENGINE
# ============================================================

def get_port_risk(port, protocol="TCP"):
    """
    Basic port-risk classification.

    This is NOT a vulnerability scanner.

    It provides an initial risk classification
    based on commonly exposed services.
    """

    if port is None:
        return "UNKNOWN"

    # --------------------------------------------------------
    # High-risk ports
    # --------------------------------------------------------
    high_risk_ports = {

        # FTP
        21,

        # Telnet
        23,

        # SMB
        445,

        # RDP
        3389,

        # VNC
        5900,
    }

    # --------------------------------------------------------
    # Medium-risk ports
    # --------------------------------------------------------
    medium_risk_ports = {

        # SSH
        22,

        # SMTP
        25,

        # DNS
        53,

        # HTTP
        80,

        # POP3
        110,

        # NetBIOS
        139,

        # IMAP
        143,

        # HTTPS
        443,

        # MySQL
        3306,

        # PostgreSQL
        5432,

        # Redis
        6379,

        # HTTP alternative
        8080,

        # HTTPS alternative
        8443,
    }

    if port in high_risk_ports:
        return "HIGH"

    if port in medium_risk_ports:
        return "MEDIUM"

    return "LOW"


# ============================================================
# PORT SCAN DISPLAY
# ============================================================

def print_listening_ports(ports):
    """
    Display TCP and UDP ports in the terminal.
    """

    print()
    print("=" * 90)
    print("CYBERMONITOR PORT SCAN")
    print("=" * 90)

    if not ports:

        print("No listening or bound ports found.")

        print("=" * 90)

        return

    for port in ports:

        print(
            f"PORT       : {port['port']}"
        )

        print(
            f"PROTOCOL   : {port['protocol']}"
        )

        print(
            f"STATE      : {port['state']}"
        )

        print(
            f"LOCAL IP   : {port['local_ip']}"
        )

        print(
            f"PROCESS    : {port['process_name']}"
        )

        print(
            f"PID        : {port['pid']}"
        )

        print(
            f"SERVICE    : {port['service']}"
        )

        print(
            f"RISK       : {port['risk_level']}"
        )

        print("-" * 90)

    print("=" * 90)


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print(
        "CyberMonitor - Local TCP + UDP Port Scanner"
    )

    ports = get_listening_ports()

    print_listening_ports(ports)

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    tcp_count = sum(
        1
        for port in ports
        if port["protocol"] == "TCP"
    )

    udp_count = sum(
        1
        for port in ports
        if port["protocol"] == "UDP"
    )

    high_count = sum(
        1
        for port in ports
        if port["risk_level"] == "HIGH"
    )

    medium_count = sum(
        1
        for port in ports
        if port["risk_level"] == "MEDIUM"
    )

    low_count = sum(
        1
        for port in ports
        if port["risk_level"] == "LOW"
    )

    print()
    print("=" * 90)
    print("PORT SUMMARY")
    print("=" * 90)

    print(f"Total Ports   : {len(ports)}")
    print(f"TCP Ports     : {tcp_count}")
    print(f"UDP Ports     : {udp_count}")
    print(f"High Risk     : {high_count}")
    print(f"Medium Risk   : {medium_count}")
    print(f"Low Risk      : {low_count}")

    print("=" * 90)