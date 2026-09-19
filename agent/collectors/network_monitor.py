import psutil


def get_network_connections():
    connections = []

    for connection in psutil.net_connections(kind="inet"):

        try:
            # Local address
            local_ip = None
            local_port = None

            if connection.laddr:
                local_ip = connection.laddr.ip
                local_port = connection.laddr.port

            # Remote address
            remote_ip = None
            remote_port = None

            if connection.raddr:
                remote_ip = connection.raddr.ip
                remote_port = connection.raddr.port

            # Get process name from PID
            process_name = None

            if connection.pid:

                try:
                    process = psutil.Process(connection.pid)
                    process_name = process.name()

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied
                ):
                    process_name = None

            connections.append(
                {
                    "pid": connection.pid,
                    "process_name": process_name,
                    "family": str(connection.family),
                    "type": str(connection.type),
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": connection.status
                }
            )

        except Exception:
            continue

    return connections