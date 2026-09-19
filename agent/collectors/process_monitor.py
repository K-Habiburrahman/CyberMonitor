import psutil
from datetime import datetime


def get_running_processes():
    processes = []

    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "username",
            "exe",
            "ppid",
            "cpu_percent",
            "memory_info",
            "create_time",
            "status"
        ]
    ):
        try:
            info = process.info

            # Get parent process information
            parent_name = None

            try:
                parent = process.parent()

                if parent:
                    parent_name = parent.name()

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_name = None

            # Convert memory from bytes to MB
            memory_mb = 0

            if info["memory_info"]:
                memory_mb = round(
                    info["memory_info"].rss / (1024 * 1024),
                    2
                )

            # Convert creation timestamp to readable time
            create_time = None

            if info["create_time"]:
                create_time = datetime.fromtimestamp(
                    info["create_time"]
                ).strftime("%Y-%m-%d %H:%M:%S")

            processes.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "username": info["username"],
                    "exe": info["exe"],
                    "parent_pid": info["ppid"],
                    "parent_name": parent_name,
                    "cpu_percent": info["cpu_percent"],
                    "memory_mb": memory_mb,
                    "create_time": create_time,
                    "status": info["status"]
                }
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes