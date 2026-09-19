import os


# Processes that can execute scripts or commands.
SCRIPTING_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}


# Common Windows system directories.
TRUSTED_SYSTEM_PATHS = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
)


def check_process_rules(process):
    alerts = []

    name = (process.get("name") or "").lower()
    exe = (process.get("exe") or "").lower()
    parent = (process.get("parent_name") or "").lower()

    # ---------------------------------------------
    # Rule 1: Scripting / command interpreter
    # ---------------------------------------------

    if name in SCRIPTING_PROCESSES:

        alerts.append({
            "rule": "SCRIPTING_PROCESS",
            "severity": "MEDIUM",
            "message": f"Command or scripting process detected: {name}"
        })

    # ---------------------------------------------
    # Rule 2: Script process started by Office
    # ---------------------------------------------

    office_processes = {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
    }

    if name in SCRIPTING_PROCESSES and parent in office_processes:

        alerts.append({
            "rule": "OFFICE_SPAWNED_SCRIPT",
            "severity": "HIGH",
            "message": (
                f"{parent} started scripting process {name}"
            )
        })

    # ---------------------------------------------
    # Rule 3: Executable running from suspicious
    #          user-writable locations
    # ---------------------------------------------

    suspicious_locations = (
        r"\appdata\local\temp",
        r"\appdata\roaming",
        r"\downloads",
        r"\desktop",
        r"\temp",
    )

    if exe:

        if any(location in exe for location in suspicious_locations):

            alerts.append({
                "rule": "SUSPICIOUS_EXECUTABLE_LOCATION",
                "severity": "HIGH",
                "message": (
                    f"Executable running from potentially "
                    f"unsafe location: {exe}"
                )
            })

    # ---------------------------------------------
    # Rule 4: Windows system process outside
    #          trusted system directories
    # ---------------------------------------------

    system_processes = {
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
    }

    if name in system_processes and exe:

        if not exe.startswith(TRUSTED_SYSTEM_PATHS):

            alerts.append({
                "rule": "SYSTEM_PROCESS_WRONG_LOCATION",
                "severity": "HIGH",
                "message": (
                    f"{name} is running from an unexpected "
                    f"location: {exe}"
                )
            })

    return alerts


def check_network_rules(connection):
    alerts = []

    remote_port = connection.get("remote_port")
    process_name = (
        connection.get("process_name") or "unknown"
    ).lower()

    # ---------------------------------------------
    # Rule 5: Suspicious remote ports
    # ---------------------------------------------

    suspicious_ports = {
        4444,
        5555,
        1337,
        31337,
    }

    if remote_port in suspicious_ports:

        alerts.append({
            "rule": "SUSPICIOUS_REMOTE_PORT",
            "severity": "HIGH",
            "message": (
                f"{process_name} connected to "
                f"suspicious remote port {remote_port}"
            )
        })

    return alerts