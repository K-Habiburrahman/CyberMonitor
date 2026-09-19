from detection.rule_engine import (
    check_process_rules,
    check_network_rules
)


def analyze_process(process):
    alerts = check_process_rules(process)

    if not alerts:
        return None

    return {
        "type": "process",
        "pid": process["pid"],
        "process_name": process["name"],
        "parent_name": process["parent_name"],
        "alerts": alerts
    }


def analyze_network(connection):
    alerts = check_network_rules(connection)

    if not alerts:
        return None

    return {
        "type": "network",
        "pid": connection["pid"],
        "process_name": connection["process_name"],
        "remote_ip": connection["remote_ip"],
        "remote_port": connection["remote_port"],
        "alerts": alerts
    }