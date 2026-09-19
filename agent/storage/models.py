from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityEvent:
    event_type: str
    severity: str
    risk_score: int
    risk_level: str
    process_name: Optional[str] = None
    pid: Optional[int] = None
    message: Optional[str] = None
    rule: Optional[str] = None
    file_path: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
