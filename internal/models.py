from dataclasses import dataclass
from enum import Enum
from typing import Optional


class EventType(Enum):
    PROCESS_EXEC = "PROCESS_EXEC"
    PROCESS_FORK = "PROCESS_FORK"
    PROCESS_EXIT = "PROCESS_EXIT"

    FILE_CREATE = "FILE_CREATE"
    FILE_MODIFY = "FILE_MODIFY"
    FILE_DELETE = "FILE_DELETE"
    FILE_CHMOD = "FILE_CHMOD"

    NETWORK_CONNECT = "NETWORK_CONNECT"


@dataclass
class Event:
    analysis_id: str
    container_id: str
    timestamp: float
    type: EventType
    
    # Process attributes (optional for FS/Network in MVP before eBPF)
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    
    # FS attributes
    file_path: Optional[str] = None
    
    # Network attributes
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None

    def __str__(self):
        if self.pid is not None and self.ppid is not None:
            return f"[{self.type.value}] - {self.process_name} (PID: {self.pid} PPID: {self.ppid})"
        return f"[{self.type.value}] {self.container_id} - {self.file_path or self.process_name or self.remote_address}"
