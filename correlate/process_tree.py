from typing import Dict, List, Optional
from internal.models import Event, EventType

class ProcessNode:
    def __init__(self, pid: int, ppid: int, name: str):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.children: List['ProcessNode'] = []
        self.events: List[Event] = []

    def add_child(self, child: 'ProcessNode'):
        if child not in self.children:
            self.children.append(child)

class ProcessTree:
    def __init__(self, analysis_id: str):
        self.analysis_id = analysis_id
        self.nodes: Dict[int, ProcessNode] = {}
        self.root_pid: Optional[int] = None

    def set_root_pid(self, pid: int):
        self.root_pid = pid
        # In case we missed the EXEC for the root_pid, inject a placeholder
        if pid not in self.nodes:
            self.nodes[pid] = ProcessNode(pid, 0, "sandbox_root")

    def add_event(self, event: Event):
        if event.type not in (EventType.PROCESS_EXEC, EventType.PROCESS_FORK, EventType.PROCESS_EXIT):
            return

        if event.type in (EventType.PROCESS_EXEC, EventType.PROCESS_FORK):
            if event.pid not in self.nodes:
                node = ProcessNode(event.pid, event.ppid, event.process_name or "unknown")
                self.nodes[event.pid] = node
            else:
                # Update name on EXEC
                if event.type == EventType.PROCESS_EXEC:
                    self.nodes[event.pid].name = event.process_name or "unknown"
            
            # Always ensure the parent relationship is linked
            parent = self.nodes.get(event.ppid)
            if parent:
                parent.add_child(self.nodes[event.pid])
            elif event.type == EventType.PROCESS_FORK:
                # If we saw a fork but parent isn't tracked yet, create a placeholder parent
                pnode = ProcessNode(event.ppid, 0, "unknown_parent")
                self.nodes[event.ppid] = pnode
                pnode.add_child(self.nodes[event.pid])
                
            self.nodes[event.pid].events.append(event)
