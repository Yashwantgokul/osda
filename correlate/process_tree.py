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

    def sandbox_pids(self):
        pids = {self.root_pid} if self.root_pid and self.root_pid > 0 else set()
        while True:
            descendants = {pid for pid, node in self.nodes.items() if node.ppid in pids}
            if descendants <= pids:
                return pids
            pids.update(descendants)

    def render(self, findings=()) -> str:
        if not self.root_pid or self.root_pid not in self.nodes:
            return "No Sandbox processes captured."
            
        output = []
        
        visited = set()
        def traverse(node, prefix="", last=True):
            if node.pid in visited:
                return
            visited.add(node.pid)
            flags = sorted({f.rule for f in findings if f.pid == node.pid})
            suffix = f" [FLAGGED: {', '.join(flags)}]" if flags else ""
            output.append(f"{prefix}{'└── ' if last else '├── '}{node.name} (PID: {node.pid}){suffix}")
            children = [n for n in self.nodes.values() if n.ppid == node.pid and n.pid != node.pid]
            for i, child in enumerate(children):
                traverse(child, prefix + ("    " if last else "│   "), i == len(children) - 1)
                    
        # Start traversal ONLY from the sandbox root PID
        traverse(self.nodes[self.root_pid])
            
        return "\n".join(output)
