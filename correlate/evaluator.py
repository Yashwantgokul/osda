"""Explainable heuristic scoring of observed sandbox behavior."""
from dataclasses import dataclass
import re
import shlex
from pathlib import PurePosixPath
from internal.models import EventType


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    points: int
    description: str
    pid: int | None = None


@dataclass
class Evaluation:
    score: int
    verdict: str
    findings: list[Finding]
    limitations: list[str]


def verdict_for_score(score):
    return "MALICIOUS" if score >= 50 else "SUSPICIOUS" if score >= 16 else "SAFE"


class SecurityEvaluator:
    def __init__(self, process_tree, events):
        self.tree = process_tree
        self.events = events

    def evaluate(self):
        pids = self.tree.sandbox_pids()
        events = sorted((e for e in self.events if e.pid in pids or
                         (e.pid is None and e.analysis_id == self.tree.analysis_id)),
                        key=lambda e: e.timestamp)
        findings, seen = [], set()

        def add(rule, points, description, pid=None):
            key = (rule, pid)
            if key not in seen:
                seen.add(key)
                findings.append(Finding(rule, "High" if points >= 35 else "Medium",
                                        points, description, pid))

        for event in events:
            if event.type == EventType.PROCESS_EXEC:
                name = PurePosixPath((event.argv or [event.process_name or ""])[0]).name
                command = shlex.join(event.argv or [event.process_name or ""])
                if name in {"nc", "netcat", "ncat", "socat"}:
                    add("network_utility", 35, f"Dual-use network utility: {command}", event.pid)
                if name in {"curl", "wget", "fetch"}:
                    add("download", 25, f"Network transfer utility: {command}", event.pid)
                if name == "nmap":
                    add("scan", 25, f"Network scanning: {command}", event.pid)
                if name in {"sudo", "pkexec"}:
                    add("privilege", 35, f"Privilege elevation utility: {command}", event.pid)
                if name in {"bash", "sh", "zsh"} and event.argv and "-c" in event.argv:
                    add("subshell", 20, f"Shell command execution: {command}", event.pid)
                if re.search(r"/dev/tcp/|(?:nc|netcat|ncat)\b.*\s-e\s|socat\b.*EXEC:", command):
                    add("reverse_shell", 50, f"Reverse-shell pattern: {command}", event.pid)
                if re.search(r"base64\b.*(?:-d|--decode)|\beval\b|exec\s*\(.*b64decode", command):
                    add("obfuscation", 35, f"Decoded or dynamic execution: {command}", event.pid)
                if "/etc/shadow" in command:
                    add("credentials", 50, f"Credential file referenced: {command}", event.pid)
                if name == "chmod" and event.argv and any(a in {"+x", "777", "a+x", "u+x"} for a in event.argv[1:]):
                    add("executable", 20, f"Executable or world-writable permissions: {command}", event.pid)
                if re.search(r"\brm\s+-[rf]*r[rf]*\s+/\s*(?:'|$)|\bkill\s+-9\b|unset\s+HISTFILE", command):
                    add("disruption", 50, f"Disruptive command pattern: {command}", event.pid)
            if event.type == EventType.FILE_DELETE:
                add("deletion", 15, f"File deleted: {event.file_path}", event.pid)
            if event.type in {EventType.FILE_CREATE, EventType.FILE_MODIFY} and event.file_path and event.file_path.startswith(("/tmp/", "/dev/shm/")):
                add("staging", 20, f"Staging directory write: {event.file_path}", event.pid)

        # Count nested shell ancestors, with cycle protection.
        for pid in pids:
            current, visited, shells = pid, set(), 0
            while current in pids and current not in visited:
                visited.add(current)
                node = self.tree.nodes[current]
                shells += node.name in {"bash", "sh", "zsh"}
                current = node.ppid
            if shells >= 3:
                add("shell_depth", 20, "Three or more nested shell processes")
                break
        limitations = ["Heuristic verdict describes observed behavior; SAFE is not a guarantee.",
                       "Filesystem coverage is limited to the mounted workspace; network activity is inferred from commands."]
        executions = [e for e in events if e.type == EventType.PROCESS_EXEC]
        downloads, executable_paths = set(), set()
        for event in executions:
            argv = event.argv or []
            if not argv:
                continue
            name = PurePosixPath(argv[0]).name
            if name in {"curl", "wget", "fetch"}:
                for option in ("-o", "-O", "--output", "--output-document"):
                    if option in argv and argv.index(option) + 1 < len(argv):
                        downloads.add(argv[argv.index(option) + 1])
            elif name == "chmod" and any(a in {"+x", "a+x", "u+x", "777"} for a in argv):
                executable_paths.update(a for a in argv[2:] if a in downloads)
            elif argv[0] in executable_paths:
                add("dropper", 50, f"Downloaded file made executable and launched: {argv[0]}", event.pid)
        if not executions:
            limitations.append("No sandbox executions captured: process coverage is incomplete.")
        elif any(not e.argv or e.argv_truncated for e in executions):
            limitations.append("Some command arguments are missing or truncated.")
        score = min(100, sum(f.points for f in findings))
        return Evaluation(score, verdict_for_score(score), findings, limitations)
