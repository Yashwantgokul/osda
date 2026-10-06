# OSDA (Operating System Dynamic Analysis) / SandboxSentinel

> **Automated Dynamic Malware and Script Analysis Sandbox utilizing Docker Isolation, eBPF Kernel Tracing, and Process Tree Correlation.**

---

## 🌟 Overview

**OSDA** (SandboxSentinel) is an automated dynamic analysis platform designed to inspect untrusted Python scripts (`.py`) and Shell scripts (`.sh`) safely within an isolated environment.

By combining **Docker containerization** with **eBPF (Extended Berkeley Packet Filter)** kernel-level instrumentation and **inotify filesystem monitoring**, OSDA captures real-time process execution hierarchies, file mutations, and execution telemetry without requiring invasive guest agent modifications.

---

## 🏗️ Architecture & Workflow

```text
                        +----------------------------+
                        |  CLI Runner (main.py)      |
                        +--------------+-------------+
                                       |
                +----------------------+----------------------+
                |                                             |
                v                                             v
  +---------------------------+                 +---------------------------+
  | Workspace Isolation Engine|                 | eBPF Kernel Tracing (BCC) |
  | - Directory provisioning  |                 | - sched_process_exec      |
  | - SHA256 integrity hash   |                 | - sched_process_fork      |
  +-------------+-------------+                 | - sched_process_exit      |
                |                               +-------------+-------------+
                v                                             |
  +---------------------------+                               |
  | Docker Sandbox Container  |                               v
  | - Isolated namespace/cgroup|                 +---------------------------+
  | - Volume bind mount       |                 | Event Consumer Queue      |
  +-------------+-------------+                 +-------------+-------------+
                |                                             |
                +----------------------+----------------------+
                                       |
                                       v
                        +----------------------------+
                        | Correlation & Reporting    |
                        | - ProcessTree hierarchy    |
                        | - Visual ASCII render      |
                        | - Analysis summary report  |
                        +----------------------------+
```

---

## 🚀 Key Features

- **Isolated Execution Environments**: Executes suspect binaries and scripts inside constrained Docker containers.
- **Kernel-Level eBPF Telemetry**: Attaches probes directly to Linux scheduler tracepoints (`sched_process_exec`, `sched_process_fork`, `sched_process_exit`) to observe process spawning transparently.
- **Host PID Discovery**: Resolves container root PID via Docker inspect to filter and isolate sandbox processes from host background noise.
- **Hierarchical Process Tree**: Correlates parent-child execution lineages into readable ASCII trees.
- **Filesystem Integrity Monitoring**: Tracks file creation, modification, and deletion events in real time.
- **Automated Reporting**: Produces clean forensic reports summarizing captured events.

---

## 📋 Prerequisites

- **Operating System**: Linux (Ubuntu 22.04 / Debian 12 recommended) with root privileges for eBPF attachment.
- **Docker Engine**: Installed and running daemon.
- **Kernel Headers & BCC**:
  ```bash
  sudo apt-get update
  sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
  ```
- **Python**: 3.10+

---

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Yashwantgokul/osda.git
   cd osda
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Build the Sandbox Shell Image (Optional for shell scripts)**:
   ```bash
   docker build -t sandboxsentinel-shell:latest .
   ```

---

## 💻 Usage

Run the dynamic analysis engine with root permissions:

```bash
# Analyze a Python script
sudo python3 main.py analyze sample.py

# Analyze a suspicious Shell payload
sudo python3 main.py analyze suspicious.sh
```

### Sample Output

```text
Starting SandboxSentinel MVP v1.0...
Analysis ID: SS-1788683859
File: suspicious.sh
Type: Shell
Status: Queued

eBPF Process Monitor started successfully.
Executing command: bash /workspace/suspicious.sh
Sandbox Host PID: 12489
Waiting for container to finish (max 30s)...

--- Sandbox Output ---
Starting suspicious behaviour...
----------------------

SANDBOX ANALYSIS REPORT
=======================

Analysis ID: SS-1788683859

RAW EVENTS (Milestones 1 & 2)
-----------------------------
[PROCESS_EXEC] - bash (PID: 12489 PPID: 11200)
[PROCESS_FORK] - bash (PID: 12512 PPID: 12489)
[PROCESS_EXEC] - sleep (PID: 12513 PPID: 12512)
[PROCESS_EXEC] - curl (PID: 12514 PPID: 12512)
[PROCESS_EXIT] - curl (PID: 12514 PPID: 12512)

PROCESS TREE
------------
└── bash (PID: 12489)
    └── bash (PID: 12512)
        ├── sleep (PID: 12513)
        └── curl (PID: 12514)

Analysis SS-1788683859 completed.
```

---

## 📂 Repository Structure

```text
├── correlate/
│   ├── __init__.py
│   └── process_tree.py     # Process correlation and visual tree builder
├── internal/
│   ├── __init__.py
│   └── models.py           # Core Event dataclasses & EventType enums
├── monitors/
│   ├── __init__.py
│   ├── ebpf_process.py     # eBPF tracepoint probes and perf buffer polling
│   └── fs_monitor.py       # Watchdog filesystem activity monitor
├── report/
│   ├── __init__.py
│   └── generator.py        # Analysis summary report generator
├── sandbox/
│   ├── __init__.py
│   ├── container.py        # Docker container orchestration
│   └── workspace.py        # File snapshotting and isolated workdir management
├── Dockerfile              # Custom container image definition
├── main.py                 # CLI entrypoint and orchestrator
├── requirements.txt        # Python package dependencies
├── sample.py               # Benign sample script
├── suspicious.sh           # Test script simulating suspicious activity
└── test_pid.py             # Docker PID inspection test script
```

---

## 🛡️ License

This project is licensed under the MIT License.
# Security evaluation

Analysis reports include the sandbox process tree, flagged processes, a capped
0–100 heuristic score, findings, and recommendations. Verdict thresholds are
SAFE (0–15), SUSPICIOUS (16–49), and MALICIOUS (50–100). Repeated observations of
the same rule for the same PID count once. Dual-use utilities can trigger rules;
the verdict describes observed behavior and is not proof that a file is safe or harmful.

The evaluator filters host process events to the sandbox root and its descendants.
Workspace filesystem monitoring starts after the target is copied and stops before
cleanup. Other container paths, including `/tmp`, are not monitored by the workspace
observer. Network behavior is inferred from command arguments, not packet capture.

On Linux with BCC, successful `execve` events include up to eight arguments of
96 bytes each (including the terminator). Missing or truncated arguments appear
as report limitations. `execveat`, shell built-ins, and script internals are not
captured as separate commands. Very short containers may exit before Docker's root
PID is inspected; reports with no captured executions explicitly disclose incomplete
coverage. ANSI verdict colors are enabled for terminals unless `NO_COLOR` is set.

Run portable evaluator checks with `python -m unittest discover -s tests -v`.
Live eBPF compilation and container capture require a Linux host with BCC and Docker.
