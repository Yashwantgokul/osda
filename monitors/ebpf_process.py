import threading
import time
from queue import Queue
import sys
import os

# Ensure BCC module can be located if installed in system dist-packages
dist_packages = '/usr/lib/python3/dist-packages'
if dist_packages not in sys.path and os.path.exists(dist_packages):
    sys.path.append(dist_packages)

try:
    from bcc import BPF
except ImportError:
    BPF = None
    print("Warning: 'bcc' module not found. eBPF monitoring will be disabled. Ensure you run as root and install python3-bpfcc.")

from internal.models import Event, EventType

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 type; // 1=EXEC, 2=FORK, 3=EXIT
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    event.type = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct event_t event = {};
    event.pid = args->child_pid;
    event.ppid = args->parent_pid;
    event.type = 2;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    event.type = 3;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

class EBPFMonitor:
    def __init__(self, event_queue: Queue):
        self.event_queue = event_queue
        self.bpf = None
        self.running = False
        self.thread = None

    def set_root_pid(self, pid: int):
        pass
