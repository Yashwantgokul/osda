import threading
import time
from queue import Queue
import sys
import os

# Ensure the virtual environment can find the globally installed bcc module
dist_packages = '/usr/lib/python3/dist-packages'
if dist_packages not in sys.path and os.path.exists(dist_packages):
    sys.path.append(dist_packages)

try:
    from bcc import BPF
except ImportError:
    BPF = None
    print("Warning: 'bcc' module not found. eBPF monitoring will be disabled. Ensure you run as root and install python3-bpfcc.")

from internal.models import Event, EventType

# argv is flattened into a single char array because bcc cannot decode 2D arrays.
ARG_COUNT = 8
ARG_SIZE = 96
NUL = bytes(1)


def _argv_bytes(event):
    # A ctypes char-array field converts to bytes at the first NUL, which would
    # discard every argument after argv[0], so slice argv out of the raw struct.
    field = type(event).argv
    return bytes(event)[field.offset:field.offset + field.size]


def _decode_argv(raw):
    """Split the flattened argv blob into its NUL-terminated strings."""
    blob = bytes(raw)
    args = []
    for i in range(ARG_COUNT):
        arg = blob[i * ARG_SIZE:(i + 1) * ARG_SIZE].split(NUL, 1)[0]
        if not arg:
            break
        args.append(arg.decode('utf-8', 'replace'))
    return args


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 type; // 1=EXEC, 2=FORK, 3=EXIT
    char comm[TASK_COMM_LEN];
    char argv[ARG_COUNT * ARG_SIZE];
    u32 argv_truncated;
    u32 pid_ns;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(exec_args, u64, struct event_t);
BPF_PERCPU_ARRAY(exec_scratch, struct event_t, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 zero = 0;
    u64 key = bpf_get_current_pid_tgid();
    struct event_t *event = exec_scratch.lookup(&zero);
    if (!event) return 0;
    event->argv_truncated = 0;
    #pragma unroll
    for (int i = 0; i < ARG_COUNT; i++) event->argv[i * ARG_SIZE] = 0;
    #pragma unroll
    for (int i = 0; i < ARG_COUNT; i++) {
        const char *arg = 0;
        bpf_probe_read_user(&arg, sizeof(arg), &args->argv[i]);
        if (!arg) break;
        int length = bpf_probe_read_user_str(&event->argv[i * ARG_SIZE], ARG_SIZE, arg);
        if (length >= ARG_SIZE) event->argv_truncated = 1;
    }
    const char *extra = 0;
    if (event->argv[(ARG_COUNT - 1) * ARG_SIZE]) bpf_probe_read_user(&extra, sizeof(extra), &args->argv[ARG_COUNT]);
    if (extra) event->argv_truncated = 1;
    exec_args.update(&key, event);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    u64 key = bpf_get_current_pid_tgid();
    exec_args.delete(&key);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    u32 zero = 0;
    u64 key = bpf_get_current_pid_tgid();
    struct event_t *saved = exec_args.lookup(&key);
    struct event_t *scratch = exec_scratch.lookup(&zero);
    if (!scratch) return 0;
    if (!saved) {
        #pragma unroll
        for (int i = 0; i < ARG_COUNT; i++) scratch->argv[i * ARG_SIZE] = 0;
        scratch->argv_truncated = 1;
    }
    struct event_t *event = saved ? saved : scratch;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = task->real_parent->tgid;
    event->pid_ns = task->nsproxy->pid_ns_for_children->ns.inum;
    event->type = 1;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    events.perf_submit(args, event, sizeof(*event));
    exec_args.delete(&key);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 zero = 0;
    struct event_t *event = exec_scratch.lookup(&zero);
    if (!event) return 0;
    event->pid = args->child_pid;
    event->ppid = args->parent_pid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->pid_ns = task->nsproxy->pid_ns_for_children->ns.inum;
    event->type = 2;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 zero = 0;
    struct event_t *event = exec_scratch.lookup(&zero);
    if (!event) return 0;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = task->real_parent->tgid;
    event->pid_ns = task->nsproxy->pid_ns_for_children->ns.inum;
    event->type = 3;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    events.perf_submit(args, event, sizeof(*event));
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
        # Tracking is now fully handled by ProcessTree.
        pass

    def start(self):
        if BPF is None:
            return

        try:
            self.bpf = BPF(text=bpf_text, cflags=["-Wno-duplicate-decl-specifier",
                                                  f"-DARG_COUNT={ARG_COUNT}",
                                                  f"-DARG_SIZE={ARG_SIZE}"])
            self.bpf["events"].open_perf_buffer(self._handle_event)
            self.running = True
            
            self.thread = threading.Thread(target=self._poll_loop, daemon=True)
            self.thread.start()
            print("eBPF Process Monitor started successfully.")
        except Exception as e:
            print(f"Failed to start eBPF monitor: {e}")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            
        # Ensure we poll one last time before exiting to catch any stragglers
        try:
            self.bpf.perf_buffer_poll(timeout=100)
        except:
            pass

    def _poll_loop(self):
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception:
                pass

    def _handle_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        
        pid = event.pid
        ppid = event.ppid
        ev_type = event.type
        comm = event.comm.decode('utf-8', 'replace')

        # Map to internal EventType
        if ev_type == 1:
            t = EventType.PROCESS_EXEC
        elif ev_type == 2:
            t = EventType.PROCESS_FORK
        elif ev_type == 3:
            t = EventType.PROCESS_EXIT
        else:
            return

        self.event_queue.put(Event(
            analysis_id="",
            container_id="",
            timestamp=time.time(),
            type=t,
            pid=pid,
            ppid=ppid,
            process_name=comm,
            argv=_decode_argv(_argv_bytes(event)) if ev_type == 1 else None,
            argv_truncated=bool(event.argv_truncated) if ev_type == 1 else False,
            pid_ns=event.pid_ns
        ))
