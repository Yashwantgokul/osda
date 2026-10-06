import os
import sys
import time
import threading
import subprocess
from queue import Queue

from monitors.ebpf_process import EBPFMonitor
from correlate.process_tree import ProcessTree
from correlate.evaluator import SecurityEvaluator
from monitors.fs_monitor import FSMonitor
from report.generator import Generator

def main():
    if len(sys.argv) < 3 or sys.argv[1] != "analyze":
        print("Usage: python3 main.py analyze <file.py/.sh>")
        print("Example: python3 main.py analyze sample.py")
        sys.exit(1)

    file_path = sys.argv[2]
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        sys.exit(1)
        
    if not (file_path.endswith('.py') or file_path.endswith('.sh')):
        print(f"Error: Unsupported file type. SandboxSentinel MVP only supports .py and .sh scripts.")
        sys.exit(1)

    analysis_id = f"SS-{int(time.time())}"
    base_dir = "./sandboxes"

    print("Starting SandboxSentinel MVP v1.0...")
    print(f"Analysis ID: {analysis_id}")
    print(f"File: {os.path.basename(file_path)}")
    print(f"Type: {'Python' if file_path.endswith('.py') else 'Shell'}")
    print("Status: Queued\n")

    if file_path.endswith(".py"):
        image = "python:3.12-slim"
    else:
        image = "sandboxsentinel-shell:latest"

    event_queue = Queue()
    reporter = Generator()
    
    # Process Tree
    tree = ProcessTree(analysis_id)
    
    # Start eBPF Monitor (Requires Root and BCC)
    ebpf_monitor = EBPFMonitor(event_queue)
    ebpf_monitor.start()

    # Consumer thread
    def process_events():
        while True:
            event = event_queue.get()
            if event is None:
                break
            event.analysis_id = analysis_id
            reporter.add_event(event)
            tree.add_event(event)

    consumer = threading.Thread(target=process_events, daemon=True)
    consumer.start()
    
    # 1. Create Workspace
    from sandbox.workspace import Workspace
    from sandbox.container import SandboxContainer
    
    ws = Workspace(base_dir, analysis_id)
    ws.create()
    filename = os.path.basename(file_path)
    ws.copy_to_workspace(file_path, filename)
    
    if filename.endswith(".py"):
        cmd = f"python3 /workspace/{filename}"
    elif filename.endswith(".sh"):
        cmd = f"bash /workspace/{filename}"
    else:
        cmd = f"/workspace/{filename}"

    container = SandboxContainer(image, ws.path)
    container.pull_image()
    
    container.create(cmd)
    fs_monitor = FSMonitor(ws.path, analysis_id, event_queue)
    fs_monitor.update_container_id(container.container_id)
    fs_monitor.start()
    
    # Start container and get its host root PID
    execution_start = time.monotonic()
    container.start()
    
    try:
        # Give container a tiny fraction of a second to initialize its init process
        time.sleep(0.1)
        root_pid_str = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.State.Pid}}", container.container.id]
        ).decode().strip()
        root_pid = int(root_pid_str)
    except Exception as e:
        print(f"Error getting container PID via inspect: {e}")
        root_pid = container.get_root_pid()
        
    # Pass the identified root PID to the event correlator
    ebpf_monitor.set_root_pid(root_pid)
    
    # 2. Feed to ProcessTree for rendering
    tree.set_root_pid(root_pid)
    
    print(f"Executing command: {cmd}")
    print(f"Sandbox Host PID: {root_pid}")
    
    print("Waiting for container to finish (max 30s)...")
    container.wait(timeout=30)
    execution_duration = time.monotonic() - execution_start
    
    if container.container:
        try:
            logs = container.container.logs().decode('utf-8')
            print("\n--- Sandbox Output ---")
            print(logs)
            print("----------------------\n")
        except Exception as e:
            print(f"Failed to fetch logs: {e}")
            
    # Drain period to ensure all events from the perf buffer are polled
    time.sleep(0.5)
            
    ebpf_monitor.stop()
    fs_monitor.stop()
    
    container.cleanup()
    ws.cleanup()
    
    # Stop consumer
    event_queue.put(None)
    consumer.join()
    
    evaluation = SecurityEvaluator(tree, reporter.events).evaluate()
    print(reporter.generate(analysis_id, tree, evaluation, filename, execution_duration))
    
    print(f"\nAnalysis {analysis_id} completed.")


if __name__ == "__main__":
    main()
