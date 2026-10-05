import os
import time
from queue import Queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from internal.models import Event, EventType

class FSEventHandler(FileSystemEventHandler):
    def __init__(self, workspace_path: str, analysis_id: str, container_id: str, event_queue: Queue):
        self.workspace_path = workspace_path
        self.analysis_id = analysis_id
        self.container_id = container_id
        self.event_queue = event_queue

    def _create_event(self, event_type: EventType, src_path: str):
        rel_path = os.path.relpath(src_path, self.workspace_path)
        self.event_queue.put(Event(
            analysis_id=self.analysis_id,
            container_id=self.container_id,
            timestamp=time.time(),
            type=event_type,
            file_path=rel_path
        ))

    def on_created(self, event):
        if not event.is_directory:
            self._create_event(EventType.FILE_CREATE, event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._create_event(EventType.FILE_MODIFY, event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._create_event(EventType.FILE_DELETE, event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            # Simplification: treat move as delete for MVP
            self._create_event(EventType.FILE_DELETE, event.src_path)

class FSMonitor:
    def __init__(self, workspace_path: str, analysis_id: str, event_queue: Queue):
        self.workspace_path = workspace_path
        self.analysis_id = analysis_id
        self.event_queue = event_queue
        self.container_id = "pending"
        self.observer = Observer()
        self.handler = FSEventHandler(self.workspace_path, self.analysis_id, self.container_id, self.event_queue)

    def start(self):
        self.observer.schedule(self.handler, self.workspace_path, recursive=True)
        self.observer.start()

    def update_container_id(self, container_id: str):
        self.container_id = container_id
        self.handler.container_id = container_id

    def stop(self):
        self.observer.stop()
        self.observer.join()
