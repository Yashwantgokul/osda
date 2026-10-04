import docker
import os

class SandboxContainer:
    def __init__(self, image: str, workspace_path: str):
        self.image = image
        self.workspace_path = workspace_path
        self.client = docker.from_env()
        self.container = None
        self.container_id = None

    def pull_image(self):
        try:
            self.client.images.get(self.image)
        except docker.errors.ImageNotFound:
            print(f"Image {self.image} not found locally. Attempting to pull...")
            try:
                self.client.images.pull(self.image)
            except docker.errors.APIError as e:
                print(f"Warning: Failed to pull image {self.image}: {e}")

    def create(self, cmd: str):
        abs_workspace = os.path.abspath(self.workspace_path)
        self.container = self.client.containers.create(
            self.image,
            command=cmd,
            volumes={abs_workspace: {'bind': '/workspace', 'mode': 'rw'}},
            detach=True,
            tty=True
        )
        self.container_id = self.container.id

    def start(self):
        if self.container:
            self.container.start()

    def get_root_pid(self) -> int:
        if self.container:
            self.container.reload()
            return self.container.attrs['State']['Pid']
        return 0

    def wait(self, timeout: int = 30):
        if self.container:
            try:
                self.container.wait(timeout=timeout)
            except Exception as e:
                print(f"Container wait exception: {e}")

    def cleanup(self):
        if self.container:
            try:
                self.container.remove(force=True)
            except Exception:
                pass
