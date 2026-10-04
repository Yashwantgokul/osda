import os
import shutil
import hashlib
from typing import Dict

class Workspace:
    def __init__(self, base_dir: str, analysis_id: str):
        self.id = analysis_id
        self.path = os.path.join(base_dir, analysis_id, "workspace")
        self.parent_dir = os.path.dirname(self.path)

    def create(self):
        os.makedirs(self.path, exist_ok=True)

    def cleanup(self):
        if os.path.exists(self.parent_dir):
            shutil.rmtree(self.parent_dir)

    def copy_to_workspace(self, src_path: str, dest_filename: str):
        dest_path = os.path.join(self.path, dest_filename)
        shutil.copy2(src_path, dest_path)

    def hash_file(self, rel_path: str) -> str:
        abs_path = os.path.join(self.path, rel_path)
        sha256_hash = hashlib.sha256()
        with open(abs_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def snapshot(self) -> Dict[str, str]:
        state = {}
        for root, dirs, files in os.walk(self.path):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, self.path)
                try:
                    state[rel_path] = self.hash_file(rel_path)
                except FileNotFoundError:
                    # File might have been deleted while walking
                    pass
        return state
