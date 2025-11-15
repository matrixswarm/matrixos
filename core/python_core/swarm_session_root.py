import shutil
from datetime import datetime
from pathlib import Path


class SwarmSessionRoot:
    def __init__(self, universe: str, base_path: str, reboot_uuid: str = None, mode: str = "new"):
        self.universe = universe
        self.base = base_path
        self.reboot_uuid = reboot_uuid or datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        self.runtime_root = Path(self.base) / "universes" / "runtime" / universe / self.reboot_uuid
        self.static_root = Path(self.base) / "universes" / "static" / universe / self.reboot_uuid

        self.runtime_comm_path = self.runtime_root / "comm"
        self.runtime_pod_path = self.runtime_root / "pod"
        self.static_comm_path = self.static_root / "comm"
        self.static_pod_path = self.static_root / "pod"

        if mode == "new":
            # full fresh start
            self.create_directories()
            self.set_latest_symlinks()

        elif mode == "reuse":
            # reuse static + comm, but clear pods
            if self.runtime_pod_path.exists():
                for pod in self.runtime_pod_path.iterdir():
                    if pod.is_dir():
                        shutil.rmtree(pod, ignore_errors=True)
            print(f"[SWARM][REUSE] Reused existing session: {self.reboot_uuid}, pods cleared.")

    def create_directories(self):
        for path in [
            self.runtime_comm_path,
            self.runtime_pod_path,
            self.static_comm_path,
            self.static_pod_path,
        ]:
            path.mkdir(parents=True, exist_ok=True)

    def set_latest_symlinks(self):
        runtime_latest = Path(self.base) / "universes" / "runtime" / self.universe / "latest"
        static_latest = Path(self.base) / "universes" / "static" / self.universe / "latest"
        self._create_symlink(runtime_latest, self.reboot_uuid)
        self._create_symlink(static_latest, self.reboot_uuid)

    def _create_symlink(self, link_path: Path, target_uuid: str):
        try:
            if link_path.is_symlink() or link_path.is_file():
                link_path.unlink()
            elif link_path.is_dir():
                shutil.rmtree(link_path)
            link_path.symlink_to(target_uuid)
        except Exception as e:
            print(f"[SWARM][ERROR] Failed to create symlink {link_path} -> {target_uuid}: {e}")
