import os
from datetime import datetime

class SwarmSessionRoot:
    """
    Runtime: always flat, e.g. /matrix/universes/<universe_id>/<date_time>/{comm,pod}
    Static: timestamped snapshots under /matrix/static/universes/<universe_id>/<date_time>/
    """

    def __init__(self, universe_id="default", reboot_uuid=None, base="/matrix"):

        self.set_latest_symlink_runtime()
        self.set_latest_symlink_static()

        self.universe_id = universe_id
        self.reboot_uuid = reboot_uuid or datetime.now().strftime("%Y%m%d_%H%M%S")

        # Runtime (flattened)
        self.base_runtime = os.path.join(base, "universes", universe_id)
        self.comm_path = os.path.join(self.base_runtime, "comm")
        self.pod_path = os.path.join(self.base_runtime, "pod")

        # Ensure runtime dirs
        for d in [self.base_runtime, self.comm_path, self.pod_path]:
            os.makedirs(d, exist_ok=True)

        # Static archive (timestamped)
        self.base_static_universe = os.path.join(base, "static", "universes", universe_id, self.reboot_uuid)
        self.static_comm_path = os.path.join(self.base_static_universe, "comm")
        self.static_pod_path = os.path.join(self.base_static_universe, "pod")
        for d in [self.base_static_universe, self.static_comm_path, self.static_pod_path]:
            os.makedirs(d, exist_ok=True)

    def set_latest_symlink_runtime(self):
        pass
    def set_latest_symlink_static(self):
        pass

    def snapshot_paths(self):
        """Return static snapshot dirs for archival use."""
        return {
            "static_comm": self.static_comm_path,
            "static_pod": self.static_pod_path,
            "timestamp": self.reboot_uuid,
        }


class PathManager:
    """
    Wraps SwarmSessionRoot with static+runtime paths.
    """

    def __init__(self, universe_id="default", reboot_uuid=None,
                 base="/matrix", python_exec="python3"):

        self.session = SwarmSessionRoot(universe_id=universe_id,
                                        reboot_uuid=reboot_uuid,
                                        base=base)

        self.base = base

        self.base_static = os.path.join(self.base, "static")

        # Static dirs
        self.static_paths = {
            "agents": os.path.join(self.base, "agents"),
            "universes": os.path.join(self.base, "universes"),
            "comm": self.session.static_comm_path,
        }

        # Runtime dirs (flattened)
        self.runtime_paths = {
            "comm": self.session.comm_path,
            "pod": self.session.pod_path,
        }

        # Ensure static dirs exist
        for p in self.static_paths.values():
            os.makedirs(p, exist_ok=True)

        self.python_exec = python_exec

    def build_resolution(self, universal_id, spawn_uuid):
        return {
            "universe_id": self.session.universe_id,
            "reboot_uuid": self.session.reboot_uuid,

            # Runtime
            "comm_path": self.runtime_paths["comm"],
            "comm_path_resolved": os.path.join(self.runtime_paths["comm"], universal_id),
            "pod_path": self.runtime_paths["pod"],
            "pod_path_resolved": os.path.join(self.runtime_paths["pod"], spawn_uuid),

            # Static
            "comm_static_path_resolved": os.path.join(self.static_paths["comm"], universal_id),
            "log_path_resolved": os.path.join(self.static_paths["comm"], universal_id, "logs", "agent.log"),

            # Agents
            "agent_path": self.static_paths["agents"],

            # Compat
            "incoming_path_template": os.path.join(self.runtime_paths["comm"], "$universal_id", "incoming"),
            "poke_worker_file": os.path.join(self.runtime_paths["comm"], universal_id,
                                             "hello.moto", "poke.worker"),
            "site_root_path": self.base,
            "install_path": self.base,
            "python_site": self.base,
            "python_exec": self.python_exec,
        }
