
from .swarm_session_root import SwarmSessionRoot

class PathManager:
    def __init__(self, universe: str, base: str, reboot_uuid: str = None, mode="new"):
        self.universe = universe
        self.base = base
        self.session = SwarmSessionRoot(universe, base, reboot_uuid=reboot_uuid, mode=mode)
        self.reboot_uuid = self.session.reboot_uuid

        # Swarm path templates (all paths use the same variable style)
        self.templates = {
            "site_root": "{base}",
            "reboot_uuid": "{reboot_uuid}",
            "runtime_comm": "{base}/universes/runtime/{universe}/{reboot_uuid}/comm/{universal_id}",
            "runtime_pod": "{base}/universes/runtime/{universe}/{reboot_uuid}/pod/{spawn_uuid}",
            "static_comm": "{base}/universes/static/{universe}/{reboot_uuid}/comm/{universal_id}",
            "agent": "{base}/agents/{lang}_core/",
            "agent_resolved": "{base}/agents/{lang}_core/{agent_name}/{agent_name}.{ext}",
            "latest_runtime": "{base}/universes/runtime/{universe}/latest",
            "latest_static": "{base}/universes/static/{universe}/latest",
        }

    def resolve(self, key, **kwargs):
        data = dict(
            base=self.base,
            universe=self.universe,
            reboot_uuid=self.reboot_uuid,
            universal_id=kwargs.get("universal_id", ""),
            spawn_uuid=kwargs.get("spawn_uuid", ""),
            agent_name=kwargs.get("agent_name", ""),
            lang=kwargs.get("lang", "python"),
            ext=kwargs.get("ext", "py"),
        )
        return self.templates[key].format(**data)

    def full_resolution(self, universal_id, spawn_uuid, lang="python", ext="py"):
        # One call, all the resolved paths
        return {
            "runtime_comm": self.resolve("runtime_comm"),
            "runtime_pod": self.resolve("runtime_pod"),
            "runtime_comm_resolved": self.resolve("runtime_comm", universal_id=universal_id),
            "runtime_pod_resolved": self.resolve("runtime_pod", spawn_uuid=spawn_uuid),
            "static_comm": self.resolve("static_comm"),
            "static_comm_resolved": self.resolve("static_comm", universal_id=universal_id),
            "latest_runtime": self.resolve("latest_runtime"),
            "latest_static": self.resolve("latest_static"),
        }
