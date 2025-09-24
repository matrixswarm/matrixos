import sys, os, random, time
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    def __init__(self):
        super().__init__()
        self.name = "NpcSimulator"
        cfg = self.tree_node.get("config", {})
        self.grid_size = int(cfg.get("grid_size", 20))
        self.npc_count = int(cfg.get("npc_count", 100))
        self.interval = 30
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=self.interval*2, emit_to_file_interval=10)

        # Simulation state
        self.player = (self.grid_size // 2, self.grid_size // 2)
        self.last_seen_player = None
        self.npcs = []
        self._init_npcs()

    def _init_npcs(self):
        roles = ["scout"]*10 + ["hunter"]*30 + ["follower"]*60
        for i, role in enumerate(roles[:self.npc_count]):
            self.npcs.append({
                "id": i,
                "role": role,
                "x": random.randint(0, self.grid_size-1),
                "y": random.randint(0, self.grid_size-1),
                "target": None
            })

    def worker(self, config: dict = None, identity: IdentityObject = None):
        try:
            self._emit_beacon()

            # Move NPCs
            for npc in self.npcs:
                self._step_npc(npc)

            # Render grid as ASCII
            grid = [["." for _ in range(self.grid_size)] for _ in range(self.grid_size)]
            px, py = self.player
            grid[py][px] = "@"
            for npc in self.npcs:
                grid[npc["y"]][npc["x"]] = "o"
            ascii_out = "\n".join(" ".join(row) for row in grid)
            self.log(f"[NPC-SIM] Frame:\n{ascii_out}")

        except Exception as e:
            self.log(error=e, block="main_try")

        interruptible_sleep(self, self.interval)

    def _step_npc(self, npc):
        px, py = self.player

        if npc["role"] == "scout":
            dx, dy = random.choice([(1,0),(-1,0),(0,1),(0,-1),(0,0)])
            npc["x"] = max(0, min(self.grid_size-1, npc["x"]+dx))
            npc["y"] = max(0, min(self.grid_size-1, npc["y"]+dy))
            if abs(npc["x"]-px)+abs(npc["y"]-py) < 4:
                self.last_seen_player = (px, py)

        elif npc["role"] in ("hunter", "follower") and self.last_seen_player:
            tx, ty = self.last_seen_player
            if npc["x"] < tx: npc["x"] += 1
            elif npc["x"] > tx: npc["x"] -= 1
            if npc["y"] < ty: npc["y"] += 1
            elif npc["y"] > ty: npc["y"] -= 1

    # === Service Manager Commands ===

    def cmd_control_npcs(self, content, packet, identity: IdentityObject = None):
        action = content.get("action", "idle")
        if action == "scatter":
            self.last_seen_player = None
            self.log("[NPC] Scatter command received.")
        elif action == "hunt":
            self.last_seen_player = self.player
            self.log("[NPC] Hunt command received.")
        else:
            self.log(f"[NPC] Unknown control action: {action}")

    def cmd_report_status(self, content, packet, identity: IdentityObject = None):
        status = {
            "npc_count": len(self.npcs),
            "player_pos": self.player,
            "last_seen_player": self.last_seen_player
        }
        self.log(f"[NPC] Status report: {status}")
        return status

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
