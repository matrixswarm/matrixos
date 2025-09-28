import sys, os, random, time, threading

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from Crypto.PublicKey import RSA
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.utils.crypto_utils import encrypt_with_ephemeral_aes, sign_data, pem_fix

class Agent(BootAgent):
    def __init__(self):
        super().__init__()
        self.name = "Npc Simulator v1"
        self.AGENT_VERSION = "1.0.0"
        cfg = self.tree_node.get("config", {})
        self.grid_size = int(cfg.get("grid_size", 20))
        self.npc_count = int(cfg.get("npc_count", 100))

        # Sentinel settings
        self.stream_interval = 1.0       # seconds between ticks
        self.max_flag_age_sec = 60       # expire stale sessions
        self.active_streams = {}         # {sess_id: {thread, stop, token, handler}}

        self.rpc_role = self.tree_node.get("rpc_router_role", "hive.rpc")

        # Signing setup
        self._signing_keys = self.tree_node.get("config", {}).get("security", {}).get("signing", {})
        self._has_signing_keys = bool(self._signing_keys.get("privkey")) and bool(
            self._signing_keys.get("remote_pubkey"))
        if self._has_signing_keys:
            priv_pem = pem_fix(self._signing_keys.get("privkey"))
            self._signing_key_obj = RSA.import_key(priv_pem.encode() if isinstance(priv_pem, str) else priv_pem)

        self._serial_num = self.tree_node.get("serial", {})

        # Game state
        self.player = (self.grid_size // 2, self.grid_size // 2)
        self.last_seen_player = None
        self.npcs = []
        self._init_npcs()

    def post_boot(self):
        self.log(f"{self.NAME} v{self.AGENT_VERSION} – a strange game. The only winning move is not to play.")

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

    # === NPC Behaviors ===
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
            npc["x"] += 1 if npc["x"] < tx else -1 if npc["x"] > tx else 0
            npc["y"] += 1 if npc["y"] < ty else -1 if npc["y"] > ty else 0

    # === Commands ===
    def cmd_start_npc_stream(self, content, packet, identity=None):
        sess = content.get("session_id")
        token = content.get("token")
        handler = content.get("return_handler", "npc_simulator.gameboard.response")
        if not (sess and token):
            self.log("[NPC] ❌ Missing session_id or token.")
            return

        # Stop existing
        if sess in self.active_streams:
            self.cmd_stop_npc_stream({"session_id": sess}, None)

        stop_flag = threading.Event()
        t = threading.Thread(
            target=self._stream_loop,
            args=(sess, token, handler, stop_flag),
            daemon=True,
        )
        self.active_streams[sess] = {
            "thread": t,
            "stop": stop_flag,
            "token": token,
            "handler": handler,
            "created": time.time()
        }
        t.start()
        self.log(f"[NPC] 🎮 Stream started for sess={sess}")

    def cmd_stop_npc_stream(self, content, packet, identity=None):
        sess = content.get("session_id")
        if not sess or sess not in self.active_streams:
            return
        self.active_streams[sess]["stop"].set()
        self.active_streams.pop(sess, None)
        self.log(f"[NPC] 🛑 Stopped stream for sess={sess}")

    def cmd_control_npcs(self, content, packet, identity=None):
        action = content.get("action", "idle")
        if action == "scatter":
            self.last_seen_player = None
            self.log("[NPC] Scatter command received.")
        elif action == "hunt":
            self.last_seen_player = self.player
            self.log("[NPC] Hunt command received.")
        else:
            self.log(f"[NPC] Unknown action: {action}")

    # === Stream Loop ===
    def _stream_loop(self, sess, token, handler, stop_flag):
        while not stop_flag.is_set():
            try:
                # check flag freshness
                relay = self.get_nodes_by_role(self.rpc_role, return_count=1)
                if not relay:
                    time.sleep(self.stream_interval)
                    continue
                flag_path = os.path.join(
                    self.path_resolution["comm_path"],
                    relay[0].get_universal_id(),
                    "broadcast",
                    f"connected.flag.{sess}"
                )
                if not os.path.exists(flag_path) or (time.time() - os.path.getmtime(flag_path)) > self.max_flag_age_sec:
                    self.log(f"[NPC][STREAM] Session {sess} expired — cleaning up.")
                    self.cmd_stop_npc_stream({"session_id": sess}, None)
                    break

                # update NPCs
                for npc in self.npcs:
                    self._step_npc(npc)

                # broadcast frame
                self._broadcast_frame(sess, token, handler)
            except Exception as e:
                self.log("[NPC][ERROR] Stream loop failed", error=e)
                break
            time.sleep(self.stream_interval)

    def _broadcast_frame(self, sess_id, token, handler):
        if not self._has_signing_keys:
            return
        payload = {
            "handler": handler,
            "content": {
                "universal_id": self.tree_node.get("universal_id"),
                "session_id": sess_id,
                "token": token,
                "player_pos": self.player,
                "npc_list": self.npcs,
                "timestamp": int(time.time())
            }
        }
        sealed = encrypt_with_ephemeral_aes(payload, self._signing_keys.get("remote_pubkey"))
        content = {
            "serial": self._serial_num,
            "content": sealed,
            "timestamp": int(time.time()),
        }
        content["sig"] = sign_data(content, self._signing_key_obj)

        pk = self.get_delivery_packet("standard.command.packet")
        pk.set_data({
            "handler": "dummy_handler",
            "origin": self.command_line_args.get("universal_id", "npc_simulator"),
            "session_id": sess_id,
            "content": content,
        })
        for ep in self.get_nodes_by_role(self.rpc_role, return_count=1):
            pk.set_payload_item("handler", ep.get_handler())
            self.pass_packet(pk, ep.get_universal_id())
        self.log(f"[NPC][BROADCAST] Frame → sess={sess_id}")

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
