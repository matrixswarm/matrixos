# Authored by Daniel F MacDonald and ChatGPT-5.1 aka The Generals
import os, sys, time, json,  importlib
from Crypto.PublicKey import RSA

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import time
import threading
import json

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject


class Agent(BootAgent):
    """
    TrendScout (Commander Edition)

    Responsibilities:
      • Receive topics from local scraper via push_local
      • Rank + merge topics
      • Forward ranked topics to Oracle
      • Receive prompts from Oracle
      • Forward them to Sora
      • Support live config updates (like Oracle)
      • Optional diagnostics
    """

    def __init__(self):
        super().__init__()

        try:
            cfg = self.tree_node.get("config", {})

            self.AGENT_VERSION = "2.0.0"

            # Oracle & Sora routing
            self.oracle_role = cfg.get("oracle_role", "hive.oracle")
            self.sora_role = cfg.get("sora_role", "hive.sora")

            # Ranking weights (can be hot-updated)
            self.source_weights = cfg.get("source_weights", {
                "google_trends": 3,
                "reddit": 2,
                "x": 2,
                "youtube": 1,
                "feedback": 5,
                "default": 1
            })

            # Diagnostics
            self.enable_diag = cfg.get("enable_diag", True)
            self._last_diag = 0
            self._diag_interval = 3600  # 1 hour

            # Live config reload support
            self._cfg_lock = threading.Lock()
            self._last_config = {}

            # Beacon
            self._emit_beacon = self.check_for_thread_poke(
                "worker", timeout=120, emit_to_file_interval=10
            )

            self.log(f"[TRENDSCOUT] Initialized v{self.AGENT_VERSION}")

        except Exception as e:
            self.log(error=e, block="init", level="ERROR")

    # ---------------------------------------------------------
    # WORKER (Oracle-style live updating)
    # ---------------------------------------------------------
    def worker_pre(self):
        self.log("[TRENDSCOUT] Ready. Waiting for incoming data.")

    def worker(self, config=None, identity: IdentityObject = None):
        """
        Oracle-style worker:
          • Heartbeat / beacon
          • Apply config updates live
        """
        if self.running:
            self._emit_beacon()

            # Live config update
            if isinstance(config, dict) and config != self._last_config:
                self.log("[TRENDSCOUT] 🔁 Live config update detected.")
                self._apply_live_config(config)
                self._last_config = dict(config)

            interruptible_sleep(self, 5)
            return

        # Shutdown path
        self.log("[TRENDSCOUT] Shutdown requested.")
        interruptible_sleep(self, 0.5)

    # ---------------------------------------------------------
    # CONFIG LIVE UPDATE
    # ---------------------------------------------------------
    def _apply_live_config(self, cfg: dict):
        try:
            with self._cfg_lock:
                if "oracle_role" in cfg:
                    self.oracle_role = cfg["oracle_role"]
                    self.log(f"[TRENDSCOUT] oracle_role → {self.oracle_role}")

                if "sora_role" in cfg:
                    self.sora_role = cfg["sora_role"]
                    self.log(f"[TRENDSCOUT] sora_role → {self.sora_role}")

                if "source_weights" in cfg:
                    self.source_weights = cfg["source_weights"]
                    self.log(f"[TRENDSCOUT] New ranking weights loaded.")

                if "enable_diag" in cfg:
                    self.enable_diag = bool(cfg["enable_diag"])

        except Exception as e:
            self.log("[TRENDSCOUT][ERROR] Failed to apply config", error=e)

    # ---------------------------------------------------------
    # HANDLER: LOCAL SCRAPER PUSH
    # ---------------------------------------------------------
    def cmd_push_local(self, content, packet, identity=None):
        """
        Entry point for TrendIngest → push_local.
        content = {
            "topics": [...],
            "source": "local_ingest",
            "session_id": "...",
            "pushed_at": ...
        }
        """
        try:
            raw_topics = content.get("topics", [])
            if not raw_topics:
                self.log("[TRENDSCOUT] Empty topic list received.", level="WARNING")
                return

            self.log(f"[TRENDSCOUT] Ingest received {len(raw_topics)} topics.")

            ranked = self._rank_topics(raw_topics)
            self.log(f"[TRENDSCOUT] Ranked top {len(ranked)} topics.")

            if self.enable_diag:
                self._run_diag(raw_topics, ranked)

            self._send_to_oracle(ranked)

        except Exception as e:
            self.log(error=e, block="push_local", level="ERROR")

    # ---------------------------------------------------------
    # RANKING (Supports live weight updates)
    # ---------------------------------------------------------
    def _rank_topics(self, topics):
        """
        topics = [
            {"topic": "...", "score": int, "source": "youtube", ...},
            ...
        ]
        """
        topic_map = {}

        with self._cfg_lock:
            weights = self.source_weights.copy()

        for t in topics:
            topic = t.get("topic")
            base = t.get("score", 10)
            src = t.get("source", "default")

            if not topic:
                continue

            w = weights.get(src, weights.get("default", 1))
            effective = base * w

            if topic not in topic_map:
                topic_map[topic] = {
                    "topic": topic,
                    "score": 0,
                    "source_hits": {}
                }

            topic_map[topic]["score"] += effective
            topic_map[topic]["source_hits"][src] = base

        ranked = sorted(topic_map.values(), key=lambda x: x["score"], reverse=True)
        return ranked[:10]

    # ---------------------------------------------------------
    # DIAGNOSTICS
    # ---------------------------------------------------------
    def _run_diag(self, raw, ranked):
        now = time.time()
        if now - self._last_diag < self._diag_interval:
            return
        self._last_diag = now

        summary = {
            "topics_in": len(raw),
            "top": ranked[0]["topic"] if ranked else None
        }

        self.log(f"[TRENDSCOUT][DIAG] {summary}")

    # ---------------------------------------------------------
    # ORACLE CHAIN
    # ---------------------------------------------------------
    def _send_to_oracle(self, ranked_topics):
        endpoints = self.get_nodes_by_role(self.oracle_role, return_count=1)
        if not endpoints:
            self.log("[TRENDSCOUT][WARN] No Oracle online.")
            return

        target = endpoints[0]

        payload = {
            "handler": "cmd_generate_video_prompts",
            "content": {
                "topics": ranked_topics,
                "session_id": None,
                "return_handler": "cmd_oracle_trend_response"
            }
        }

        pk = self.get_delivery_packet("standard.command.packet")
        pk.set_data(payload)
        pk.set_payload_item("handler", target.get_handler())

        self.pass_packet(pk, target.get_universal_id())
        self.log(f"[TRENDSCOUT] Forwarded {len(ranked_topics)} topics to Oracle.")

    # ---------------------------------------------------------
    # ORACLE → SORA RESPONSE
    # ---------------------------------------------------------
    def cmd_oracle_trend_response(self, content, packet, identity=None):
        """
        content = {"prompts":[{"topic":..., "prompt":...}, ...]}
        """
        try:
            prompts = content.get("prompts", [])
            if not prompts:
                self.log("[TRENDSCOUT] Oracle returned empty prompts.", level="WARNING")
                return

            sora_nodes = self.get_nodes_by_role(self.sora_role, return_count=1)
            if not sora_nodes:
                self.log("[TRENDSCOUT] No Sora online.")
                return

            target = sora_nodes[0]

            for p in prompts:
                pk = self.get_delivery_packet("standard.command.packet")
                pk.set_data({
                    "handler": "cmd_generate_video",
                    "content": {
                        "topic": p.get("topic"),
                        "prompt": p.get("prompt"),
                        "session_id": None,
                        "return_handler": "cmd_sora_video_ready"
                    }
                })
                pk.set_payload_item("handler", target.get_handler())
                self.pass_packet(pk, target.get_universal_id())

            self.log("[TRENDSCOUT] Forwarded Oracle prompts to Sora.")

        except Exception as e:
            self.log(error=e, block="oracle_trend_response", level="ERROR")

    # ---------------------------------------------------------
    # SORA FINAL RESPONSE
    # ---------------------------------------------------------
    def cmd_sora_video_ready(self, content, packet, identity=None):
        self.log(f"[TRENDSCOUT] 🎬 Video ready: {content}")


if __name__ == "__main__":
    agent = Agent()
    agent.boot()