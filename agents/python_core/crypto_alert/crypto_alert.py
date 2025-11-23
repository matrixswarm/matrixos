# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import importlib
import time
import threading
import json
from pathlib import Path

import requests

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.class_lib.crypto.symmetric_encryption.aes.aes import AESHandlerBytesShim


class Agent(BootAgent):

    def __init__(self):
        super().__init__()




        try:

            self.log("NOT PRODUCTION READY -- DO NOT USE")
            self.log("NOT PRODUCTION READY -- DO NOT USE")
            self.log("NOT PRODUCTION READY -- DO NOT USE")
            self.log("NOT PRODUCTION READY -- DO NOT USE")
            self.name = "CryptoAgent"

            cfg = self.tree_node.get("config", {}) or {}

            # Exchange driver (loaded from factory)
            self.exchange = None

            # Live config
            self._private_config = dict(cfg)
            self._initialized_from_tree = False

            # Last price state: pair -> {last_price: float}
            self._state = {}

            # Per-cycle trigger batching
            self._alert_buffer = []

            # Persistent AES storage for alert/watch config
            self._alerts_file = os.path.join(self.path_resolution["static_comm_path_resolved"], "crypto_alerts.json.aes")

            # Interval
            self.interval = int(self._private_config.get("poll_interval", 20))

            # Streaming sessions (Phoenix sessions)
            # sess_id -> {
            #   "thread": Thread,
            #   "stop": Event,
            #   "token": str,
            #   "return_handler": str,
            #   "can_broadcast": bool
            # }
            self.active_streams = {}
            self._stream_lock = threading.Lock()
            self.monitor_running = False

            # Beacons
            self._emit_beacon = self.check_for_thread_poke("worker", timeout=self.interval * 2, emit_to_file_interval=10)

            # AES handler
            self._aes_key = cfg.get('security', {}).get('symmetric_encryption', {}).get('key')
            self._aes = AESHandlerBytesShim(self._aes_key)

            # Roles
            # RPC router used for crypto_reply callbacks
            self._rpc_role = self.tree_node.get("config", {}).get("rpc_router_role", "hive.rpc")

            # Alert fan-out role (hive.alert style)
            self._alert_role = self.tree_node.get("config", {}).get("alert_role", "hive.alert")

        except Exception as e:
            self.log(error=e, level="ERROR", block="INIT")

    # ============================================================
    #           PERSISTENT ALERT CONFIG (AES ENCRYPTED)
    # ============================================================

    def _load_alerts_file(self) -> list:
        """Load persisted watch_list (list of alerts) from AES file."""
        try:
            if not os.path.exists(self._alerts_file):
                return []
            raw = Path(self._alerts_file).read_bytes()
            decoded = self._aes.decrypt(raw).decode()
            data = json.loads(decoded)
            if isinstance(data, list):
                return data
            return []
        except Exception as e:
            self.log("[CRYPTO_ALERT] Failed to load alerts file", error=e)
            return []

    def _save_alerts_file(self, alerts: list):
        """Persist current watch_list to AES file."""
        try:
            raw = json.dumps(alerts, indent=2).encode()
            ct = self._aes.encrypt(raw)
            tmp_path = self._alerts_file + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(ct)
            os.replace(tmp_path, self._alerts_file)
        except Exception as e:
            self.log("[CRYPTO_ALERT] Failed to save alerts file", error=e)

    # ============================================================
    #                     EXCHANGE LOADER
    # ============================================================

    def cmd_update_agent_config(self):
        """Load/refresh the exchange driver based on config."""
        try:
            self._initialized_from_tree = True
            exchange_name = self._private_config.get("exchange", "coingecko")
            mod_path = f"crypto_alert.factory.cryptocurrency.exchange.{exchange_name}.price"

            self.log(f"Attempting to load exchange module: {mod_path}", block="EXCHANGE")
            try:
                module = importlib.import_module(mod_path)
                importlib.reload(module)
                ExchangeClass = getattr(module, "Exchange")
                self.exchange = ExchangeClass(self)
                self.log(f"[EXCHANGE] ✅ Loaded exchange handler: {exchange_name}")
            except Exception as e:
                self.log(f"[EXCHANGE] Failed to load exchange '{exchange_name}'", error=e)

        except Exception as e:
            self.log("Failed to initialize config", error=e)

    # ============================================================
    #                  CONFIG RETRIEVAL FOR GUI
    # ============================================================
    def cmd_retrieve_config(self, content, packet, identity=None):
        """Send current watch_list config back to Phoenix panel."""
        try:
            payload = {"watch_list": self._private_config.get("watch_list", [])}
            self.crypto_reply(
                response_handler="crypto_alert.config",
                payload=payload,
                session_id=content.get("session_id"),
                token=content.get("token"),
                rpc_role=self._rpc_role
            )
        except Exception as e:
            self.log("[CRYPTO_ALERT] Failed to retrieve config", error=e)

    # ============================================================
    #                     STREAM CONTROL
    # ============================================================
    def cmd_stream_prices(self, content, packet, identity=None):
        """Start streaming live price updates back to Phoenix for a session."""
        try:
            session_id = content.get("session_id")
            token = content.get("token")
            return_handler = content.get("return_handler", "crypto_alert.update")

            if not session_id or not token:
                self.log("[STREAM] Missing session_id or token.")
                return

            stop_flag = threading.Event()
            t = threading.Thread(
                target=self._stream_loop,
                args=(session_id, token, return_handler, stop_flag),
                daemon=True
            )

            with self._stream_lock:
                self.active_streams[session_id] = {
                    "thread": t,
                    "stop": stop_flag,
                    "token": token,
                    "return_handler": return_handler,
                    "can_broadcast": False,
                }

            t.start()
            self.log(f"[STREAM] Crypto stream started for sess={session_id}")

            # Start monitor thread once
            if not self.monitor_running:
                threading.Thread(target=self._monitor_sessions, daemon=True).start()
                self.monitor_running = True

        except Exception as e:
            self.log("[STREAM] Failed to start", error=e)

    def cmd_stop_stream_prices(self, content, packet, identity=None):
        """Stop streaming for a given session."""
        try:
            session_id = content.get("session_id")
            with self._stream_lock:
                stream = self.active_streams.pop(session_id, None)
            if stream:
                stream["stop"].set()
                self.log(f"[STREAM] 🛑 Stopped crypto stream for sess={session_id}")
        except Exception as e:
            self.log("[STREAM] Failed to stop", error=e)

    # ============================================================
    #                    STREAM LOOP (LOGSTREAMER-STYLE)
    # ============================================================

    def _stream_loop(self, session_id, token, return_handler, stop_flag):
        """Continuously pushes batched price updates back to Phoenix."""
        last_sent = {}
        try:
            while not stop_flag.is_set():
                # Check session entry
                stream = self.active_streams.get(session_id)
                if not stream:
                    break

                # Wait for broadcast flag from WS relay
                if not stream["can_broadcast"]:
                    if self._broadcast_ready(session_id):
                        stream["can_broadcast"] = True
                        self.log(f"[STREAM] Broadcast enabled for sess={session_id}")
                    else:
                        time.sleep(self.interval)
                        continue

                updates = []
                now = int(time.time())
                watch_list = self._private_config.get("watch_list", [])

                for alert in watch_list:
                    if not alert.get("stream_enabled", True):
                        continue

                    pair = alert.get("pair")
                    if not pair:
                        continue

                    try:
                        price = self.exchange.get_price(pair)
                    except Exception as e:
                        self.log("[STREAM] Price fetch failed", error=e)
                        continue

                    old = last_sent.get(pair)
                    # If price is None → cannot compute delta
                    if price is None:
                        # Only update if old is None (first seen)
                        if old is None:
                            last_sent[pair] = None
                            updates.append({"pair": pair, "price": None, "ts": now})
                        continue  # skip this asset this cycle
                    # Safe-cast
                    try:
                        price = float(price)
                    except:
                        continue
                    # Delta check
                    if old is None or abs(price - float(old)) >= 0.01:
                        last_sent[pair] = price
                        updates.append({"pair": pair, "price": price, "ts": now})

                if updates:
                    payload = {
                        "session_id": session_id,
                        "token": token,
                        "updates": updates
                    }
                    self._async_callback(return_handler, payload, session_id, token)

                interruptible_sleep(self, self.interval)
        except Exception as e:
            self.log("[STREAM] Fatal loop error", error=e)

    def _async_callback(self, return_handler, payload, session_id=None, token=None):
        """Launch a secure Phoenix callback on its own thread."""

        def _worker():
            try:
                self.crypto_reply(
                    response_handler=return_handler,
                    payload=payload,
                    session_id=session_id,
                    token=token,
                    rpc_role=self._rpc_role
                )
            except Exception as e:
                self.log("[CRYPTO_ALERT][ERROR] async callback failed", error=e)

        threading.Thread(target=_worker, daemon=True).start()

    # ============================================================
    #               BROADCAST FLAG / SESSION MONITOR
    # ============================================================
    def _broadcast_ready(self, session_id: str, threshold: int = 30) -> bool:
        """
        Checks whether connected.flag.<session_id> exists and is fresh
        inside the WebSocket relay agent's broadcast dir.
        """
        try:
            endpoints = self.get_nodes_by_role(self._rpc_role)
            if not endpoints:
                return False

            for ep in endpoints:
                relay_uid = ep.get_universal_id()
                base = os.path.join(self.path_resolution["comm_path"], relay_uid, "broadcast")
                flag = os.path.join(base, f"connected.flag.{session_id}")
                if not os.path.exists(flag):
                    continue
                age = time.time() - os.path.getmtime(flag)
                if age <= threshold:
                    return True
            return False
        except Exception as e:
            self.log("[SESSION-MONITOR] broadcast_ready error", error=e)
            return False

    def _monitor_sessions(self, check_interval=15, threshold=30):
        while True:
            try:
                for sess, sdata in list(self.active_streams.items()):
                    if not self._is_session_alive(sess, threshold):
                        self.log(f"[STREAMER] 🧹 Removing orphaned crypto stream sess={sess}")
                        self.cmd_stop_stream_prices({"session_id": sess}, None)
                time.sleep(check_interval)
            except Exception:
                time.sleep(check_interval)

    def _is_session_alive(self, session_id: str, threshold: int = 30) -> bool:
        """Check whether a session's broadcast flag is still fresh."""
        return self._broadcast_ready(session_id, threshold=threshold)

    # ============================================================
    #          UNIVERSAL ALERT DISPATCH (DISCRETE PACKETS)
    # ============================================================

    def send_simple_alert(self, message: str):
        """
        Send an alert as a discrete packet using notify.alert.general,
        same pattern as ApacheSentinel / other watchdogs.
        """
        try:
            endpoints = self.get_nodes_by_role(self._alert_role)
            if not endpoints:
                self.log("[ALERT] No alert-compatible agents found.")
                return

            pk1 = self.get_delivery_packet("standard.command.packet")

            # Try to get outward-facing server IP (best-effort)
            try:
                server_ip = requests.get("https://api.ipify.org").text.strip()
            except Exception:
                server_ip = "Unknown"

            pk2 = self.get_delivery_packet("notify.alert.general")
            pk2.set_data({
                "server_ip": server_ip,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "universal_id": self.command_line_args.get("universal_id", "unknown"),
                "level": "critical",
                "msg": message,
                "formatted_msg": f"📈 Crypto Alert\n{message}",
                "cause": "Crypto Trigger",
                "origin": self.command_line_args.get("universal_id", "unknown")
            })

            pk1.set_packet(pk2, "content")

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log("[ALERT] send_simple_alert failed", error=e)

    # ============================================================
    #                        WORKER LOOP
    # ============================================================

    def worker_pre(self):
        """Load persisted alerts into config on boot."""
        self.log("[CRYPTO_ALERT] Pre-boot: loading saved alerts...")
        try:
            saved = self._load_alerts_file()
            if saved:
                self._private_config["watch_list"] = saved
                self.log(f"[CRYPTO_ALERT] Loaded {len(saved)} saved alerts.")
        except Exception as e:
            self.log("[CRYPTO_ALERT] Failed to load alerts in worker_pre", error=e)

    def worker(self, config: dict = None, identity: IdentityObject = None):
        """
        Main alert engine: normalize alert configs, evaluate triggers,
        and dispatch discrete alerts via send_simple_alert().
        """
        try:
            self._emit_beacon()

            # Merge new config from Matrix/Phoenix
            if config and isinstance(config, dict):
                self._private_config.update(config)
                self._initialized_from_tree = False

                # If watch_list arrived, persist it
                if "watch_list" in config:
                    wl = config.get("watch_list") or []
                    self._save_alerts_file(wl)

            # Ensure exchange is loaded
            if not self._initialized_from_tree:
                self.cmd_update_agent_config()

            watch_list = self._private_config.get("watch_list", [])
            if not watch_list:
                self.log("No watch_list configured; standing by.")
                interruptible_sleep(self, self.interval)
                return

            # Normalize and re-assign list (adds toggles & limits)
            normalized = [self._normalize_alert(a) for a in watch_list]
            self._private_config["watch_list"] = normalized
            watch_list = normalized

            # Evaluate triggers
            self._alert_buffer.clear()

            for alert in watch_list:
                if not alert.get("active", True):
                    continue
                if not alert.get("alert_enabled", True):
                    continue

                pair = alert.get("pair", "BTC/USDT")
                if not pair:
                    continue

                try:
                    current = self.exchange.get_price(pair)
                except Exception:
                    continue

                last_price = self._state.get(pair, {}).get("last_price")
                if last_price is None:
                    # seed and skip trigger on first observation
                    self._state[pair] = {"last_price": current}
                    continue

                # Evaluate trigger
                self._evaluate_trigger(alert, pair, current, last_price)

                # Update last price
                self._state[pair] = {"last_price": current}

            # Flush batched alerts – discrete universal packets
            for msg in self._alert_buffer:
                self.send_simple_alert(msg)

            # Persist updated watch_list (for trigger_hit_count, active flags)
            self._save_alerts_file(self._private_config.get("watch_list", []))

        except Exception as e:
            self.log(error=e, block="main_try")

        interruptible_sleep(self, self.interval)

    # ============================================================
    #                 ALERT NORMALIZATION / DEFAULTS
    # ============================================================

    def _normalize_alert(self, alert: dict) -> dict:
        """Ensure all toggle/limit fields exist with sane defaults."""
        a = dict(alert)

        # toggles
        a.setdefault("stream_enabled", True)
        a.setdefault("alert_enabled", True)
        a.setdefault("active", True)

        # per-alert limits
        try:
            a["trigger_limit"] = int(a.get("trigger_limit", 9999999))
        except Exception:
            a["trigger_limit"] = 9999999

        try:
            a["trigger_hit_count"] = int(a.get("trigger_hit_count", 0))
        except Exception:
            a["trigger_hit_count"] = 0

        # default trigger type
        a.setdefault("trigger_type", "price_change_above")

        return a

    # ============================================================
    #                  TRIGGER ENGINE (PER-ALERT)
    # ============================================================

    def _evaluate_trigger(self, alert: dict, pair: str, current: float, last_price: float):
        """
        Evaluate one alert, and if triggered, record the message and
        bump per-alert trigger_hit_count. When limit reached, mark inactive.
        """
        try:
            ttype = alert.get("trigger_type", "price_change_above")
            parts = ttype.rsplit("_", 1)
            base = parts[0]
            mode = parts[1] if len(parts) > 1 else "above"

            hit_count = alert.get("trigger_hit_count", 0)
            tlimit = alert.get("trigger_limit", 9999999)
            if hit_count >= tlimit:
                alert["active"] = False
                return

            if base == "price_change":
                self._trg_price_change(alert, pair, current, last_price, mode)
            elif base == "price_delta":
                self._trg_price_delta(alert, pair, current, last_price, mode)
            elif base == "price":
                self._trg_price_threshold(alert, pair, current, mode)
            elif base == "asset_conversion":
                self._trg_asset_conversion(alert, pair)
            else:
                self.log(f"[TRIGGER] Unknown type: {ttype}")
        except Exception as e:
            self.log("[TRIGGER] Evaluation failure", error=e)

    def _record_trigger(self, alert: dict, message: str):
        """Record a fired trigger into the buffer and increment hit count."""
        self._alert_buffer.append(message)
        try:
            alert["trigger_hit_count"] = int(alert.get("trigger_hit_count", 0)) + 1
        except Exception:
            alert["trigger_hit_count"] = 1

        if alert["trigger_hit_count"] >= alert.get("trigger_limit", 9999999):
            alert["active"] = False

    # ---- Price % change trigger ----
    def _trg_price_change(self, alert, pair, current, last_price, mode):
        try:
            threshold_pct = float(alert.get("change_percent", 1.5))
            delta = current - last_price
            pct = abs(delta / last_price) * 100.0
            condition = (mode == "above" and delta > 0) or (mode == "below" and delta < 0)
            if condition and pct >= threshold_pct:
                msg = f"{pair} moved {pct:.2f}% {mode.upper()} → from {last_price} to {current}"
                self._record_trigger(alert, msg)
        except Exception as e:
            self.log("[TRIGGER][price_change] failure", error=e)

    # ---- Absolute price delta trigger ----
    def _trg_price_delta(self, alert, pair, current, last_price, mode):
        try:
            threshold_abs = float(alert.get("change_absolute", 1000))
            delta = current - last_price
            absd = abs(delta)
            condition = (mode == "above" and delta > 0) or (mode == "below" and delta < 0)
            if condition and absd >= threshold_abs:
                msg = f"{pair} moved ${absd:.2f} {mode.upper()} → from {last_price} to {current}"
                self._record_trigger(alert, msg)
        except Exception as e:
            self.log("[TRIGGER][price_delta] failure", error=e)

    # ---- Threshold trigger ----
    def _trg_price_threshold(self, alert, pair, current, mode):
        try:
            if current is None:
                return
            try:
                threshold = float(alert.get("threshold", 0))
            except:
                return  # invalid threshold

            # NONE-SAFE threshold
            if threshold is None:
                return

            if mode == "above" and current > threshold:
                msg = f"{pair} is above threshold: {current} > {threshold}"
                self._record_trigger(alert, msg)
            elif mode == "below" and current < threshold:
                msg = f"{pair} is below threshold: {current} < {threshold}"
                self._record_trigger(alert, msg)
        except Exception as e:
            self.log("[TRIGGER][threshold] failure", error=e)

    # ---- Asset conversion trigger ----
    def _trg_asset_conversion(self, alert, pair):
        try:
            from_asset = alert.get("from_asset", "BTC")
            to_asset = alert.get("to_asset", "ETH")
            from_amount = float(alert.get("from_amount", 0.1))
            threshold = float(alert.get("threshold", 3.0))

            pair1 = f"{from_asset}/USDT"
            pair2 = f"{to_asset}/USDT"
            price1 = self.exchange.get_price(pair1)
            price2 = self.exchange.get_price(pair2)

            if price1 is None or price2 is None:
                return

            value = from_amount * price1 / price2
            if value >= threshold:
                msg = f"{from_amount} {from_asset} = {value:.4f} {to_asset} (≥ {threshold})"
                self._record_trigger(alert, msg)
        except Exception as e:
            self.log("[TRIGGER][asset_conversion] failure", error=e)

    # ============================================================
    #      LEGACY SELF-MANAGEMENT (OPTIONAL, KEPT FROM ORIGINAL)
    # ============================================================

    def _save_config_patch(self):
        """Preserve ability to mark the agent inactive in the tree."""
        try:
            uid = self.command_line_args.get("universal_id", "unknown")
            patch = {
                "target_universal_id": uid,
                "config": {"active": False},
                "push_live_config": True,
                "respond_to": "crypto_gui_1",
                "handler_role": "hive.rpc.route",
                "handler": "cmd_rpc_route",
                "response_handler": "rpc_result_update_agent",
                "response_id": f"{uid}-deactivate"
            }

            pkt = self.get_delivery_packet("standard.command.packet")
            pkt.set_data({
                "handler": "cmd_update_agent",
                "content": patch
            })

            self.pass_packet(pkt, "matrix")

        except Exception as e:
            self.log("Error saving config patch", error=e)

    def _self_destruct(self):
        """Request Matrix to delete this agent."""
        try:
            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({
                "handler": "cmd_delete_agent",
                "content": {
                    "target_universal_id": self.command_line_args.get("universal_id", "unknown")
                }
            })

            self.pass_packet(pk, "matrix")

        except Exception as e:
            self.log(error=e)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()


