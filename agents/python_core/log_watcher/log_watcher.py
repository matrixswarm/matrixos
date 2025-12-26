# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
# ChatGPT-3 Docstrings
import os, sys, time, json, uuid, importlib, threading

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):

    def __init__(self):
        super().__init__()


        try:
            cfg = self.tree_node.get("config", {})

            self._interval = cfg.get("check_interval_sec", 30)
            self._emit_beacon = self.check_for_thread_poke("worker", timeout=self._interval * 2,  emit_to_file_interval=10)


            self.AGENT_VERSION = "2.0.0"

            self._patrol_interval = int(cfg.get("patrol_interval_hours", 6)) * 3600
            self._last_patrol = 0
            self.enable_oracle = bool(cfg.get("enable_oracle", 0))
            self.oracle_role = cfg.get("oracle_role", "hive.oracle")
            self._alert_role = cfg.get("alert_role", "hive.alert")

            self._last_alert=0
            self._alert_cooldown=0

            self.oracle_timeout = int(cfg.get("oracle_timeout", 600))
            self._active_collectors = []
            self.collectors = cfg.get("collectors", ["httpd", "sshd"])
            self._rpc_role = self.tree_node.get("rpc_router_role", "hive.rpc")

            self.oracle_stack = {}


        except Exception as e:
            self.log(error=e, block="main_try")

    # ------------------------------------------------------------------
    def post_boot(self):
        self.log(f"{self.NAME} v{self.AGENT_VERSION} — Oracle-aware patrol online.")

    def worker(self, config=None, identity:IdentityObject=None):
        """
        Main scheduled loop.

        Performs one *digest patrol* every ``self._interval`` seconds:
        • Emits a beacon so Phoenix’s liveness watchdog doesn’t mark it stale
        • Flushes expired Oracle requests from ``self.oracle_stack``
        • Triggers :pymeth:`_run_digest_cycle` if the patrol timer has elapsed.

        Notes
        -----
        Runs inside the MatrixSwarm thread harness; any uncaught exception is
        logged and the loop sleeps briefly before continuing.
        """
        try:
            self._emit_beacon()
            now = time.time()
            self._check_oracle_timeouts()
            self.oracle_stack = {k: v for k, v in self.oracle_stack.items()
                                 if now - v["timestamp"] < self.oracle_timeout}

            if self.enable_oracle and (now - self._last_patrol) >= self._patrol_interval:
                self._last_patrol = now
                self._run_digest_cycle(use_oracle=True, patrol=True)
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

        interruptible_sleep(self, self._interval)



    # ------------------------------------------------------------------
    def run_collectors(self, limit_to=None):

        collector_results = {}
        collectors_cfg = self.tree_node.get("config", {}).get("collectors", {})

        try:
            loader = importlib.import_module(f"log_watcher.factory.utility.log_reader")

        except Exception as e:
            self.log(error=e, block="log_reader_loader", level="ERROR")
            return {}

        # Normalize collector selection list
        if limit_to:
            limit_to = [c.strip().lower() for c in limit_to]

        for name, cfg in collectors_cfg.items():

            try:
                key = name.strip().lower()
                self.log(
                    f'[LOG-WATCHER][COLLECT] → {name} | paths={cfg.get("paths",[])} | max_lines={cfg.get("max_lines",[])} | rotate_depth={cfg.get("rotate_depth",[])}'
                )

                if limit_to and key not in limit_to:
                    continue

                try:
                    result = loader.collect_log(self.log, cfg or {})
                    collector_results[name] = result if isinstance(result, dict) else {"lines": result}
                    self.log(f"[COLLECTOR] ✅ {name} parsed {len(collector_results[name].get('lines', []))} lines.")
                except ModuleNotFoundError:
                    self.log(f"[COLLECTOR] ❌ {name} not found")
                except Exception as e:
                    self.log(f"[COLLECTOR] ❌ {name} failed: {e}", error=e)

            except Exception as e:
                self.log(error=e, block="main_try", level="ERROR")

        return collector_results

    # ------------------------------------------------------------------
    def cmd_generate_system_log_digest(self, content, packet, identity=None):
        try:
            limit_to = content.get("collectors")

            use_oracle = bool(content.get("use_oracle", False))
            session_id = content.get("session_id")
            return_handler = content.get("return_handler")
            include_details = bool(content.get("include_details", True))

            # ⚙ preserve GUI token across whole path
            query_id = f"log_digest_{int(time.time())}"
            token = content.get("token", query_id)

            summary = self.run_collectors(limit_to=limit_to)
            formatted = self._render_digest(summary, use_full_format=include_details)

            # immediate digest to GUI, tagged with same token
            self._broadcast_output(
                token=token,
                session_id=session_id,
                offset=0,
                lines=formatted.splitlines(),
                response_handler=return_handler,
            )

            if not use_oracle:
                return

            # store oracle job with same token
            self.oracle_stack[query_id] = {
                "timestamp": time.time(),
                "payload": summary,
                "session_id": session_id,
                "return_handler": return_handler,
                "token": token,
            }

            self._send_to_oracle(summary, query_id)
            threading.Thread(
                target=self._oracle_timeout_watchdog,
                args=(query_id, self.oracle_timeout),
                daemon=True,
            ).start()

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")



    def _oracle_timeout_watchdog(self, query_id, timeout):

        try:
            start = time.time()
            while time.time() - start < timeout:
                time.sleep(2)
                if query_id not in self.oracle_stack:
                    return  # Oracle responded in time

            entry = self.oracle_stack.pop(query_id, None)
            if not entry:
                return

            lines = [
                "⚠ Oracle timeout — no response received in time.",
                "Returning base digest without analysis.",
            ]

            self._broadcast_output(
                token=entry["token"],
                session_id=entry["session_id"],
                offset=0,
                lines=lines,
                response_handler=entry["return_handler"],
            )

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")


    def _run_digest_cycle(self, use_oracle=False, session_id=None, return_handler=None, patrol=False):
        """Runs collector cycle manually or during patrol, with optional Oracle analysis."""

        try:
            include_details = True  # default verbosity
            token = f"patrol_{uuid.uuid4().hex[:8]}" if patrol else f"manual_{uuid.uuid4().hex[:8]}"

            summary = self.run_collectors()
            formatted = self._render_digest(summary, use_full_format=include_details)

            # Only broadcast to cockpit when it's an interactive (manual) run
            if not patrol and session_id:
                self._broadcast_output(
                    token=token,
                    session_id=session_id,
                    offset=0,
                    lines=formatted.splitlines(),
                    response_handler=return_handler,
                )

            if not use_oracle:
                return

            # prevent stacking duplicate patrol queries
            if patrol and len(self.oracle_stack) > 3:
                self.log("[LOGWATCH] Throttling patrol Oracle submissions.")
                # trim oldest entries
                oldest = sorted(self.oracle_stack.keys())[:-2]
                for oid in oldest:
                    self.oracle_stack.pop(oid, None)
                return

            # avoid duplicate summaries
            if any(v.get("payload") == summary for v in self.oracle_stack.values()):
                self.log("[LOGWATCH] Identical digest already pending; skipping.")
                return

            query_id = f"log_digest_{int(time.time())}"
            self.oracle_stack[query_id] = {
                "timestamp": time.time(),
                "payload": summary,
                "session_id": session_id,
                "return_handler": return_handler or "logwatch_panel.update",
                "token": token,
                "patrol": patrol,
            }

            # send job to Oracle
            self._send_to_oracle(summary, query_id)

            # spin watchdog for timeout
            threading.Thread(
                target=self._oracle_timeout_watchdog,
                args=(query_id, self.oracle_timeout),
                daemon=True,
            ).start()

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def _render_digest(self, collector_results, use_full_format=True):
        """
        Converts collector_results into a unified digest string or structured payload.
        Compatible with legacy 'use_full_format' flag.
        """
        try:
            digest_lines = []
            for name, section in collector_results.items():
                digest_lines.append(f"--------------------- {name.upper()} Begin ------------------------")

                # 🛡 Guard malformed data
                if not isinstance(section, dict):
                    self.log(
                        f"[DIGEST] ⚠️ Skipping malformed collector '{name}' (expected dict, got {type(section).__name__})")
                    continue

                lines = section.get("lines", [])
                summary = section.get("summary")
                stats = section.get("stats", {})

                # 🔍 Basic or detailed digest
                if use_full_format:
                    if isinstance(lines, list):
                        digest_lines.extend(lines)
                    else:
                        digest_lines.append(str(lines))

                # 🧮 Summary & stats (always included)
                if summary:
                    digest_lines.append(f"\n## SUMMARY ##\n{summary}")
                if stats:
                    digest_lines.append(f"\n## STATS ##\n{json.dumps(stats, indent=2)}")

                digest_lines.append(f"---------------------- {name.upper()} End -------------------------\n")

            return "\n".join(digest_lines)

        except Exception as e:
            self.log("[DIGEST][ERROR] Failed to render digest", error=e)
            return f"[DIGEST][ERROR] {e}"

    # ------------------------------------------------------------------
    def _send_to_oracle(self, summary, query_id):
        """
        Breaks the digest into chat-style messages and sends to Oracle using `messages` format.
        """
        try:
            endpoints = self.get_nodes_by_role(self.oracle_role, return_count=1)
            if not endpoints:
                self.log(f"[LOGWATCH] No Oracle agents found for role {self.oracle_role}.")
                return

            # Start with a system directive
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are Oracle, a diagnostic AI tasked with analyzing system logs. "
                        "Summarize anomalies, errors, or signs of misconfiguration. "
                        "Be concise, structured, and use bullet points if needed."
                    )
                },
                {
                    "role": "user",
                    "content": f"Begin analysis. Query ID: {query_id}."
                }
            ]

            # Chunk collector results as separate messages
            for name, section in summary.items():
                section_msg = {
                    "role": "user",
                    "content": f"Section: {name.upper()}\n\n{json.dumps(section, indent=2)[:5000]}"
                }
                messages.append(section_msg)

            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({
                "handler": "cmd_msg_prompt",
                "content": {
                    "messages": messages,
                    "query_id": query_id,
                    "target_universal_id": self.command_line_args.get("universal_id"),
                    "return_handler": "cmd_oracle_response",
                },
            })

            for ep in endpoints:
                pk.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk, ep.get_universal_id())

            self.log(f"[LOGWATCH] Digest sent to Oracle (query {query_id}) with {len(messages)} messages.")

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    # ------------------------------------------------------------------
    def cmd_oracle_response(self, content, packet, identity=None):
        try:
            query_id = content.get("query_id")
            entry = self.oracle_stack.pop(query_id, None)
            if not entry:
                self.log(f"[ORACLE] Received unknown query_id: {query_id}")
                return

            token = entry["token"]
            lines = [
                "=== ORACLE ANALYSIS BEGIN ===",
                content.get("response", "").strip(),
                "=== ORACLE ANALYSIS END ===",
            ]
            self._broadcast_output(
                token=token,
                session_id=entry["session_id"],
                offset=0,
                lines=lines,
                response_handler=entry["return_handler"],
            )
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    # ------------------------------------------------------------------
    def _check_oracle_timeouts(self):
        now = time.time()
        expired = [qid for qid, v in self.oracle_stack.items() if now - v["timestamp"] > self.oracle_timeout]
        try:
            for qid in expired:
                entry = self.oracle_stack.pop(qid)
                msg = f"[LOGWATCH] Oracle timeout — no response for {qid}."
                self._broadcast_output(
                    token=entry.get("token", qid),
                    session_id=entry.get("session_id"),
                    offset=0,
                    lines=[msg],
                    response_handler="logwatch_panel.update",
                )
                self._send_alert(msg, qid)
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")


    # ------------------------------------------------------------------
    def _send_alert(self, message, incident_id):
        """Push an alert if Oracle finds or times out on a concern."""

        try:

            if not message or not str(message).strip():
                self.log(f"[LOGWATCH][ALERT] Empty message for incident {incident_id}, skipping.")
                return
            if time.time() - self._last_alert < self._alert_cooldown:
                self.log("[LOGWATCH][ALERT] Cooldown active, skipping duplicate alert.")
                return
            self._last_alert = time.time()

            endpoints = self.get_nodes_by_role(self._alert_role)
            if not endpoints:
                self.log("[LOGWATCH][ALERT] No alert agents found.")
                return

            pk = self.get_delivery_packet("notify.alert.general")
            pk.set_data({
                "msg": message,
                "cause": "Oracle-Analyzed Digest",
                "origin": self.command_line_args.get("universal_id"),
            })
            cmd = self.get_delivery_packet("standard.command.packet")
            cmd.set_data({"handler": "cmd_send_alert_msg"})
            cmd.set_packet(pk, "content")

            for ep in endpoints:
                cmd.set_payload_item("handler", ep.get_handler())
                self.pass_packet(cmd, ep.get_universal_id())

            self.log(f"[LOGWATCH][ALERT] Dispatched alert for {incident_id}.")

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    # ------------------------------------------------------------------
    def _broadcast_output(self, token, session_id, offset, lines, response_handler):
        try:

            payload = {
                "session_id": session_id,
                "token": token,
                "start_line": offset,
                "lines": lines,
                "next_offset": offset + len(lines),
                "timestamp": int(time.time()),
            }

            self.crypto_reply(
                response_handler=response_handler,
                payload=payload,
                session_id=session_id,
                token=token
            )

        except Exception as e:
            self.log("[LOGWATCH][ERROR] broadcast_output failed", error=e)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
