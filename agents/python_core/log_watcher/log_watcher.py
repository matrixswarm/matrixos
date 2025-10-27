# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
# ChatGPT-3 Docstrings
import os, sys, time, json, uuid, importlib, threading
from Crypto.PublicKey import RSA

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.gui.callback_dispatcher import PhoenixCallbackDispatcher, CallbackCtx
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.utils.crypto_utils import pem_fix


class Agent(BootAgent):

    def __init__(self):
        super().__init__()


        try:
            cfg = self.tree_node.get("config", {})

            self.AGENT_VERSION = "2.0.0"
            self._interval = cfg.get("check_interval_sec", 30)
            self._patrol_interval = cfg.get("patrol_interval_hours", 6) * 3600
            self._last_patrol = 0
            self.enable_oracle = bool(cfg.get("enable_oracle", 0))
            self.oracle_role = cfg.get("oracle_role", "hive.oracle")
            self.alert_role = cfg.get("alert_role", "hive.alert")
            self._last_alert=0
            self._alert_cooldown=0

            self.oracle_timeout = int(cfg.get("oracle_timeout", 120))
            self.collectors = cfg.get("collectors", ["httpd", "sshd"])
            self._rpc_role = self.tree_node.get("rpc_router_role", "hive.rpc")

            self.oracle_stack = {}

            # encryption
            self._signing_keys = self.tree_node.get('config', {}).get('security', {}).get('signing', {})
            self._has_signing_keys = bool(self._signing_keys.get('privkey')) and bool(self._signing_keys.get('remote_pubkey'))

            if self._has_signing_keys:
                priv_pem = self._signing_keys.get("privkey")
                priv_pem = pem_fix(priv_pem)
                self._signing_key_obj = RSA.import_key(priv_pem.encode() if isinstance(priv_pem, str) else priv_pem)

            self._serial_num = self.tree_node.get('serial', {})

            self._emit_beacon = self.check_for_thread_poke("worker", timeout=self._interval * 2, emit_to_file_interval=10)

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
    def run_collectors(self):

        results = {}
        for name in self.collectors:
            try:
                mod = importlib.import_module(f"log_watcher.factory.collectors.{name}")
                results[name] = mod.collect()
            except Exception as e:
                self.log(f"[COLLECTOR][ERROR] {name}: {e}", level="ERROR")
        return results

    # ------------------------------------------------------------------
    def cmd_generate_system_log_digest(self, content, packet, identity=None):
        try:
            requested_collectors = content.get("collectors")
            if requested_collectors:
                self.collectors = requested_collectors

            use_oracle = bool(content.get("use_oracle", False))
            session_id = content.get("session_id")
            return_handler = content.get("return_handler")
            include_details = bool(content.get("include_details", True))

            # ⚙ preserve GUI token across whole path
            query_id = f"log_digest_{int(time.time())}"
            token = content.get("token", query_id)

            summary = self.run_collectors()
            formatted = self._render_digest(summary, use_full_format=include_details)

            # immediate digest to GUI, tagged with same token
            self._broadcast_output(
                token=token,
                session_id=session_id,
                offset=0,
                lines=formatted.splitlines(),
                return_handler=return_handler,
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
                return_handler=entry["return_handler"],
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
                    return_handler=return_handler,
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

    def _render_digest(self, summary: dict, use_full_format: bool = True) -> str:
        out = []
        for name, section in summary.items():

            try:
                header = f"--------------------- {name.upper()} Begin ------------------------"
                footer = f"---------------------- {name.upper()} End -------------------------"

                out.append(header)
                if not use_full_format:
                    out.append(section.get("summary", "(no summary)"))
                else:
                    for key, values in section.items():
                        if key == "summary":
                            out.append(section["summary"])
                            continue
                        if isinstance(values, list):
                            out.append(f"\n## {key.upper()} ##")
                            out.extend(values)
                out.append(footer)
                out.append("")  # spacing

            except Exception as e:
                self.log(error=e, block="main_try", level="ERROR")

        return "\n".join(out)

    # ------------------------------------------------------------------
    def _send_to_oracle(self, summary, query_id):

        try:
            endpoints = self.get_nodes_by_role(self.oracle_role, return_count=1)
            if not endpoints:
                self.log(f"[LOGWATCH] No Oracle agents found for role {self.oracle_role}.")
                return

            prompt = (
                "Analyze the following system log digest for anomalies or potential issues.\n\n"
                f"{json.dumps(summary, indent=2)}"
            )
            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({
                "handler": "cmd_msg_prompt",
                "content": {
                    "prompt": prompt,
                    "query_id": query_id,
                    "target_universal_id": self.command_line_args.get("universal_id"),
                    "return_handler": "cmd_oracle_response",
                },
            })

            for ep in endpoints:
                pk.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk, ep.get_universal_id())

            self.log(f"[LOGWATCH] Digest sent to Oracle (query {query_id}).")

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
                return_handler=entry["return_handler"],
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
                    return_handler="logwatch_panel.update",
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

            endpoints = self.get_nodes_by_role(self.alert_role)
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
    def _broadcast_output(self, token, session_id, offset, lines, return_handler):
        try:
            ctx = (
                CallbackCtx(agent=self)
                .set_rpc_role(self._rpc_role)
                .set_response_handler(return_handler)
                .set_confirm_response(True)
                .set_session_id(session_id)
                .set_token(token)
            )
            payload = {
                "session_id": session_id,
                "token": token,
                "start_line": offset,
                "lines": lines,
                "next_offset": offset + len(lines),
                "timestamp": int(time.time()),
            }

            dispatcher = PhoenixCallbackDispatcher(self)
            dispatcher.dispatch(ctx=ctx, content=payload)
        except Exception as e:
            self.log("[LOGWATCH][ERROR] broadcast_output failed", error=e)

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
