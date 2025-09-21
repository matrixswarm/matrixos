import os
import time
import json

class ReflexAlertMixin:

    def alert_operator(self, qid=None, message=None, level="critical", cause="[PARSE ERROR]"):

        msg = message or f"🚨 Reflex termination (exit_code = -1)"

        # Accept single role or list of roles
        roles = getattr(self, "alert_roles", ["comm"])
        if isinstance(roles, str):
            roles = [roles]

        targets = []
        for role in roles:
            found = self.get_nodes_by_role(role)
            if found:
                targets.extend(found)

        if not targets:
            self.log(f"[REFLEX][ALERT] No agents found for roles: {roles}. Alert not dispatched.")
            return

        for target in targets:
            self.log(f"[REFLEX] Alert routed to {target['universal_id']}")
            self.drop_reflex_alert(msg, target["universal_id"], level=level, cause=cause)

    def drop_reflex_alert(self, message, agent_dir, level="critical", cause="reflex-trigger"):
        payload = {
            "type": "send_packet_incoming",
            "content": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "universal_id": self.command_line_args.get("universal_id", "unknown"),
                "level": level,
                "msg": message,
                "formatted_msg": f"📣 Swarm Message\n{message}",
                "cause": cause,
                "origin": self.command_line_args.get("universal_id", "unknown")
            }
        }

        inbox = os.path.join(self.path_resolution["comm_path"], agent_dir, "incoming")
        os.makedirs(inbox, exist_ok=True)

        try:
            path = os.path.join(inbox, f"reflex_alert_{int(time.time())}.msg")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            self.log(f"[REFLEX] Alert dropped to: {path}")
        except Exception as e:
            self.log(f"[REFLEX][ERROR] Failed to write alert msg: {e}")
