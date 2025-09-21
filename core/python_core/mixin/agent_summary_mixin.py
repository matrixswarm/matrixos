import os
import json
import time

class AgentSummaryMixin:
    def write_summary(self, label: str):
        """
        Write a machine-readable JSON summary for the agent.

        label: short identifier like "nginx", "apache", or "redis"
        """
        summary_dir = os.path.join(self.path_resolution["comm_path_resolved"], "summary")
        os.makedirs(summary_dir, exist_ok=True)

        summary = {
            "universal_id": self.command_line_args.get("universal_id", "unknown"),
            "agent": self.command_line_args.get("agent_name", label + "-sentinel"),
            "timestamp": int(time.time()),
            "uptime_sec": self.stats["uptime_sec"],
            "downtime_sec": self.stats["downtime_sec"],
            "restarts": self.stats["restarts"],
            "boot_time": self.boot_time
        }

        filename = f"{label}_uptime_{self.stats['date']}.json"
        summary_path = os.path.join(summary_dir, filename)

        try:

            latest_path = os.path.join(summary_dir, f"{label}_uptime_latest.json")
            with open(latest_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)

            self.log(f"[SUMMARY] ✅ {label} summary written to: {summary_path}", level="INFO")

        except Exception as e:
            self.log(f"[SUMMARY][ERROR] Failed to write {label} summary: {e}", level="ERROR")

    def maybe_roll_day(self, label: str):
        if self.stats["date"] != self.today():
            self.write_summary(label)
            self.stats = {
                "date": self.today(),
                "uptime_sec": 0,
                "downtime_sec": 0,
                "restarts": 0,
                "last_state": None,
                "last_change": time.time()
            }