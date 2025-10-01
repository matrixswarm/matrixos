#Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys, os, time, psutil
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    """
    A hardened MatrixSwarm agent that monitors system resources and
    reports structured metrics to the forensic role.
    """
    def __init__(self):
        super().__init__()
        self.name = "SystemHealthMonitor"

        cfg = self.tree_node.get("config", {})
        self.mem_threshold = cfg.get("mem_threshold_percent", 95.0)
        self.cpu_threshold = cfg.get("cpu_threshold_percent", 90.0)
        self.disk_threshold = cfg.get("disk_threshold_percent", 95.0)
        self.interval = cfg.get("check_interval_sec", 60)
        self.report_to_role = cfg.get("report_to_role", "hive.forensics.data_feed")

        self._emit_beacon = self.check_for_thread_poke("worker",
                                                      timeout=self.interval*2,
                                                      emit_to_file_interval=10)

        # Cooldown store for each metric to avoid spamming
        self.last_alerts = {}

        self.log(f"[SYSTEM-HEALTH] Ready. Mem>{self.mem_threshold} CPU>{self.cpu_threshold} Disk>{self.disk_threshold} Reporting→{self.report_to_role}")

    def send_status_report(self, service_name, status, severity, details):
        """Send a structured status event packet with metrics attached."""
        endpoints = self.get_nodes_by_role(self.report_to_role)
        if not endpoints:
            self.log(f"[SYSTEM-HEALTH] No endpoints for role '{self.report_to_role}'", level="WARN")
            return

        pk_inner = self.get_delivery_packet("standard.status.event.packet")
        pk_inner.set_data({
            "source_agent": self.name,
            "service_name": service_name,
            "status": status,
            "details": details,
            "severity": severity,
        })

        pk = self.get_delivery_packet("standard.command.packet")
        pk.set_data({"handler": "cmd_ingest_status_report"})
        pk.set_packet(pk_inner, "content")

        for ep in endpoints:
            pk.set_payload_item("handler", ep.get_handler())
            self.pass_packet(pk, ep.get_universal_id())
        self.log(f"[SYSTEM-HEALTH] {severity} {service_name} sent to {self.report_to_role}", level="INFO")

    def check_and_report(self, key, condition, service_name, status, severity, details):
        """Wraps checks with 5-minute cooldown to prevent alert storms."""
        now = time.time()
        last = self.last_alerts.get(key, 0)
        if condition and (now - last > 300):
            self.send_status_report(service_name, status, severity, details)
            self.last_alerts[key] = now

    def worker(self, config: dict = None, identity: IdentityObject = None):

        try:
            self._emit_beacon()

            # Memory
            mem = psutil.virtual_memory()
            sev = "CRITICAL" if mem.percent > self.mem_threshold + 5 else "WARNING"
            self.check_and_report("memory",
                                  mem.percent > self.mem_threshold,
                                  "system.memory",
                                  "high_usage",
                                  sev,
                                  {"usage_percent": mem.percent, "threshold": self.mem_threshold})

            # CPU (use load avg for Unix if available)
            cpu = psutil.cpu_percent(interval=None)
            sev = "CRITICAL" if cpu > self.cpu_threshold + 5 else "WARNING"
            self.check_and_report("cpu",
                                  cpu > self.cpu_threshold,
                                  "system.cpu",
                                  "high_load",
                                  sev,
                                  {"usage_percent": cpu, "threshold": self.cpu_threshold})

            # Disks – iterate partitions
            for part in psutil.disk_partitions():
                usage = psutil.disk_usage(part.mountpoint)
                sev = "CRITICAL" if usage.percent > self.disk_threshold + 5 else "WARNING"
                self.check_and_report(f"disk_{part.mountpoint}",
                                      usage.percent > self.disk_threshold,
                                      f"system.disk.{part.mountpoint}",
                                      "low_space",
                                      sev,
                                      {"mount": part.mountpoint,
                                       "usage_percent": usage.percent,
                                       "threshold": self.disk_threshold})
        except Exception as e:
            self.log(error=e, level="ERROR", block="main_try")

        interruptible_sleep(self, self.interval)

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
