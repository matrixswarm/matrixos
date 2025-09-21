#Authored by Daniel F MacDonald and Gemini
import sys
import os
import psutil

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    """
    A config-driven MatrixSwarm agent that monitors system resources.
    It sends reports to the role defined in its configuration.
    """
    def __init__(self):
        """
        Initializes the agent and loads its configuration directly from the
        directive's tree_node, following the swarm's standard pattern.
        """
        super().__init__()
        try:
            self.name = "SystemHealthMonitor"

            # Get the agent's specific config dictionary from the global tree_node.
            config = self.tree_node.get("config", {})

            self.log("Initializing SystemHealthMonitor from directive config...")

            # Set attributes, using config values but keeping original defaults as fallbacks.
            self.mem_threshold = config.get("mem_threshold_percent", 95.0)
            self.cpu_threshold = config.get("cpu_threshold_percent", 90.0)
            self.disk_threshold = config.get("disk_threshold_percent", 95.0)
            self.interval = config.get("check_interval_sec", 60)
            self.report_to_role = config.get("report_to_role", "hive.forensics.data_feed")


            self.log(f"Monitoring configured: [Mem: {self.mem_threshold}%, CPU: {self.cpu_threshold}%, Disk: {self.disk_threshold}%]")
            self.log(f"Reporting to role '{self.report_to_role}'")
            self._emit_beacon = self.check_for_thread_poke("worker", timeout=self.interval*2, emit_to_file_interval=10)
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def send_status_report(self, service_name, status, severity, details):
        """Helper method to construct and send a status packet to the configured role."""
        try:
            if not self.report_to_role:
                self.log(f"alert handler {self.report_to_role} not provided.", level='ERROR')
                return

            endpoints = self.get_nodes_by_role(self.report_to_role)
            if not endpoints:
                self.log(f"No alert-compatible agents found for '{self.report_to_role}'", level='ERROR')
                return

            pk_content = {
                "handler": self.report_to_role,
                "content": {"source_agent": self.name,
                            "service_name": service_name,
                            "status": status,
                            "details": details,
                            "severity": severity}
            }


            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data(pk_content)

            pk.set_packet(pk, "content")

            for ep in endpoints:
                pk.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk, ep.get_universal_id())
                self.log(f"[SYSTEM-HEALTH] Sent '{severity}' for '{service_name}' → {ep.get_universal_id()} ({self.report_to_role})", level="WARN")

            #if self.debug.is_enabled():
            #    self.log(f"Sent '{severity}' for '{service_name}' to role '{self.report_to_role}'", level="INFO")
        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def worker(self, config: dict = None, identity: IdentityObject = None):
        """Main execution loop for the agent."""
        try:
            self._emit_beacon()
            # Check Memory
            mem = psutil.virtual_memory()
            if mem.percent > self.mem_threshold:
                self.send_status_report("system.memory", "high_usage", "WARNING",
                                        f"Memory usage is critical: {mem.percent:.2f}%.")

            # Check CPU
            cpu = psutil.cpu_percent(interval=1)
            if cpu > self.cpu_threshold:
                self.send_status_report("system.cpu", "high_load", "WARNING", f"CPU load is critical: {cpu:.2f}%.")

            # Check Disk
            disk = psutil.disk_usage('/')
            if disk.percent > self.disk_threshold:
                self.send_status_report("system.disk", "low_space", "WARNING",
                                        f"Root disk space is critical: {disk.percent:.2f}% full.")


        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

        interruptible_sleep(self, self.interval)

if __name__ == "__main__":
    agent = Agent()
    agent.boot()