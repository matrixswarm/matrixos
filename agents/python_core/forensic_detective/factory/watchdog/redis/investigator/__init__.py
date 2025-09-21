#Authored by Daniel F MacDonald and ChatGPT aka The Generals
import os
import subprocess

class Investigator:
    """
    Forensic Investigator for Redis.
    Correlates status events and error conditions to provide
    concise, actionable findings for operators.
    """
    def __init__(self, agent_ref, service_name, all_events):
        self.agent = agent_ref
        self.service_name = service_name
        self.all_events = all_events

        self.CAUSE_PRIORITIES = [
            # System-level first
            {"service": "system.memory", "status": "high_usage", "finding": "Probable Cause: System memory exhaustion (Redis heavily depends on RAM)."},
            {"service": "system.cpu", "status": "high_load", "finding": "Possible Cause: CPU contention affecting Redis latency."},
            {"service": "system.disk", "status": "low_space", "finding": "Possible Cause: Disk space exhaustion (persistence writes failing)."},
            # Redis-specific
            {"service": "redis", "status": "crashed", "finding": "Critical: Redis process crashed."},
            {"service": "redis", "status": "not_listening", "finding": "Redis running but not listening on expected port/socket."},
            {"service": "dependency.filesystem", "status": "readonly", "finding": "Possible Cause: Filesystem went read-only, blocking AOF/RDB persistence."},
        ]

    def add_specific_findings(self, findings):
        self.agent.log(f"Running REDIS-specific forensic checks for {self.service_name}")
        concise_finding = "No high-priority Redis cause identified in correlated events."
        primary_cause_found = False

        # Priority scan
        for priority in self.CAUSE_PRIORITIES:
            for event in self.all_events:
                if event.get('service_name') == priority['service'] and event.get('status') == priority['status']:
                    concise_finding = priority['finding'] + (f"\nDetails: {event.get('details')}" if event.get('details') else "")
                    primary_cause_found = True
                    break
            if primary_cause_found:
                break

        findings.insert(0, f"**Concise Analysis:**\n---\n{concise_finding}\n---")

        # Attach recent Redis logs if available
        try:
            log_paths = [
                "/var/log/redis/redis-server.log",
                "/var/log/redis/redis.log"
            ]
            for log_path in log_paths:
                if os.path.exists(log_path):
                    log_output = subprocess.check_output(["tail", "-n", "20", log_path], text=True).strip()
                    if log_output:
                        findings.append(f"**Recent Redis Log ({log_path}):**\n---\n{log_output}\n---")
                        break
        except Exception as e:
            findings.append(f"[!] Redis log check failed: {e}")

        return findings
