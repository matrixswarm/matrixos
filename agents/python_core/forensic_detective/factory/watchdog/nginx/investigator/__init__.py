import os
import subprocess

class Investigator:
    """
    Forensic Investigator for Nginx.
    Correlates status events and error conditions to provide
    concise, actionable findings for operators.
    """
    def __init__(self, agent_ref, service_name, all_events):
        self.agent = agent_ref
        self.service_name = service_name
        self.all_events = all_events

        self.CAUSE_PRIORITIES = [
            # Resource issues first
            {"service": "system.memory", "status": "high_usage", "finding": "Probable Cause: System memory exhaustion."},
            {"service": "system.cpu", "status": "high_load", "finding": "Probable Cause: High CPU load."},
            {"service": "system.disk", "status": "low_space", "finding": "Possible Cause: Low disk space on a critical partition."},
            # Nginx-specific
            {"service": "nginx", "status": "crashed", "finding": "Critical: Nginx process crashed."},
            {"service": "nginx", "status": "not_listening", "finding": "Nginx process running but not listening on expected ports."},
            {"service": "dependency.filesystem", "status": "readonly", "finding": "Possible Cause: Filesystem went read-only (fatal for Nginx writes)."},
        ]

    def add_specific_findings(self, findings):
        self.agent.log(f"Running NGINX-specific forensic checks for {self.service_name}")
        concise_finding = "No high-priority Nginx cause identified in correlated events."
        primary_cause_found = False

        # Priority scan for the most likely cause
        for priority in self.CAUSE_PRIORITIES:
            for event in self.all_events:
                if event.get('service_name') == priority['service'] and event.get('status') == priority['status']:
                    concise_finding = priority['finding'] + (f"\nDetails: {event.get('details')}" if event.get('details') else "")
                    primary_cause_found = True
                    break
            if primary_cause_found:
                break

        findings.insert(0, f"**Concise Analysis:**\n---\n{concise_finding}\n---")

        # Attach recent Nginx error log (if available)
        try:
            log_paths = [
                "/var/log/nginx/error.log",
                "/var/log/nginx/error.log.1"
            ]
            for log_path in log_paths:
                if os.path.exists(log_path):
                    log_output = subprocess.check_output(["tail", "-n", "20", log_path], text=True).strip()
                    if log_output:
                        findings.append(f"**Recent Nginx Error Log ({log_path}):**\n---\n{log_output}\n---")
                        break
        except Exception as e:
            findings.append(f"[!] Nginx log check failed: {e}")

        return findings
