import os
import subprocess

class Investigator:
    """
    Forensic Investigator for MySQL.
    Correlates status events and error conditions to provide
    concise, actionable findings for operators.
    """
    def __init__(self, agent_ref, service_name, all_events):
        self.agent = agent_ref
        self.service_name = service_name
        self.all_events = all_events

        self.CAUSE_PRIORITIES = [
            # Prioritize resource issues and classic MySQL pitfalls
            {"service": "system.memory", "status": "high_usage", "finding": "Probable Cause: System memory exhaustion."},
            {"service": "system.cpu", "status": "high_load", "finding": "Probable Cause: High CPU load."},
            {"service": "system.disk", "status": "low_space", "finding": "Possible Cause: Low disk space."},
            {"service": "mysql", "status": "crashed", "finding": "Critical: MySQL process crashed."},
            {"service": "mysql", "status": "not_listening", "finding": "MySQL process running but not listening on expected port."},
            {"service": "dependency.filesystem", "status": "readonly", "finding": "Possible Cause: Filesystem went read-only (often fatal for MySQL)."},
        ]

    def add_specific_findings(self, findings):
        self.agent.log(f"Running MYSQL-specific forensic checks for {self.service_name}")
        concise_finding = "No high-priority MySQL cause identified in correlated events."
        primary_cause_found = False

        # Use priority list to find the most likely cause
        for priority in self.CAUSE_PRIORITIES:
            for event in self.all_events:
                if event.get('service_name') == priority['service'] and event.get('status') == priority['status']:
                    concise_finding = priority['finding'] + (f"\nDetails: {event.get('details')}" if event.get('details') else "")
                    primary_cause_found = True
                    break
            if primary_cause_found:
                break

        findings.insert(0, f"**Concise Analysis:**\n---\n{concise_finding}\n---")

        # Pull MySQL or MariaDB error log as supporting evidence
        try:
            log_paths = [
                "/var/log/mysql/error.log",
                "/var/log/mariadb/mariadb.log",
                "/var/log/mysql/mysql.err",
                "/var/log/mysqld.log"
            ]
            for log_path in log_paths:
                if os.path.exists(log_path):
                    log_output = subprocess.check_output(["tail", "-n", "20", log_path], text=True).strip()
                    if log_output:
                        # Search for known error patterns
                        error_patterns = {
                            "segfault": "Apache process segfaulted.",
                            "Syntax error": "Syntax error in Apache config.",
                            "client denied by server configuration": "Access denied by Apache config."
                        }
                        for line in log_output.splitlines():
                            for pattern, explanation in error_patterns.items():
                                if pattern in line:
                                    findings.append(f"**Pattern Match:** {explanation}\n> {line}")
        except Exception as e:
            findings.append(f"[!] MySQL log check failed: {e}")

        return findings
