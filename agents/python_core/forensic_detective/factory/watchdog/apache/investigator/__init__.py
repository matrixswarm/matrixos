# forensic_detective/factory/watchdog/apache/investigator.py
# Authored by Daniel F MacDonald and Gemini

import os
import subprocess


class Investigator:
    """
    Forensic Investigator for the Apache HTTP Server.

    Correlates status events and error conditions related to Apache to provide
    concise, actionable findings for operators.
    """

    def __init__(self, agent_ref, service_name, all_events):
        """
        Initializes the investigator.

        Args:
            agent_ref (Agent): A reference to the parent ForensicDetective agent.
            service_name (str): The name of the service (should be 'apache').
            all_events (list): A list of all recent event dictionaries from the
                               detective's buffer for correlation.
        """
        self.agent = agent_ref
        self.service_name = service_name
        self.all_events = all_events

        # A prioritized list of known causes for Apache failures.
        self.CAUSE_PRIORITIES = [
            # Resource issues are often the root cause
            {"service": "system.memory", "status": "high_usage",
             "finding": "Probable Cause: System memory exhaustion is impacting Apache performance."},
            {"service": "system.cpu", "status": "high_load",
             "finding": "Probable Cause: High CPU load is starving Apache of resources."},
            {"service": "system.disk", "status": "low_space",
             "finding": "Possible Cause: Low disk space may be preventing Apache from writing logs or cache files."},

            # Apache-specific issues
            {"service": "apache", "status": "crashed",
             "finding": "Critical: The Apache process (httpd/apache2) has crashed."},
            {"service": "apache", "status": "not_listening",
             "finding": "The Apache process is running but not listening on expected ports (80/443)."},
            {"service": "apache", "status": "config_error",
             "finding": "A recent configuration test failed, which may be the cause of the outage."},

            # Filesystem dependencies
            {"service": "dependency.filesystem", "status": "readonly",
             "finding": "Possible Cause: The root filesystem went read-only, which can be fatal for Apache."},
        ]

    def add_specific_findings(self, findings):
        """
        Analyzes events to find the root cause of an Apache failure.

        This method scans correlated events against a priority list of known
        causes and checks recent Apache error logs for specific details.

        Args:
            findings (list): The list of findings to append to.

        Returns:
            list: The updated list of findings with Apache-specific analysis.
        """
        self.agent.log(f"Running APACHE-specific forensic checks for {self.service_name}")
        concise_finding = "No high-priority cause for the Apache event was identified in correlated events."
        primary_cause_found = False

        # Scan for the most likely cause based on priority
        for priority in self.CAUSE_PRIORITIES:
            for event in self.all_events:
                if event.get('service_name') == priority['service'] and event.get('status') == priority['status']:
                    concise_finding = priority['finding']
                    if event.get('details'):
                        concise_finding += f"\nDetails: {event.get('details')}"
                    primary_cause_found = True
                    break
            if primary_cause_found:
                break

        findings.insert(0, f"**Concise Analysis:**\n---\n{concise_finding}\n---")

        # Attach recent Apache error log snippets for context
        try:
            # Common log paths for Apache on different Linux distributions
            log_paths = [
                "/var/log/apache2/error.log",  # Debian/Ubuntu
                "/var/log/httpd/error_log",  # RHEL/CentOS
                "/var/log/apache2/error.log.1",
                "/var/log/httpd/error_log.1"
            ]
            log_found = False
            for log_path in log_paths:
                if os.path.exists(log_path):
                    log_output = subprocess.check_output(["tail", "-n", "20", log_path], text=True,
                                                         stderr=subprocess.DEVNULL).strip()
                    if log_output:
                        findings.append(
                            f"**Recent Apache Error Log ({os.path.basename(log_path)}):**\n---\n```\n{log_output}\n```\n---")
                        log_found = True
                        break  # Stop after finding the first relevant log
            if not log_found:
                findings.append(
                    "**Recent Apache Error Log:**\n---\nCould not find recent entries in standard log locations.\n---")

        except Exception as e:
            findings.append(f"[!] Apache log check failed: {e}")

        return findings