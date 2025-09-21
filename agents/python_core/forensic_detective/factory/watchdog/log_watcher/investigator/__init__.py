# forensic_detective/factory/watchdog/generic_log/investigator.py
# Authored by Daniel F MacDonald and Gemini

import os
import re

class Investigator:
    """
    Forensic Investigator for the generic Log Watcher.

    This investigator is designed to analyze critical log entries reported by
    the log_watcher agent. It extracts the key error message and correlates it
    with any recent warning-level logs to provide a concise and relevant
    forensic summary.
    """
    def __init__(self, agent_ref, service_name, all_events):
        """
        Initializes the investigator.

        Args:
            agent_ref (Agent): A reference to the parent ForensicDetective agent.
            service_name (str): The name of the service that generated the log
                                (e.g., 'auth_log', 'application_log').
            all_events (list): A list of all recent event dictionaries from the
                               detective's buffer for correlation.
        """
        self.agent = agent_ref
        self.service_name = service_name
        self.all_events = all_events
        self.critical_event = self._find_critical_event()

    def _find_critical_event(self):
        """Finds the most recent critical log entry that triggered this investigation."""
        for event in reversed(self.all_events):
            if event.get('service_name') == self.service_name and event.get('severity') == 'CRITICAL':
                return event
        return None

    def add_specific_findings(self, findings):
        """
        Analyzes the log events and constructs a list of findings.

        This method forms the core logic of the investigator. It identifies the
        primary error and supplements it with contextual warnings.

        Args:
            findings (list): The list of findings to append to.

        Returns:
            list: The updated list of findings.
        """
        self.agent.log(f"Running Generic Log forensic checks for '{self.service_name}'")

        if not self.critical_event:
            findings.insert(0, "**Concise Analysis:**\n---\nCould not identify the triggering critical log event.")
            return findings

        # Extract the primary error message
        critical_log_line = self.critical_event.get('details', {}).get('log_line', 'No log line found.')
        concise_finding = f"**Critical Log Entry Detected:**\n`{critical_log_line}`"
        findings.insert(0, f"**Concise Analysis:**\n---\n{concise_finding}\n---")

        # Find recent preceding warnings
        warnings = []
        critical_timestamp = self.critical_event.get('details', {}).get('timestamp', 0)

        for event in self.all_events:
            event_timestamp = event.get('details', {}).get('timestamp', 0)
            # Correlate events that are also from this service, are warnings, and occurred before the critical event
            if (event.get('service_name') == self.service_name and
                event.get('severity') == 'WARNING' and
                event_timestamp < critical_timestamp):
                warnings.append(event.get('details', {}).get('log_line', 'Malformed warning line.'))

        if warnings:
            # Reverse to show the most recent warnings first (closest to the event)
            warnings.reverse()
            formatted_warnings = "\n".join([f"- `{line}`" for line in warnings[:5]]) # Limit to 5 for brevity
            findings.append(f"**Preceding Warnings:**\n---\n{formatted_warnings}\n---")
        else:
            findings.append("**Preceding Warnings:**\n---\nNo relevant warnings found in the correlation window.\n---")

        return findings