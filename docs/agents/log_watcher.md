#### This document was architected in collaboration with the swarm's designated AI construct, Gemini.
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Log Watcher

`log_watcher` is a flexible and robust agent designed to monitor any specified log file in real-time. It tails the file, intelligently classifies new entries based on custom rules, and reports them to the swarm for analysis, making it a foundational sensor for system and application monitoring.

---
## How it Works

1.  **Log Tailing**: The agent continuously monitors a specified log file for new lines. It is built to handle log rotation gracefully, automatically detecting when a file has been rotated and seamlessly switching to the new file without losing its place.
2.  **Severity Classification**: Using a configurable set of rules (`severity_rules`), the agent scans each new log line for keywords. Based on these keywords, it assigns a severity level (`INFO`, `WARNING`, `CRITICAL`) to the event.
3.  **Report Dispatch**: Once a line is processed and classified, the agent packages the information—including the original log line, the assigned severity, and the service name—into a standardized status report.
4.  **Targeted Reporting**: The report is sent to all agents within the swarm that have the designated `report_to_role` (e.g., `hive.forensics.data_feed`), ensuring that the data is delivered to the correct analytical agents like `forensic_detective`.

---
## Integration with Forensic Detective

`log_watcher` is a primary data source for `forensic_detective`. This integration allows the swarm to turn raw log data into intelligent, correlated security alerts.

* **Triggering Analysis**: When `log_watcher` sends a report with a `CRITICAL` severity, it triggers `forensic_detective` to begin a new investigation.
* **Specialized Investigators**: The `forensic_detective` uses the `service_name` from the log watcher's report to load a specialized "investigator" module. For `log_watcher`, this is the `generic_log` investigator.
* **Contextual Correlation**: The `generic_log` investigator analyzes the critical log line and correlates it with recent `WARNING` level events from the same log file, providing crucial context about what led up to the critical event. This turns a single error line into a meaningful narrative, such as "Critical error preceded by multiple failed login attempts."

---
## Configuration

* **`log_path`** (Required): The absolute path to the log file you want to monitor (e.g., `/var/log/auth.log`, `/var/log/nginx/access.log`).
* **`service_name`** (Default: `generic_log`): A unique name for the service generating the log. This name is used by `forensic_detective` to load the correct investigator factory. For this agent, it should typically be kept as `generic_log`.
* **`report_to_role`** (Default: `hive.forensics.data_feed`): The swarm role that should receive the status reports. This should point to your `forensic_detective` agents.
* **`severity_rules`** (Required): A dictionary that defines the keywords used to classify log lines. You can define keywords for `CRITICAL` and `WARNING` levels. Any line not matching these is considered `INFO`.

### Example Directive

This directive configures `log_watcher` to monitor the system's authentication log, flagging root logins as critical and failed password attempts as warnings.

```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "auth-log-monitor-1",
            "name": "log_watcher",
            "config": {
                "log_path": "/var/log/auth.log",
                "service_name": "generic_log",
                "report_to_role": "hive.forensics.data_feed",
                "severity_rules": {
                    "CRITICAL": [
                        "session opened for user root"
                    ],
                    "WARNING": [
                        "failed password",
                        "invalid user",
                        "authentication failure"
                    ]
                }
            }
        }
    ]
}