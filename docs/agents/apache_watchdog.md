#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Apache Watchdog

The `apache_watchdog` agent is a service monitor designed to ensure an Apache web server remains online and healthy. It periodically checks the status of the `httpd` or `apache2` service and its network ports, attempts to restart it if it fails, and sends alerts to other agents.

---
## How it Works

The agent operates in a loop with the following logic:

1.  **Check Service**: It uses `systemctl is-active` to verify if the Apache service is running.
2.  **Check Ports**: It uses the `ss` command to ensure that the configured web ports (e.g., 80, 443) are open and listening.
3.  **Take Action**:
    * If both checks pass, it logs that the service is healthy.
    * If either check fails, it logs the failure, sends an alert to configured relay agents (like `discord_relay`), and attempts to restart the Apache service using `systemctl restart`.
4.  **Fail-Safe**: If the restart command fails multiple times in a row (exceeding `restart_limit`), the watchdog will disable itself to prevent a destructive restart loop and send a final alert that it has been disabled.

---
## Configuration

Add the `apache_watchdog` to your directive and customize its behavior in the `config` block.

**Configurable Options:**

* **`check_interval_sec`** (Default: `10`): How often, in seconds, to check the service.
* **`service_name`** (Default: `"httpd"`): The name of the service for `systemctl` (use `"apache2"` for Debian/Ubuntu).
* **`ports`** (Default: `[80, 443]`): A list of network ports that should be open.
* **`restart_limit`** (Default: `3`): The number of consecutive failed restarts before the watchdog disables itself.
* **`always_alert`** (Default: `true`): If true, sends an alert on every detected failure. If false, it uses the `alert_cooldown`.
* **`alert_cooldown`** (Default: `300`): The number of seconds to wait before sending another alert for the same issue.

### Example Directive

This directive deploys an `apache_watchdog` configured for an Ubuntu server.

```python
# /boot_directives/webserver_monitoring.py

matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        # An agent to receive the alerts
        {
            "universal_id": "discord-1",
            "name": "discord_relay",
            # ... other config for discord relay
        },
        # The watchdog itself
        {
            "universal_id": "apache-sentry-1",
            "name": "apache_watchdog",
            "config": {
                "check_interval_sec": 30,
                "service_name": "apache2",
                "ports": [80]
            }
        }
    ]
}

