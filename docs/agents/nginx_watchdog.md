#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Nginx Watchdog

The `nginx_watchdog` is a service monitor that ensures the Nginx web server remains online and healthy.

---
## How it Works

The agent uses `systemctl is-active` to check if the Nginx service is running and `ss -ltn` to verify that it is listening on its configured web ports (e.g., 80, 443). If either check fails, it sends an alert and attempts to restart the Nginx service. If restarts fail repeatedly, it will disable itself to prevent a restart loop and send a final critical alert.

---
## Configuration

* **`check_interval_sec`** (Default: `10`): How often, in seconds, to check the service.
* **`service_name`** (Default: `"nginx"`): The name of the service for `systemctl`.
* **`ports`** (Default: `[80, 443]`): A list of network ports that Nginx should be listening on.
* **`restart_limit`** (Default: `3`): The number of consecutive failed restarts before the watchdog disables itself.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "nginx-sentry-1",
            "name": "nginx_watchdog",
            "config": {
                "ports": [80, 443, 8080]
            }
        }
    ]
}