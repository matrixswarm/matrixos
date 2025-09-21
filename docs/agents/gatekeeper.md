#### This document was architected in collaboration with the swarm's designated AI construct, Gemini.
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Gatekeeper

`gatekeeper` is a specialized sentinel agent that monitors SSH login activity. It provides real-time alerts for new SSH sessions, enriched with geographic location data to help identify unauthorized access attempts.

---
## How it Works

1.  **Log Tailing**: The agent actively monitors the system's authentication log file (`/var/log/secure` or `/var/log/auth.log`) for new entries.
2.  **Event Parsing**: It specifically looks for lines indicating a successful SSH login ("Accepted"). When a login event is detected, it parses the line to extract the username, source IP address, and authentication method (password or public key).
3.  **GeoIP Enrichment**: For each login, it uses a local MaxMind GeoIP database to resolve the source IP address to a geographic location (city and country).
4.  **Alerting**: It formats the gathered information—user, IP, location, and time—into a structured alert message and dispatches it to designated alert-handling agents within the swarm.

---
## Configuration

* **`log_path`** (Default: `/var/log/secure` or `/var/log/auth.log`): The absolute path to the SSH authentication log file. The agent auto-detects the correct path on most systems.
* **`maxmind_db`** (Default: `GeoLite2-City.mmdb`): The path to the MaxMind GeoIP database file used for IP address lookups.
* **`always_alert`** (Default: `1`): When enabled (`1`), an alert is sent for every login. If disabled (`0`), it will only alert once per unique IP address within a 5-minute cooldown period.
* **`geoip_enabled`** (Default: `1`): Enables or disables the GeoIP lookup functionality.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "gatekeeper-1",
            "name": "gatekeeper",
            "config": {
                "always_alert": 0,
                "geoip_enabled": 1
            }
        }
    ]
}