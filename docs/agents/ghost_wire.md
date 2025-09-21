#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Ghost Wire

`ghost_wire` is an advanced host intrusion detection agent. It provides three layers of real-time surveillance: user session tracking, suspicious command detection, and file integrity monitoring.

---
## How it Works

1.  **User Tracking**: It uses the `who` command to monitor signed-in users. It logs sign-in and sign-out events.
2.  **Command Polling**: It injects a `PROMPT_COMMAND` into shell configuration files (`.bashrc`) to ensure command history is written in real time. It then polls these history files, checks new commands against a list of suspicious patterns, and logs/alerts on matches.
3.  **File Integrity Monitoring**: It uses `inotify` to watch a list of critical files and directories (e.g., `/etc/passwd`, `/var/www`). It will log any modification, creation, or deletion events in these paths.

---
## Configuration

* **`tick_rate`** (Default: `5`): The interval in seconds for checking user sessions and command history.
* **`command_patterns`** (Default: `["rm -rf", "scp", "sudo"]`): A list of command strings to treat as suspicious.
* **`watch_paths`** (Default: `["/etc/passwd", "/root/.ssh"]`): A list of critical file paths to monitor for changes.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "ghostwire-1",
            "name": "ghost_wire",
            "config": {
                "command_patterns": ["sudo", "su", "wget", "curl"],
                "watch_paths": ["/var/www/html", "/etc/nginx/sites-enabled"]
            }
        }
    ]
}
