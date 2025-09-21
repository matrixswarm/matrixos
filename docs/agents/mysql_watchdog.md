#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: MySQL Watchdog

The `mysql_watchdog` is a service monitor designed to ensure a MySQL or MariaDB database server remains online and healthy.

---
## How it Works

The agent periodically checks the database service using `systemctl is-active`. If the service is down, it will attempt to restart it. It also checks if the service is listening on its configured network port and socket file. If any checks fail, it sends a detailed alert packet to agents with the `hive.alert.send_alert_msg` role. If restarts fail repeatedly, it will disable itself to prevent a restart loop.

---
## Configuration

* **`check_interval_sec`** (Default: `20`): How often, in seconds, to check the service.
* **`mysql_port`** (Default: `3306`): The network port the database should be listening on.
* **`socket_path`** (Default: `/var/run/mysqld/mysqld.sock`): The path to the MySQL socket file.
* **`service_name`** (Default: `"mysql"`): The name of the service for `systemctl` (use `"mariadb"` for MariaDB).
* **`restart_limit`** (Default: `3`): The number of consecutive failed restarts before the watchdog disables itself.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "mysql-sentry-1",
            "name": "mysql_watchdog",
            "config": {
                "service_name": "mariadb"
            }
        }
    ]
}