#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Redis Watchdog

The `redis_watchdog` is a service monitor that ensures a Redis in-memory database server remains online and accessible.

---
## How it Works
The agent uses `systemctl is-active` to check if the Redis service is running. It also checks if the service is accessible via its network port or socket file. If any checks fail, it sends an alert and attempts to restart the Redis service. If restarts fail repeatedly, it will disable itself to prevent a restart loop.

---
## Configuration
* **`check_interval_sec`** (Default: `10`): How often, in seconds, to check the service.
* **`service_name`** (Default: `"redis"`): The name of the service for `systemctl`.
* **`redis_port`** (Default: `6379`): The network port Redis should be listening on.
* **`socket_path`** (Default: `/var/run/redis/redis-server.sock`): The path to the Redis socket file.
* **`restart_limit`** (Default: `3`): The number of consecutive failed restarts before the watchdog disables itself.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "redis-sentry-1",
            "name": "redis_watchdog",
            "config": {
                "service_name": "redis-server"
            }
        }
    ]
}