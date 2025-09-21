#### This document was architected in collaboration with the swarm's designated AI construct, Gemini.
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Agent Doctor

`agent_doctor` is a system-level diagnostic agent responsible for monitoring the health and responsiveness of all other agents within the swarm. It acts as a watchdog, periodically performing health checks and reporting the status of each agent's core processes.

---
## How it Works

1.  **Swarm Scan**: The doctor begins by scanning the central communication directory to compile a list of all registered agents.
2.  **Phantom Detection**: For each agent found, it cross-references with the pod directory to ensure a boot file exists. If an agent's communication files are present but its boot file is missing, it is flagged as a "phantom" and reported.
3.  **Beacon Verification**: For legitimate agents, the doctor checks a special `hello.moto` directory for beacon files (e.g., `poke.heartbeat`, `poke.worker`). These files are regularly updated by each agent's active threads.
4.  **Consciousness Check**: It reads the timestamp from each beacon file and calculates its age. Based on this age, it determines the status of the thread as:
    * `✅`: Healthy and responsive.
    * `⚠️ Stale`: The beacon hasn't been updated recently.
    * `💥 Expired`: The beacon is significantly out of date.
    * `💀 Dead`: The thread has explicitly reported a fatal error.
5.  **Reporting**: The doctor logs a consolidated status report for every agent in the swarm, providing a clear and immediate overview of the swarm's operational health.

---
## Configuration

* **`max_allowed_beacon_age`** (Default: `8`): The maximum age in seconds a beacon can be before it is considered "stale". A beacon twice this age is considered "expired".

---
### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "agent-doctor-1",
            "name": "agent_doctor",
            "config": {
                "max_allowed_beacon_age": 10
            }
        }
    ]
}