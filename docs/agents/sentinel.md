#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Sentinel

The `sentinel` is a high-availability watchdog agent. Its primary purpose is to monitor another critical agent (typically `matrix` itself) and automatically re-spawn it if it goes down. This is the key to the swarm's self-healing and resurrection capabilities.

---
## How it Works
The agent monitors the `poke.heartbeat` file of its assigned target. If the timestamp in the heartbeat file becomes older than the configured timeout, the `sentinel` assumes the target agent has crashed. It then uses its `spawn_agent_direct` method to re-launch the target agent using the configuration stored in its `security_box`. A chain of sentinels can be created, each watching the one before it, forming a resilient "protection layer" around the core Matrix agent.

---
## Configuration
* **`watching`** (Default: `"the Matrix"`): A descriptive name for what is being monitored.
* **`universal_id_under_watch`** (Default: `false`): This should be set to the `universal_id` of the agent being monitored.
* **`timeout`** (Default: `60`): The number of seconds a heartbeat can be silent before the target is considered dead.
* **`matrix_secure_verified`** (Default: `false`): If `true`, this sentinel will be injected with the real Matrix private key and a copy of the Matrix agent's configuration, allowing it to perform a full resurrection.

### Example Directive
```python
# A chain of two sentinels protecting the main Matrix agent.
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "guardian-1",
            "name": "sentinel",
            "config": {
                "watching": "guardian-2",
                "universal_id_under_watch": "guardian-2"
            },
            "children": [
                {
                    "universal_id": "guardian-2",
                    "name": "sentinel",
                    "config": {
                        "matrix_secure_verified": 1,
                        "watching": "the Queen",
                        "universal_id_under_watch": "matrix"
                    }
                }
            ]
        }
    ]
}
