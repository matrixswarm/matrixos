#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Commander

The `commander` agent acts as a simple, text-based dashboard for the swarm. Its purpose is to provide a live status overview of all running agents within the same universe.

---
## How it Works

The agent's `worker()` method periodically scans the `/comm` and `/pod` directories to identify all "real" agents (those with a `boot.json` file). For each agent found, it checks the timestamp of its `poke.heartbeat` file to determine how long ago it was last seen. It then logs a formatted table to its own log file, showing each agent's ID, status flag (✅, ⚠️, ❌), and last seen time.

---
## Configuration

The `commander` agent requires no special configuration in the directive.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "commander-1",
            "name": "commander"
        }
    ]
}
```
To view the dashboard, tail the commander's log file:
```bash
tail -f /comm/commander-1/logs/agent.log
```

