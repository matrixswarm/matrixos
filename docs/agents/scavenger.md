#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Scavenger

The `scavenger` agent is the swarm's automated cleanup crew. It runs in the background and is responsible for removing the directories and runtime files of agents that have been properly terminated.

---
## How it Works
The agent periodically scans all agent `pod` directories. For each pod, it checks for the existence of `tombstone` and `die` files in both its `/pod` and `/comm` directories. If these signals are present and older than a set time (to prevent cleaning up during a graceful shutdown), the scavenger verifies the agent's process is no longer running. Once confirmed dead, it completely removes the agent's `/pod` and `/comm` directories from the filesystem and sends a `cmd_deletion_confirmation` packet to Matrix.

---
## Configuration
The `scavenger` agent requires no special configuration in the directive.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "scavenger-1",
            "name": "scavenger"
        }
    ]
}