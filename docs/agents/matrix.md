#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Matrix

The **`matrix`** agent is the central authority and root node of the entire swarm. It is the "queen" of the hive, the first agent to be spawned by the `site_boot.py` script, and is ultimately responsible for launching, managing, and maintaining the top-level structure of the agent hierarchy defined in a directive.

---
## How it Works

The Matrix agent is unique because it serves several critical system-wide functions that no other agent does.

1.  **Root of Trust**: At boot time, the Matrix agent generates the master cryptographic key pair. It uses its private key to sign the identity tokens of every other agent defined in the directive. This act establishes the "chain of trust" for the entire swarm. An agent's identity is only considered valid if it has been signed by Matrix.
2.  **Primary Spawner**: After initializing, the Matrix agent reads its own `agent_tree.json` directive and begins the process of spawning its direct children (e.g., `commander`, `scavenger`, `sentinel`, etc.) using its `spawn_manager`. These children then go on to spawn their own children, bringing the entire swarm to life hierarchically.
3.  **Central Command Hub**: While agents can communicate directly with each other, many core commands are routed through Matrix. It often acts as a central bus, receiving command packets from external sources (like the `matrix_https` agent) and forwarding them to the appropriate subordinate agent.
4.  **Resurrection Target**: Because of its critical role, the Matrix agent is typically the primary target for protection by a chain of `sentinel` agents. If the Matrix agent crashes, the designated `sentinel` is responsible for resurrecting.

---
## Configuration

The `matrix` agent itself typically requires no special configuration in the `config` block of a directive, as its behavior is fundamental to the system's architecture. Its configuration is the entire `children` array that defines the top level of the swarm.

### Example Directive

The `matrix` node is always the root of any directive file. All other agents are defined as its children.

```python
# A simple directive showing Matrix as the root.
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "commander-1",
            "name": "commander"
        },
        {
            "universal_id": "scavenger-1",
            "name": "scavenger"
        }
    ]
}