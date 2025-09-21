#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Reaper

The `reaper` is a tactical agent designed to terminate other agents. It can operate in two modes: **mission mode**, where it is launched with a specific list of targets to kill, or **patrol mode**, where it runs persistently and watches for "hit cookie" files to appear in other agents' directories.

---
## How it Works

The `reaper` uses the `ReaperUniversalHandler` to manage the termination process. This handler first attempts a "graceful" shutdown by dropping a `die` file into the target's `/incoming` directory. If the agent doesn't shut down within a timeout period, the handler escalates to forcefully terminate the underlying process ID. In mission mode, the `reaper` executes its kill list and then terminates itself. In patrol mode, it continuously scans all `/comm` directories for a `hit.cookie` file and executes a hit on any target specified within.

---
## Configuration

* **`is_mission`** (Default: `false`): If `true`, the agent runs once, kills the `kill_list`, and exits. If `false`, it enters patrol mode.
* **`kill_list`** (Default: `[]`): A list of `universal_id`s to terminate when in mission mode.
* **`delay`** (Default: `0`): Seconds to wait before executing a mission, allowing other processes to initialize.
* **`tombstone_comm`** (Default: `true`): If `true`, leaves a `tombstone` file in the target's `/comm` directory.
* **`tombstone_pod`** (Default: `true`): If `true`, leaves a `tombstone` file in the target's `/pod` directory.

### Example Directive (Mission Mode)
```python
# This directive launches a reaper to kill 'agent-x' and 'agent-y'
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "reaper-assassin-1",
            "name": "reaper",
            "config": {
                "is_mission": True,
                "kill_list": ["agent-x", "agent-y"]
            }
        }
    ]
}
