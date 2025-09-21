#### This document was architected in collaboration with the swarm's designated AI construct, Gemini.  
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Permissions Guardian

`permissions_guardian` is a mission-based agent responsible for enforcing file and directory permissions across designated paths. It detects discrepancies against a configured policy and optionally corrects them. Each run is single-pass and stateful, leaving behind a verifiable, encrypted change history.

---

## How it Works

1. **Config-Driven Scanning**: The agent reads a list of target directories from its `config` block. Each target specifies a path and the desired `file_mode` and `dir_mode` (e.g., `0o644` for files, `0o755` for directories).

2. **Recursive Traversal**: It walks each target directory recursively, comparing the current permissions of each file and subdirectory to the policy.

3. **Permission Enforcement**: If `log_only` is `False`, the agent applies the correct permissions via `chmod`. Otherwise, it only logs discrepancies.

4. **Encrypted History**: Each scan’s results—including what was changed or flagged—are saved into a persistent, encrypted `.state/scan_history.json.enc` file using AES-GCM.

5. **Receipt Drop**: On completion, a `mission.complete` receipt is written to signal to parent cron-based orchestrators that the agent has completed its task and can be rescheduled.

---

## Configuration

* **`is_cron_job`** (Default: `1`): Indicates the agent is designed to run in a cron-managed loop.
* **`cron_interval_sec`** (Default: `300`): Interval in seconds between cron invocations.
* **`log_only`** (Default: `1`): When enabled, the agent logs permission issues without applying fixes.
* **`targets`** (Required): A list of dictionaries, each specifying:
  - `path`: The target path key (e.g., `agent_path`, `core_path`, `comm_path`).
  - `file_mode`: Desired permissions for files (e.g., `420` == `0o644`).
  - `dir_mode`: Desired permissions for directories (e.g., `493` == `0o755`).
---

### Example Directive

```python
{
    "universal_id": "perm-guardian-1",
    "name": "permissions_guardian",
    "config": {
        "is_cron_job": 1,
        "cron_interval_sec": 300,
        "log_only": 1,
        "targets": [
            {"path": "agent_path", "dir_mode": 493, "file_mode": 420},
            {"path": "core_path", "dir_mode": 493, "file_mode": 420},
            {"path": "comm_path", "dir_mode": 509, "file_mode": 436}
        ]
    }
}
```