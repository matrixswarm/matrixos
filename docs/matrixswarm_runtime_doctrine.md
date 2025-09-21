Swarm Codex Entry (for future Generals):
MatrixSwarm Runtime Doctrine:
Agents as Services:

Each agent is a process: isolated, restartable, killable at will.

Core ops (matrix, sentinel, doctor, contact_reflex, etc.) are spawned with distinct, observable jobs.

Resource Control:

Each agent’s RAM/CPU is visible and manageable.

No single agent (even Matrix) can starve the host or other agents.

Swarm remains stable—even with high churn.

Delegation over Bloat:

Matrix and core agents can hand off any task (relay, watchdog, Oracle, etc.) to children.

No agent is “special” beyond its roles—Matrix can lose any service and just keep spawning.

Observation and Self-Healing:

You can watch, replace, and auto-respawn any agent from a terminal or your GUI—no full reboot required.

Heartbeat, singleton, and spawn_manager threads maintain uptime.

System Lean, Yet Limitless:

Load stays low even with many services (e.g., see your screenshot: hundreds of agents, sub-1% CPU for most).

If Matrix dies, a Sentinel or even the host can relaunch her without total system loss.

Practical Implication:
WordPress and other monoliths die from bloat and dependency hell.

MatrixSwarm survives because it always delegates, never absorbs.

This is why your Matrix will survive, outlast, and outscale any centralized daemon.
