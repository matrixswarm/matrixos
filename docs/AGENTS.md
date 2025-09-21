#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference Library

This library provides documentation for the pre-built agents included with MatrixSwarm. Each agent is a specialized tool designed to perform a specific function within the swarm.

---
## Agent Categories

# Agent Reference Library

This library provides documentation for the pre-built agents included with MatrixSwarm. Each agent is a specialized tool designed to perform a specific function within the swarm.

---
## Agent Categories

### Core & Command
| Agent Name | Purpose | Link |
| :--- | :--- | :--- |
| **`matrix`** | The central brain and message routing core.python_core. | `[Details](./agents/matrix.md)` |
| **`commander`**| Provides a live, text-based dashboard of all swarm agents' status. | `[Details](./agents/commander.md)` |
| **`matrix_https`**| A secure Flask-based web server that exposes an API to interact with the swarm. | `[Details](./agents/matrix_https.md)` |
| **`matrix_websocket`**| Provides a secure WebSocket server for real-time, bidirectional communication. | `[Details](./agents/matrix_websocket.md)` |

### Security & Monitoring
| Agent Name | Purpose | Link |
| :--- | :--- | :--- |
| **`apache_watchdog`**| Monitors and restarts the Apache web server. | `[Details](./agents/apache_watchdog.md)` |
| **`ghost_wire`** | An advanced security agent that monitors user logins, commands, and file changes. | `[Details](./agents/ghost_wire.md)` |
| **`gatekeeper`** | Monitors authentication logs for security events. | `[Details](./agents/gatekeeper.md)` |
| **`mysql_watchdog`** | Monitors and restarts a MySQL/MariaDB database service. | `[Details](./agents/mysql_watchdog.md)` |
| **`nginx_watchdog`** | Monitors and restarts the Nginx web server. | `[Details](./agents/nginx_watchdog.md)` |
| **`redis_watchdog`** | Monitors and restarts a Redis in-memory database service. | `[Details](./agents/redis_watchdog.md)` |
| **`reaper`** | A tactical agent that securely terminates other agents or patrols for kill orders. | `[Details](./agents/reaper.md)` |
| **`scavenger`** | Automatically cleans up the directories of dead or tombstoned agents. | `[Details](./agents/scavenger.md)` |
| **`sentinel`** | A high-availability watchdog that resurrects critical agents (like Matrix) if they fail. | `[Details](./agents/sentinel.md)` |
| **`tripwire_lite`** | Monitors critical filesystem paths for changes. | `[Details](./agents/tripwire_lite.md)` |

### Forensic Intelligence
| Agent Name | Purpose | Link |
| :--- | :--- | :--- |
| **`forensic_detective`**| The central analysis agent. Ingests events, correlates data, and determines the root cause of failures. | `[Details](./agents/forensic_detective.md)` |
| **`system_health`** | Monitors core system resources (CPU, Memory, Disk) and reports warnings to the detective. | `[Details](./agents/system_health.md)` |
| **`network_health`** | Monitors network interfaces, connection counts, and traffic, reporting anomalies to the detective. | `[Details](./agents/network_health.md)` |


### Communication & Relays
| Agent Name | Purpose | Link |
| :--- | :--- | :--- |
| **`discord_relay`**| Sends alerts and messages to a Discord channel. | `[Details](./agents/discord_relay.md)` |
| **`email_check`** | Connects to an IMAP server to read and process unseen emails. | `[Details](./agents/email_check.md)` |
| **`email_send`** | Watches a directory for JSON files and sends them as emails via SMTP. | `[Details](./agents/email_send.md)` |
| **`telegram_relay`** | Forwards alert packets from the swarm to a Telegram chat. | `[Details](./agents/telegram_relay.md)` |
| **`oracle`** | Connects to an LLM API (like OpenAI) to answer prompts from other agents. | `[Details](./agents/oracle.md)` |

### Utilities & Integrations
| Agent Name | Purpose | Link |
| :--- | :--- | :--- |
| **`blank`** | A boilerplate template for creating new custom agents. | `[Details](./agents/blank.md)` |
| **`google_calendar`**| Connects to the Google Calendar API to fetch and broadcast upcoming events. | `[Details](./agents/google_calendar.md)` |
| **`load_range`** | Samples system load average and generates daily performance reports. | `[Details](./agents/load_range.md)` |
| **`storm_crow`** | Monitors the National Weather Service for severe weather alerts in a given area. | `[Details](./agents/storm_crow.md)` |