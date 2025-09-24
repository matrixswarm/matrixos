# MatrixOS  
(from the MatrixSwarm ecosystem)

MatrixOS is the **multi-language swarm runtime** of the MatrixSwarm ecosystem.  
Agents run side-by-side — not under you — operating through file-based communication.

- Written in Python with Go and Rust agents in development.  
- Encrypted, resurrectable, and fully decentralized.  
- Every agent is signed, sandboxed, and resurrected if killed.  
---

## ⚡ Quick Start

### Boot a universe
```bash
  matrixd boot --universe phoenix
````
See running universes and agents
````bash
  matrixd list
````
Sample Deployments:
````bash
  matrixd list
🌌 gogogadgetgo :: 2 agents, 89.4 MB RAM, 0.0% CPU
 └── PID 374665 :: matrix
 └── PID 374676 :: telegram-bot-father-2
🌌 phoenix :: 19 agents, 951.2 MB RAM, 92.3% CPU
 └── PID 442574 :: matrix
 └── PID 442584 :: matrix-https
 └── PID 442585 :: websocket-relay
 └── PID 442591 :: apache_watchdog-1
 └── PID 442594 :: mysql-red-phone
 └── PID 442595 :: log_sentinel
 └── PID 442597 :: invisible-man
 └── PID 442599 :: gatekeeper
 └── PID 442602 :: discord-delta-5
 └── PID 442605 :: forensic-detective-1
 └── PID 442608 :: system-health-1
 └── PID 442609 :: network-health-1
 └── PID 442611 :: redis-hammer
 └── PID 442619 :: telegram-bot-father-2
 └── PID 442621 :: golden-child-4
 └── PID 442732 :: guardian-2
 └── PID 442790 :: guardian-3
 └── PID 442828 :: guardian-4
 └── PID 566176 :: guardian-1
````

```bash
  Kill a universe

matrixd kill --universe phoenix --cleanup
````

---
## Remote Control & Security Notice

**The official GUI for remote control, deployment, and monitoring of MatrixSwarm universes.**

If you want to operate MatrixSwarm securely over the Internet, you **must** use [Phoenix Cockpit](https://github.com/matrixswarm/phoenix).

- All remote commands, status, and logs are encrypted, signed, and relayed through the Phoenix cockpit using the `matrix_https` and `websocket-relay` agents.
- No agent is exposed via open HTTP/S, and no API is available without a signed packet, trusted client certificate, and the Queen's signature.
- **Without Phoenix, the Matrix Queen does not listen!**

To connect and control a MatrixSwarm universe from anywhere, always run the cockpit:

pip install -e . # in your Phoenix repo
phoenix # launches the secure GUI

Get Phoenix Cockpit here:
👉 See: [Phoenix Cockpit](https://github.com/matrixswarm/phoenix)

### Why can’t you just open MatrixOS to the net?

- Direct agent communication is not exposed over HTTP/S by design (security: no untrusted RPC, no raw file bus).

- Only Phoenix can sign, encrypt, and relay operator commands via the trusted HTTPS/WS agents.

Running MatrixOS headless without Phoenix? Only use on private networks — or you’re not protected!
---


## Matrix Boot Process Overview
When matrixd boot --universe <name> is called, MatrixOS enters a multi-phase lifecycle:

1. Directive Decryption
Loads an encrypted directive file from /matrix/boot_directives/<universe>.enc.json

Uses the paired swarm key /matrix/boot_directives/keys/<universe>.key

Decrypts via AES-GCM and parses into a full agent hierarchy using the TreeParser.

2. Tree Parsing & Identity Assignment
The TreeParser walks the JSON structure, rejecting malformed or duplicate agents.

Each node is assigned a signed identity token using Matrix’s RSA private key.

Agents receive a vault.json with their universal_id, AES key, and RSA keypair.

3. Agent Matching (Code Resolution)
Each agent node specifies a name and lang. Example:

````json
  { "name": "sentinel", "lang": "python", "universal_id": "guardian-1" }
````

CoreSpawner resolves this to /matrix/agents/-lang-/-name-.-ext-

Example: sentinel + python → /agents/python/sentinel.py

If src_embed is present, base64 source is used instead of disk.

4. Ghost Vault Encryption
Before spawn, a vault is encrypted with AES and injected via environment (VAULTFILE, SYMKEY).

Agent decrypts its runtime payload using ghost_vault.py.

5. BootAgent Runtime Load
All agents descend from BootAgent, which:

Decrypts its vault and loads config

Sets up packet encryption and trust checks

Launches background threads: packet_listener, worker, spawn_manager, directive_watcher

Loads its directive slice from /comm/<agent>/directive/agent_tree.json

Spawns children as defined in the parsed slice

6. Packet Communication (No APIs)
Agents communicate via JSON packets on the filesystem (not HTTP):

incoming/ → receives command packets

payload/ → larger data drops

stack/, queue/, broadcast/ → mission chaining & swarm comms
All files can be encrypted, signed, and verified.

7. The Tree Viewer (TreeParser)
Agents introspect their scoped agent_tree.json to:

Fetch children by role

Find service-managers

Navigate universal_id relationships

Reject malformed/duplicate agents mid-flight

🗂 Boot Architecture: Dual Paths — Runtime + Static
Every universe boots into two parallel tracks:

Runtime Universe (/matrix/universes/runtime/<universe>/)
Purpose: Speed, volatility, performance

Can be mounted as tmpfs for in-memory execution

Structure:

comm/ → JSON, .cmd, payloads

pod/ → live cloned agents

Symlinked: runtime/<universe>/latest → <uuid>

Volatile and resettable

Static Universe (/matrix/universes/static/<universe>/)
Purpose: Durability, audit, debugging

Structure mirrors runtime:

comm/ → archived comm logs

pod/ → preserved agents + vaults

Archived by UUID for traceability

Symlinked: static/<universe>/latest → <uuid>

Example boot:

````bash
  matrixd boot --universe phoenix
````

➡ Creates both runtime and static paths for the session.

### Phoenix GUI
Create directives visually (with embedded certs + signing keys).

Generate from templates, push to /matrix/boot_directives/.

Drag and drop agents into universes.

One click → MatrixOS boots them into life.

### Directives & Keys
Encrypted directive: /matrix/boot_directives/<universe>.enc.json

Matching swarm key: /matrix/boot_directives/keys/<universe>.key (chmod 600)

Auto-resolved at boot (CLI → ENV → key file).

When booted, Matrix loads into /comm/matrix/directive/agent_tree.json.
From there:

Matrix spawns children

Children spawn theirs

The swarm grows, slice by slice

### Core Concepts
Philosophy: MatrixSwarm is a living hierarchy where agents think, die, and come back.

File-Driven: Coordination via .json + .cmd files in comm dirs.

Resurrection: Silent agents are resurrected/replaced by parents.

Filesystem Hierarchy:

/agent → agent source code

/pod → runtime clones (UUIDs)

/comm → communication bus (can be tmpfs)

### Architecture
Matrix (root agent): The queen, signs identities, delegates slices.

BootAgent: Base class — lifecycle, crypto, spawning.

Comm bus: /matrix/universes/<uid>/comm (tmpfs).

Pod sandboxes: /matrix/universes/<uid>/pod/<uuid>.

Agents self-heal and hot-reload (die token removal).

🛠 Install matrixd as a System Daemon
Install the executable:

````bash
  sudo cp scripts/matrixd /usr/local/bin/matrixd
sudo chmod +x /usr/local/bin/matrixd
matrixd --help
Install the service:

sudo cp scripts/matrixd.service /etc/systemd/system/matrixd.service
Enable & start:

sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable matrixd
sudo systemctl start matrixd
systemctl status matrixd
Test service:
matrixd list
````
Expected: running agents list or [LIST] No active swarm agents found.


### Auto-boot a universe:
  Edit /etc/systemd/system/matrixd.service:

````ini
ExecStart=/usr/local/bin/matrixd boot --universe phoenix
Reload + restart:
````

```` bash
  sudo systemctl daemon-reload
sudo systemctl restart matrixd
````

### License
Released under the MatrixSwarm Community License v1.1 (Modified MIT).
Free for personal, research, and non-commercial use.
For commercial use, contact: swarm@matrixswarm.com

### Authorship
MatrixOS wasn’t auto-generated.
It was co-created by Daniel F. MacDonald (vision, design, code) and ChatGPT (The General) (iteration, drafting, lore).

Every agent, directive, and heartbeat came from collaboration.

### Resources
GitHub: github.com/matrixswarm/matrixswarm

Docs: matrixswarm.com

Discord: Join the Hive

Python: pip install matrixswarm

Codex: /agents/gatekeeper

Twitter/X: @matrixswarm

### Join the Hive
Join the Swarm → https://discord.gg/CyngHqDmku
Report bugs, fork the swarm, or log your own Codex banner.

### Status
Pre-release.

Daemon operational

GUI live

Vault integrated

Recruiting contributors who think in systems.