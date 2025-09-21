# 🤝 Contributing to MatrixSwarm

Welcome to the Hive.
MatrixSwarm is a living system — an AI-native OS that spawns agents, self-heals, and delegates.
If you're reading this, you're already one of us.

---

## 🧭 How to Get Started

```bash
git clone https://github.com/matrixswarm/matrixswarm.git
cd matrixswarm
python3 bootloader.py
```

Then launch the GUI:
```bash
python3 gui/matrix_gui.py
```

> From here, you can spawn agents, inject missions, and view logs in real time.

---

## 🧪 How to Build a Basic Agent

Create a Python file under `/agent/youragent/youragent.py`:

```python
from core.python_core.boot_agent import BootAgent

class YourAgent(BootAgent):
    def worker(self):
        while self.running:
            self.log("[YOURAGENT] Still breathing...")
            time.sleep(5)
```

Create a mission file to spawn it:
```json
{
  "universal_id": "youragent-1",
  "agent_name": "YourAgent",
  "delegated": []
}
```
Drop it into the GUI or send it via the HTTPS `/matrix` endpoint.

---

## 🔐 How to Generate HTTPS Certs

MatrixSwarm uses mutual TLS. Here’s how to create local certs for GUI-to-Matrix HTTPS:

### Step 1: Generate Root CA
```bash
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem
```

### Step 2: Server Cert
```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out server.crt -days 500 -sha256
```

### Step 3: Client Cert
```bash
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out client.crt -days 500 -sha256
```

Put them in `/certs/` and you’re good to go.

---

## 🧬 Missions and Teams

### A single agent:
```json
{
  "universal_id": "logger-1",
  "agent_name": "Logger",
  "delegated": []
}
```

### A team file:
Place it in `deploy/teams/logger_team.json`:
```json
{
  "universal_id": "logger-alpha",
  "agent_name": "Logger",
  "delegated": ["listener-1", "watchdog-2"]
}
```

Use the GUI dropdown or inject via HTTPS.

---

## 🎯 Contribution Targets

- ✅ New agents (helpers, watchdogs, swarm intelligence)
- ✅ GUI improvements (dark mode, diagnostics, tooltips)
- ✅ Tree auditing / logging utilities
- ✅ Clean mission templates or documentation
- ✅ Fix ghost node bugs or malformed children

Every file you touch should have purpose. Every agent you build should have a name.

---

## 🎖 Swarm Lore Is Real

All core agents contain **Swarm Lore Banners™**. These are sacred headers that declare their role.

If you create a new agent, honor the tradition:
```python
# ╔════════════════════════════════════╗
# ║        🐝 BUZZ AGENT 🐝           ║
# ║  Signal Amplifier · Ping Beacon   ║
# ║  Born under the Pulse Protocol    ║
# ╚════════════════════════════════════╝
```

---

## 🧠 Final Note

MatrixSwarm is not a project.
It’s a system. A digital ecology.

No change is too small. No agent is meaningless.

> Inject it. Tag it. Evolve it.

🧠⚔️

