# 🧭 Swarm Vault + GUI Blueprint

## 🎯 Aims
- **Replace manual cert juggling** with a fully automated, GUI-driven workflow.  
- **Isolate each deployment** so no two swarms ever share certs (no “1 password for 1000 sites”).  
- **Make swarm control enterprise-friendly**, with a FileZilla-style admin console that’s approachable for operators, but still lethal under the hood.  
- **Preserve lethal Matrix power** while wrapping it in an interface that inspires trust and usability.  

---

## 🛡️ Objectives

### 1. Vault as Source of Truth
- Store deployments, certs, swarm keys, connection info.  
- Never rely on loose certs on the filesystem.  
- Each deployment has its own swarm key and certs.  

### 2. Deployment Records
- Flat `agents[]` (no children, no config).  
- Include:
  - `swarm_key` (for deployment + log decryption).  
  - `encrypted_hash` (fingerprint of sealed directive).  
  - `encrypted_path` (where the `.enc.json` is saved).  
  - `interfaces` (HTTPS, WebSocket, Discord, Telegram, etc. each with host, port, cert, fingerprint).  
- Used by GUI to list sites and launch sessions.  

### 3. Directive Minting
- Start from template directive (hierarchical, structural).  
- Stamp in certs from deployment.  
- Auto-create `.config["security"]` if missing.  
- Embed agent sources (Clown Car) if option set.  
- Add `_hashbang` if option set.  
- Encrypt with swarm key → write `.vault` file.  
- Save swarm key + hash back into deployment record.  

### 4. GUI Control Panel
- **Left panel**: Deployments list (from vault).  
- **Right panel**: Tabs for connected sessions.  
- **Connect** button:
  - Generates `session_id`.  
  - Opens new tab.  
  - Loads interfaces + swarm key from deployment record.  
  - Auto-connects to HTTPS, WS, etc. with correct certs.  
- Each tab includes:
  - Agent Tree viewer.  
  - Log viewer (decrypt logs with swarm key).  
  - Command console (send packets via channels).  
  - Live feeds (WebSocket, Discord, etc.).  

### 5. Security Features
- Auto-lock GUI (screen-saver mode) with vault password re-entry.  
- No manual host/cert input needed.  
- Every swarm siloed cryptographically.  

### 6. Enterprise Feel
- Dashboard landing page:
  - Deployments overview.  
  - Vault health + cert/key stats.  
  - Recent activity feed.  
  - Quick action buttons (New Deployment, Seal Directive, Connect to Site).  
- FileZilla-style “sites list” but with Matrix swarm guts underneath.  

---

## 🧩 Blueprint Summary
- **Vault = brain**: stores deployments with swarm_key, interfaces, and hashes.  
- **Deployment = site record**: flat JSON + metadata, never shipped, GUI reference.  
- **Directive = runtime**: minted, stamped with certs + options, encrypted, uploaded to server.  
- **GUI = operator bridge**: enterprise-style, user-friendly panels, one-click swarm connect.  
- **Security = enforced**: unique keys per swarm, vault password lock, cert silos.  

---

## 🔷 Visual Flow

```mermaid
flowchart LR
    A[Template Directive] --> B[Deployment<br/>(flat agents + certs)]
    B --> C[Mint Runtime Directive<br/>+ embed/hashbang]
    C --> D[Encrypted Directive<br/>(.enc.json + swarm_key)]
    D --> E[Server Swarm Boot<br/>matrixswarm-boot]

    subgraph GUI
    B --> F[Vault<br/>Deployments List]
    F --> G[Control Panel<br/>Sessions / Tabs]
    G --> H[Operator Tools<br/>Agent Tree, Logs, Commands]
    end

