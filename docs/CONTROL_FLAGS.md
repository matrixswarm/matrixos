# 🛡️ Hive Control Flags

The filesystem itself is our control bus.  
Flags are just files in each agent’s `comm/<universal_id>/broadcast/` dir.  
Presence + freshness of a flag drives agent behavior.  

---

## Standard Flags

### 🔌 connected.flag
- Created when relay has ≥1 downstream clients.  
- Removed when last client disconnects.  
- mtime refreshed every 10s while alive.  
- **Matrix rule:** only broadcast if `connected.flag` exists and mtime < 30s.

---

### ⏸️ pause.flag
- Presence means "don’t send heavy payloads to this agent".  
- Absence means normal traffic.  
- Useful for rate-limiting or maintenance windows.

---

### 🚨 alert.flag
- Dropped by sentinels (Tripwire, Gatekeeper, GhostWire) when they detect an incident.  
- Matrix or Phoenix sees it → raises inbound `hive.alert`.  
- Removed after alert is processed.

---

### 🎭 role.<name>.flag
- Dynamic role assignment.  
- Example: `role.tree.feed.flag` means this agent wants agent_tree updates.  
- Matrix can scan broadcast/ for `role.*.flag` to build live role maps.

---

### 🔒 lock.flag
- Used to serialize access to a shared resource.  
- Presence = someone is working.  
- Others wait until removed.  
- Atomic `open/remove` is enough (or `os.O_EXCL`).

---

### 🕑 cron.flag / mission.complete
- Used by `spawn_manager` to schedule cron jobs.  
- `mtime` = last run time.  
- If `(now - mtime) >= interval` → job triggers, file removed.  
- Agent recreates it after mission success.

---

## Usage Notes
- Always check `os.path.exists()` first.  
- Always check `time.time() - os.path.getmtime(flag)` for freshness.  
- Thresholds should be conservative (e.g. 30s for connected).  
- If a process dies, its broadcast folder is removed → all flags disappear automatically.
