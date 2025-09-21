import os
import threading
import json
import time

def attach(agent, config):
    webhook_url = config.get("webhook_url")  # Optional for Discord
    levels = config.get("levels", ["critical", "warning"])
    role = config.get("role", "alarm_listener")

    agent.inbox_paths = []

    for level in levels:
        path = os.path.join(agent.path_resolution["comm_path_resolved"], "incoming", role, level)
        os.makedirs(path, exist_ok=True)
        agent.inbox_paths.append(path)

    agent.log(f"[RELAY FACTORY] Watching {len(agent.inbox_paths)} inbox(es) for levels: {levels}")

    def reflex_loop():
        seen = set()
        while agent.running:
            try:
                for inbox in agent.inbox_paths:
                    for fname in os.listdir(inbox):
                        if not fname.endswith(".msg"):
                            continue
                        fpath = os.path.join(inbox, fname)
                        if fpath in seen:
                            continue
                        with open(fpath, "r", encoding="utf-8") as f:
                            payload = json.load(f)

                        msg = payload.get("msg") or payload.get("cause") or str(payload)

                        if webhook_url:
                            _send_discord(agent, webhook_url, msg)
                        else:
                            agent.log("[RELAY FACTORY][ERROR] No delivery method configured.")

                        seen.add(fpath)
                        os.remove(fpath)
                        agent.log(f"[RELAY FACTORY] Dispatched and removed: {fname}")
            except Exception as e:
                agent.log(f"[RELAY FACTORY][ERROR] Loop exception: {e}")
            time.sleep(2)

    threading.Thread(
        target=reflex_loop,
        daemon=True,
        name=f"{agent.command_line_args.get('universal_id', 'unknown')}_reflex"
    ).start()

def _send_discord(agent, webhook_url, msg):
    import requests
    res = requests.post(webhook_url, json={"content": msg})
    if res.status_code == 204:
        agent.log(f"[DISCORD] ✅ Sent: {msg}")
    else:
        agent.log(f"[DISCORD] ❌ Discord error {res.status_code}: {res.text}")
