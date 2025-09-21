import threading
import os
import json
import time
import requests

def format_message(data):
    lines = ["📡 Telegram Swarm Alert"]
    keys = ["universal_id", "timestamp", "level", "cause"]
    for key in keys:
        if key in data:
            lines.append(f"{key}: {data[key]}")
    for key, value in data.items():
        if key not in keys:
            lines.append(f"{key}: {value}")
    return "\n".join(lines)

def attach(agent, config):
    token = config.get("bot_token",None)
    chat_id = config.get("chat_id",0)
    levels = config.get("levels", ["critical", "warning"])
    role = config.get("role", "alarm_listener")

    if not token or not str(chat_id).isdigit():
        agent.log(f"[TELEGRAM FACTORY][ABORT] Invalid bot_token or chat_id → token: {token}, chat_id: {chat_id}")
        return

    agent.inbox_paths = []

    for level in levels:
        path = os.path.join(agent.path_resolution["comm_path_resolved"], "incoming", role, level)
        os.makedirs(path, exist_ok=True)
        agent.inbox_paths.append(path)

    agent.log(f"[TELEGRAM FACTORY] Watching {len(agent.inbox_paths)} inbox(es) for levels: {levels}")


    def reflex_loop():
        seen = set()
        while agent.running:
            try:
                for inbox in agent.inbox_paths:
                    if not os.path.exists(inbox):
                        continue
                    for fname in os.listdir(inbox):
                        agent.log(f"[DEBUG] Found candidate file: {fname}")
                        if not fname.endswith(".msg"):
                            continue
                        fpath = os.path.join(inbox, fname)
                        if fpath in seen:
                            agent.log(f"[DEBUG] Skipping already seen: {fpath}")
                            continue
                        with open(fpath, "r", encoding="utf-8") as f:
                            payload = json.load(f)
                        msg = format_message(payload)

                        url = f"https://api.telegram.org/bot{token}/sendMessage"
                        res = requests.post(url, json={"chat_id": chat_id, "text": msg})

                        if res.status_code == 200:
                            agent.log(f"[TELEGRAM FACTORY] ✅ Alert sent:\n{msg}")
                        else:
                            agent.log(f"[TELEGRAM FACTORY] ❌ Telegram API error {res.status_code}: {res.text}")

                        seen.add(fpath)
                        os.remove(fpath)
                        agent.log(f"[TELEGRAM FACTORY] Dispatched and removed: {fname}")
            except Exception as e:
                agent.log(f"[TELEGRAM FACTORY][ERROR] {e}")
            time.sleep(2)

    threading.Thread(
        target=reflex_loop,
        daemon=True,
        name=f"{agent.command_line_args.get('universal_id', 'unknown')}_reflex"
    ).start()
