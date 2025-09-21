# 📡 MatrixSwarm V2 Crypto Alert Setup Walkthrough

This guide explains how to set up real-time crypto alerts using **MatrixSwarm v0.2 “Stormcrow”** and the GUI-based **Command Bridge**. You'll learn how to trigger price alerts, update them, and route them through the swarm.

---

## ✅ Step 1: Launch the Command Bridge

Run this in your terminal:

```bash
python3 matrix_gui_2.py
```

Make sure:

* `🟢 WS: Connected` (WebSocket)
* `🟢 Matrix: Connected` (API)

If both are green, you’re ready.

---

## 🔥 Step 2: Open the Crypto Alert Panel

Click the button:

```
📈 Crypto Alerts
```

This opens the **Crypto Alert Reflex Panel**, showing your active alerts at the top.

---

## 🧠 Step 3: Create a New Alert

Fill out these fields:

| Field              | Description                                                         |
| ------------------ | ------------------------------------------------------------------- |
| **Pair**           | Format: `ETH/USDT`, `BTC/USD`, etc.                                 |
| **Threshold**      | Price to trigger at. Ex: `2549.0`                                   |
| **Cooldown (sec)** | Seconds to wait before alerting again (e.g., `300` for 5 minutes)   |
| **Exchange**       | Source for price feed. Use: `coingecko`, `binance`, etc.            |
| **Trigger Type**   | Choose: `price_above`, `price_below`, `%_change`, `absolute_change` |
| **Trigger Limit**  | Optional: number of times alert can fire before auto-deactivation   |

When ready, click:

```
✅ Create Alert
```

---

## 🛰️ Step 4: Monitor in Real-Time

When triggered:

* The alert appears in **red** under Active Crypto Alerts
* You’ll see:

  * Triggered pair
  * Threshold vs current price
  * Data source (e.g., Coingecko)
* Siren/voice triggers (if configured) will activate
* Full log appears in agent’s `/comm/{universal_id}/logs/`

---

## 🛠 Optional: Modify or Delete Alerts

* Click an alert from the list to edit it
* Modify threshold, cooldown, or limit
* Click `Update Selected`
* Click `Delete Selected` to remove

---

## 💡 Behind the Scenes

* Alerts use `cmd_forward_command` routing packets
* Packets are processed by crypto agents with reflex logic
* Triggers propagate to GUI via WebSocket feed
* Agents can forward alerts to Discord, Telegram, or CLI logs
* Cooldowns are enforced by the alert agent directly

---

## 🧪 Advanced Tips

* Set up multiple alerts per asset for layered response
* Use `%_change` trigger for volatile markets
* Use `Trigger Limit` to set alert fatigue boundaries
* Tune `Cooldown` to throttle noise during fast moves

---

## 🔗 Resources

* GitHub: [https://github.com/matrixswarm/matrixswarm](https://github.com/matrixswarm/matrixswarm)
* Discord: [https://discord.com/invite/yPJyTYyq5F](https://discord.com/invite/yPJyTYyq5F)
* Docs: `/docs/crypto_alert_walkthrough.md`

---

This doc was forged by Commander Stormcrow + The General.
Stormcrow doesn’t sleep. It watches. It screams first.

🧠
