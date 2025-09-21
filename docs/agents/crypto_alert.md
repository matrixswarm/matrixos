#### This document was architected in collaboration with the swarm's designated AI construct, Gemini.
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Crypto Alert

The `crypto_alert` agent is a highly flexible cryptocurrency market monitor. It connects to various exchanges via a dynamic factory system to track asset prices and trigger alerts based on user-defined conditions. This allows operators to create real-time notifications for significant market movements, price thresholds, or specific asset conversion rates.

**Tags:** `crypto`, `trading`, `alerting`, `market-monitor`, `dynamic-loading`, `api-integration`, `finance`, `real-time`

---
## How it Works

The agent operates in a configurable loop with the following logic:

1.  **Dynamic Exchange Loading**: On initialization, the agent reads the `exchange` from its configuration and dynamically loads the corresponding handler module from the `crypto_alert.factory.cryptocurrency.exchange` directory. This allows for easy expansion to new exchanges without altering the core agent logic.
2.  **Polling**: The agent periodically fetches price data for a specified trading pair from the loaded exchange. The polling frequency is configurable via `poll_interval`.
3.  **Trigger Evaluation**: It evaluates the fetched price data against a specified `trigger_type`. The agent supports several conditions, including percentage change, absolute price change, crossing a price threshold, and asset-to-asset conversion rates.
4.  **Alerting**: If a trigger condition is met, the agent constructs and dispatches an alert packet to other agents in the swarm that have the configured `alert_role` and are listening for the `alert_handler`.
5.  **Self-Deactivation**: The agent can be configured to stop after a certain number of trigger events to prevent alert flooding, after which it will mark itself as inactive.

---
## Configuration

Add the `crypto_alert` agent to your directive and customize its behavior in the `config` block.

**Core Options:**

* **`exchange`** (Default: `"coingecko"`): The name of the exchange to use. This must correspond to a module name in the exchange factory.
* **`poll_interval`** (Default: `20`): How often, in seconds, to check the asset's price.
* **`pair`** (Default: `"BTC/USDT"`): The trading pair to monitor (e.g., "ETH/USDT", "SOL/USDT").
* **`active`** (Default: `True`): Set to `False` to disable the agent's monitoring loop.

**Triggering Options:**

* **`trigger_type`** (Default: `"price_change_above"`): The core condition to check for. See the "Trigger Types" section below for all options.
* **`change_percent`** (Default: `1.5`): The percentage change required to trigger a `price_change` alert.
* **`change_absolute`** (Default: `1000`): The absolute price change (in quote currency) required to trigger a `price_delta` alert.
* **`threshold`** (Default: `0`): The price level to check against for `price` or `asset_conversion` alerts.
* **`from_asset`** / **`to_asset`** / **`from_amount`**: Used only with the `asset_conversion` trigger to check the value of one asset in terms of another.

**Alerting & Limits:**

* **`alert_handler`** (Required): The handler that a receiving agent (e.g., `discord_relay`) should use to process the alert.
* **`alert_role`** (Required): The role of the agent(s) that should receive the alert packet.
* **`limit_mode`** (Default: `"forever"`): Determines if the agent should deactivate. Set to `"limited"` to use the activation limit.
* **`activation_limit`** (Default: `1`): If `limit_mode` is `"limited"`, the agent will deactivate after this many alerts.

---
## Trigger Types

The `trigger_type` option defines the agent's monitoring logic.

* **`price_change_above`**: Triggers when the price increases by more than `change_percent` since the last check.
* **`price_change_below`**: Triggers when the price decreases by more than `change_percent` since the last check.
* **`price_delta_above`**: Triggers when the price increases by more than `change_absolute`.
* **`price_delta_below`**: Triggers when the price decreases by more than `change_absolute`.
* **`price_above`**: Triggers if the current price is greater than `threshold`.
* **`price_below`**: Triggers if the current price is less than `threshold`.
* **`asset_conversion`**: Triggers if `from_amount` of `from_asset` is worth more than `threshold` of `to_asset`.

---
### Example Directive

This directive deploys a `crypto_alert` to monitor for a 5% price drop in Ethereum on Binance and sends an alert to a Discord relay agent. The monitor will deactivate after the first alert.

```python
# /boot_directives/crypto_monitoring.py

matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        # An agent to receive and forward the alerts
        {
            "universal_id": "discord-relay-1",
            "name": "discord_relay",
            "roles": ["alert_router"],
            # ... other config for discord relay
        },
        # The crypto alert agent itself
        {
            "universal_id": "eth-dip-monitor-1",
            "name": "crypto_alert",
            "config": {
                "exchange": "binance",
                "poll_interval": 60,
                "pair": "ETH/USDT",
                "trigger_type": "price_change_below",
                "change_percent": 5.0,
                "limit_mode": "limited",
                "activation_limit": 1,
                "alert_handler": "cmd_post_webhook",
                "alert_role": "alert_router"
            }
        }
    ]
}
