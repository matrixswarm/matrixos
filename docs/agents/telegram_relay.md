#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Telegram Relay

The `telegram_relay` agent acts as a gateway to send swarm alerts and messages to a specific Telegram chat via a Telegram Bot.

---
## How it Works
This agent primarily works by listening for packets with the `cmd_send_alert_msg` handler. When it receives such a packet, it extracts the message content, formats it, and sends it to the configured Telegram `chat_id` using the provided `bot_token` via the Telegram Bot API.

---
## Configuration
* **`bot_token`**: The API token for your Telegram Bot, obtained from the BotFather.
* **`chat_id`**: The unique ID of the Telegram chat, channel, or user that should receive the messages.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "telegram-bot-1",
            "name": "telegram_relay",
            "config": {
                "bot_token": "YOUR_TELEGRAM_BOT_TOKEN_HERE",
                "chat_id": "YOUR_CHAT_ID_HERE"
            }
        }
    ]
}