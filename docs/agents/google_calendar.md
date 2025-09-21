#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Google Calendar

The `google_calendar` agent connects to the Google Calendar API, periodically fetches upcoming events, and broadcasts them as messages to other agents in the swarm.

---
## How it Works

The agent uses a Google Cloud service account `credentials.json` file to authenticate with the Google Calendar API. In its `worker()` loop, it checks for any calendar events occurring between now and a configurable number of minutes in the future. For each upcoming event found, it creates a JSON message and drops it into the `/incoming` directory of every agent specified in its `broadcast_to` configuration.

---
## Configuration

* **`calendar_id`** (Default: `"primary"`): The ID of the Google Calendar to watch.
* **`interval`** (Default: `300`): How often, in seconds, to check for new events.
* **`watch_ahead_minutes`** (Default: `15`): How many minutes into the future to look for events.
* **`broadcast_to`** (Default: `[]`): A list of `universal_id`s of agents who should receive the event notifications.
* **Credentials**: The agent requires a `credentials.json` file from a Google Cloud service account with the "Google Calendar API" enabled. By default, it looks for this file at the root of the project, or at the path specified by the `SWARM_CRED_PATH` environment variable.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "calendar-scout-1",
            "name": "google_calendar",
            "config": {
                "calendar_id": "your_email@gmail.com",
                "watch_ahead_minutes": 60,
                "broadcast_to": ["discord-relay-1"]
            }
        },
        { "universal_id": "discord-relay-1", "name": "discord_relay" }
    ]
}

