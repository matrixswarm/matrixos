#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Storm Crow

The `storm_crow` agent connects to the National Weather Service (NWS) API to monitor for severe weather alerts for a specific geographic location and broadcast them to the swarm.

---
## How it Works
The agent first resolves a ZIP code into latitude and longitude coordinates using a public API. It then periodically polls the NWS API for active alerts at that location. If it finds a new, previously unseen alert, it formats the information into a message and sends it as an alert packet to any agent with the `hive.alert.send_alert_msg` role.

---
## Configuration
* **`zip-code`**: The US ZIP code to monitor. This can also be set via the `WEATHER_ZIPCODE` environment variable. If not provided, it defaults to latitude and longitude environment variables.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "storm-crow-1",
            "name": "storm_crow",
            "config": {
                "zip-code": "90210"
            }
        },
        { "universal_id": "discord-relay-1", "name": "discord_relay" }
    ]
}