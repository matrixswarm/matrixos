#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Matrix WebSocket

The `matrix_websocket` agent provides a secure, real-time, bidirectional communication channel for the swarm. It's primarily used by GUIs and other external tools to receive live updates and send commands without relying on traditional HTTP polling.

---
## How it Works

The agent starts a WebSocket server using the `websockets` library on a specified port, secured with TLS certificates. It maintains a set of connected clients. Other agents can send packets to the `matrix_websocket` agent with a handler like `cmd_broadcast` or `cmd_send_alert_msg`. The WebSocket agent then serializes this packet to JSON and broadcasts it instantly to all connected clients.

---
## Configuration

* **`port`** (Default: `8765`): The port on which the WebSocket server will listen.
* **Certificates**: Requires `server.crt` and `server.key` to be present in the `/socket_certs` directory. These can be generated using the `generate_certs.sh` script.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "matrix-websocket-1",
            "name": "matrix_websocket",
            "config": {
                "port": 8765
            }
        }
    ]
}
