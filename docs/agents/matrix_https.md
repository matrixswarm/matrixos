#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Matrix HTTPS

The `matrix_httpshttps` agent provides a secure HTTPS API endpoint to interact with the swarm. It runs a Flask web server with TLS and requires mutual (client-side) certificate authentication, making it a secure gateway for GUIs or other external tools.

---
## How it Works

The agent starts a Flask server in a background thread. It defines several API routes:
* `/agents`: Returns a list of all active agents.
* `/matrix/ping`: A simple health check endpoint.
* `/matrix/cmd_get_log`: Retrieves and decrypts the log file for a specified agent.
* `/matrix/cmd_list_tree`: Fetches and returns the master agent tree directive.
* `/matrix` (POST): A generic endpoint that forwards any other command packet directly to the root `matrix` agent's incoming queue for processing.

**Security**: The server is configured to use SSL/TLS and requires connecting clients to present a valid certificate that has been signed by the swarm's root CA, ensuring only trusted clients can issue commands.

---
## Configuration

This agent requires SSL certificates (`server.fullchain.crt`, `server.key`, `rootCA.pem`) to be present in the `/https_certs` directory. These can be generated using the `generate_certs.sh` script. No additional `config` block options are needed.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "matrix-https-1",
            "name": "matrix_https"
        }
    ]
}