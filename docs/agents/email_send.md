#### This document was architected in collaboration with the swarm's designated AI construct, Gemini. 
#### Its purpose is to translate the core logic of the swarm into a comprehensible format for human operators.

# Agent Reference: Email Send

The `email_send` agent acts as an SMTP gateway for the swarm. It watches a directory for formatted JSON files and sends them as emails.

---
## How it Works

The agent monitors its `/comm/{universal_id}/payload` directory. When a `.json` file appears in this directory, the agent reads it, assuming it contains `to`, `subject`, and `body` fields. It then connects to a configured SMTP server using the provided credentials and sends the email. After successfully sending, it deletes the JSON file.

---
## Configuration

Credentials can be provided via the directive's `config` block or through environment variables (e.g., in a `.env` file).

* **`smtp_host`**: The hostname of the SMTP server.
* **`smtp_port`**: The port for the SMTP server.
* **`email`**: The sending email address (for login).
* **`password`** The password for the email account.

### Example Directive
```python
matrix_directive = {
    "universal_id": "matrix",
    "name": "matrix",
    "children": [
        {
            "universal_id": "smtp-gateway-1",
            "name": "email_send",
            "config": {
                "smtp_host": "smtp.gmail.com",
                "smtp_port": 587,
                "email": "your_email@gmail.com",
                "password": "your_app_password"
            }
        }
    ]
}
```
To send an email, another agent would drop a file like email.json into /comm/smtp-gateway-1/payload/ with the content: { "to": "recipient@example.com", "subject": "Swarm Alert", "body": "This is a message from the swarm." }

