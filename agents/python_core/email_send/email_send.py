# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Gemini, code enhancements and Docstrings
import ssl
import sys
import os
import smtplib
import socket
from email.message import EmailMessage

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    """
    An agent that relays swarm alerts to a specified email address.

    This agent acts as a standard alert handler, listening for commands sent
    to the `cmd_send_alert_msg` handler. It is designed to work reliably
    with modern email providers like Gmail and Outlook by using a secure
    SSL/TLS connection from the outset.
    """
    def __init__(self):
        """
        Initializes the agent and loads its SMTP configuration.

        This method loads all necessary SMTP credentials and server details
        from the agent's directive configuration block.

        Attributes:
            smtp_host (str): The SMTP server hostname (e.g., "smtp.gmail.com").
            smtp_port (int): The SMTP server port (e.g., 465 for SSL).
            from_address (str): The email address to send from.
            password (str): The password or App Password for the sender's email.
            to_address (str): The email address to send the alert to.
        """
        super().__init__()

        config = self.tree_node.get("config", {})
        self.smtp_host = config.get("smtp_host")
        self.smtp_port = config.get("smtp_port")
        self.from_address = config.get("from_address")
        self.password = config.get("password")
        self.to_address = config.get("to_address")

    def cmd_send_email(self, content: dict, packet: dict, identity: IdentityObject = None):
        try:


            smtp_host = content.get("smtp_host")
            smtp_port = int(content.get("smtp_port", 465))
            from_addr = content.get("from")
            to_addr = content.get("to")
            password = content.get("password")
            subject = content.get("subject", "(no subject)")
            body = content.get("body", "")

            if not all([smtp_host, from_addr, password, to_addr]):
                self.log("[EMAIL] ❌ Missing required fields.", level="ERROR")
                return

            msg = EmailMessage()
            msg["From"] = from_addr
            msg["To"] = to_addr
            msg["Subject"] = subject
            msg.set_content(body)
            context = ssl.create_default_context()
            try:
                self.log(f"[EMAIL][CONNECT] Attempting SSL connect to {smtp_host}:{smtp_port}")
                with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=10) as server:
                    self.log("[EMAIL][CONNECT] Connected, starting login…")
                    server.login(from_addr, password)
                    self.log("[EMAIL][SEND] Logged in, sending message…")
                    server.send_message(msg)
                    self.log("[EMAIL][SEND] ✅ Message dispatched.")
            except (socket.timeout, smtplib.SMTPConnectError) as e:
                self.log(f"[EMAIL][TIMEOUT] Connection timed out: {e}", level="ERROR")
            except Exception as e:
                import traceback
                self.log(f"[EMAIL][FAIL] Unexpected error in SMTP_SSL: {e}", error=e, level="ERROR")
                self.logger.log(traceback.format_exc(), level="DEBUG")

        except Exception as e:
            self.log("[EMAIL] ❌ Failed to send email", error=e)

    def cmd_send_alert_msg(self, content: dict, packet, identity: IdentityObject = None):
        """
        The main command handler for receiving and processing swarm alerts.

        This method is triggered when another agent sends a packet to it. It
        extracts the relevant information from the alert, formats it for an
        email, and calls the internal `_send_email` method to dispatch it.

        Args:
            content (dict): The alert payload from the sending agent.
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """
        if not all([self.smtp_host, self.smtp_port, self.from_address, self.password, self.to_address]):
            self.log("SMTP configuration is incomplete. Cannot send email.", level="ERROR")
            return

        try:
            # The 'cause' of the alert makes a great email subject
            subject = content.get("cause", "MatrixSwarm Alert")

            # Prioritize the pre-formatted message, but fall back to the raw message
            body = content.get("formatted_msg") or content.get("msg") or "No message content provided."

            self._send_email(subject, body)

        except Exception as e:
            self.log("Failed to process alert for email sending.", error=e, block="main_try")

    def _send_email(self, subject: str, body: str):
        """
        Send email securely with full TLS validation and optional in-memory PEM loading.
        """
        try:
            msg = EmailMessage()
            msg["From"] = self.from_address
            msg["To"] = self.to_address
            msg["Subject"] = subject
            msg.set_content(body)

            # Build strict TLS context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, context=context) as server:
                server.login(self.from_address, self.password)
                server.send_message(msg)
                self.log(f"[EMAIL][TLS] ✅ Secure email sent to {self.to_address}")

        except smtplib.SMTPAuthenticationError:
            self.log("[EMAIL][TLS][AUTH] ❌ Authentication failed (check credentials).", level="ERROR")
        except ssl.SSLError as e:
            self.log(f"[EMAIL][TLS][CERT] SSL handshake failed: {e}", level="ERROR")
        except Exception as e:
            self.log("[EMAIL][TLS][ERROR] Unexpected send failure.", error=e, block="_send_email")

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
