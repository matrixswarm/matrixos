# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import ssl
import sys
import os
import smtplib
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
            smtp_server (str): The SMTP server hostname (e.g., "smtp.gmail.com").
            smtp_port (int): The SMTP server port (e.g., 465 for SSL).
            from_address (str): The email address to send from.
            password (str): The password or App Password for the sender's email.
            to_address (str): The email address to send the alert to.
        """
        super().__init__()

        try:
            config = self.tree_node.get("config", {}).get("email",{})
            self.smtp_server = config.get("smtp_server")  # matches your directive
            self.smtp_port = config.get("smtp_port")
            self.from_address = config.get("smtp_username")  # sender's email
            self.password = config.get("smtp_password")
            self.to_address = config.get("smtp_to")  # default recipient
            self.encryption = (config.get("smtp_encryption") or "SSL").upper().strip()
        except Exception as e:
            self.log(error=e, level="ERROR")


    def cmd_send_email(self, content: dict, packet: dict, identity: IdentityObject = None):
        """Entry point when swarm sends a 'send email' command."""
        try:
            smtp_server = content.get("smtp_server") or self.smtp_server
            raw_port = content.get("smtp_port") or self.smtp_port or 465
            try:
                smtp_port = int(raw_port)
            except (ValueError, TypeError):
                smtp_port = 465

            from_addr = content.get("from") or self.from_address
            to_addr = content.get("to") or self.to_address
            subject = content.get("subject").strip()
            password = content.get("password") or self.password
            encryption = (content.get("smtp_encryption") or self.encryption).upper().strip()
            body = content.get("body", "")

            if not all([smtp_server, from_addr, password, to_addr]):
                self.log("[EMAIL] ❌ Missing required fields.", level="ERROR")
                return

            self._send_mail(
                smtp_server=smtp_server,
                smtp_port=smtp_port,
                encryption=encryption,
                from_addr=from_addr,
                to_addr=to_addr,
                password=password,
                subject=subject,
                body=body,
            )
        except Exception as e:
            self.log("[EMAIL] ❌ Failed to dispatch email", error=e)

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
        if not all([self.smtp_server, self.smtp_port, self.from_address, self.password, self.to_address]):
            self.log("SMTP configuration is incomplete. Cannot send email.", level="ERROR")
            return

        try:
            # The 'cause' of the alert makes a great email subject
            subject = content.get("cause", "MatrixSwarm Alert")

            # Prioritize the pre-formatted message, but fall back to the raw message
            body = content.get("formatted_msg") or content.get("msg") or "No message content provided."

            self._send_mail(
                smtp_server=self.smtp_server,
                smtp_port=self.smtp_port or 465,
                encryption="SSL",
                from_addr=self.from_address,
                to_addr=self.to_address,
                password=self.password,
                subject=subject,
                body=body,
            )

        except Exception as e:
            self.log("Failed to process alert for email sending.", error=e, block="main_try")

    def _send_mail(
            self,
            smtp_server: str,
            smtp_port: int,
            encryption: str,
            from_addr: str,
            to_addr: str,
            password: str,
            subject: str,
            body: str,
    ):
        """Handles all SMTP/STARTTLS/PLAIN send operations."""
        try:
            msg = EmailMessage()
            msg["From"] = from_addr
            msg["To"] = to_addr
            msg["Subject"] = subject
            msg.set_content(body)

            context = ssl.create_default_context()

            if encryption == "SSL":
                self.log(f"[EMAIL][CONNECT] Using SSL on {smtp_server}:{smtp_port}")
                with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context, timeout=10) as server:
                    server.login(from_addr, password)
                    server.send_message(msg)
                    self.log("[EMAIL][SEND] ✅ Sent via SSL.")

            elif encryption == "STARTTLS":
                self.log(f"[EMAIL][CONNECT] Using STARTTLS on {smtp_server}:{smtp_port}")
                with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(from_addr, password)
                    server.send_message(msg)
                    self.log("[EMAIL][SEND] ✅ Sent via STARTTLS.")

            else:
                self.log(f"[EMAIL][CONNECT] Using plain SMTP on {smtp_server}:{smtp_port}")
                with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                    server.login(from_addr, password)
                    server.send_message(msg)
                    self.log("[EMAIL][SEND] ✅ Sent without encryption.")
        except Exception as e:
            self.log("[EMAIL][ERROR] Send failure", error=e)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
