import os
import json
import time
import base64

class IdentityRegistryMixin:

    def dispatch_identity_command(self, target_uid="matrix"):
        """
        Creates a command.dispatch packet that embeds a notify.identity.register packet,
        then routes it to the target_uid (defaults to Matrix).
        """
        pubkey = self.secure_keys.get("pub")
        bootsig = self.tree_node.get("bootsig")

        if not pubkey or not bootsig:
            self.log("[DISPATCH-ID] ❌ Missing pubkey or bootsig.")
            return

        # ▶️ Inner packet: notify.identity.register
        identity_packet = self.get_delivery_packet("standard.identity.register", new=True)
        identity_packet.set_data({
            "universal_id": self.command_line_args["universal_id"],
            "pubkey": self.secure_keys["pub"],
            "bootsig": self.tree_node["bootsig"]
        })

        dispatch_packet = self.get_delivery_packet("standard.command.dispatch", new=True)

        dispatch_packet.set_packet(identity_packet, field_name="command")

        dispatch_packet.set_data({
            "target_universal_id": self.command_line_args["matrix"],
            "origin": self.command_line_args["universal_id"],
            "drop_zone": "incoming",
            "delivery": "file.json_file"
        })


        self.pass_packet(dispatch_packet, "matrix")

    def register_identity(self):
        """
        Uses Swarm packet + delivery agent pipeline to send identity registration.
        """

        pubkey = self.secure_keys.get("pub")
        bootsig = self.tree_node.get("bootsig") or {}

        if not pubkey or not bootsig:
            self.log("[IDENTITY][ERROR] Missing pubkey or bootsig. Cannot register identity.")
            return

        pk = self.get_delivery_packet("notify.identity.register", new=True)
        pk.set_data({
            "universal_id": self.command_line_args.get("universal_id", "unknown"),
            "pubkey": pubkey,
            "bootsig": bootsig
        })

        comms = self.get_nodes_by_role("matrix")

        if not comms:
            self.log("[IDENTITY][ERROR] No Matrix node found.")
            return

        for comm in comms:
            self.pass_packet(pk, comm["universal_id"])
