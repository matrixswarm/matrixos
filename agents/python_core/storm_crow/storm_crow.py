# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys
import os
import time
import requests
import re
import unicodedata

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))


from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):

    def __init__(self):
        super().__init__()
        self.name = "StormCrow"

        self.interval = 900
        self._initialized_from_tree = False
        self._private_config = self.tree_node.get("config", {})
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=self.interval*2, emit_to_file_interval=10)

    def cmd_update_agent_config(self):

        try:

            self._initialized_from_tree = True
            # Support ZIP code override
            self.zipcode = self._private_config.get("zip_code", 20007)


            self.log(f"🌪 [HOWDY] We've moved. StormCrow now watches over ZIP: {self.zipcode}")

            if self.zipcode:
                self.lat, self.lon = self.resolve_zip_to_latlon(self.zipcode)
            else:
                self.lat = self._private_config.get("weather_latitude", "38.9152945")
                self.lon = self._private_config.get("weather_longitude", "-77.0827632")

            endpoint= self._private_config.get("alert_endpoint", "https://api.weather.gov/alerts/active?point")

            self.alert_endpoint = f"{endpoint}={self.lat},{self.lon}"
            self.last_alert_ids = set()

        except Exception as e:
            self.log("Failed to initialize config", error=e)

    def pre_boot(self):
        self.log("Pre-boot weather alert initialization complete.")

    def post_boot(self):
        self.log("Agent is live and scanning the sky.")
        self.log("╔════════════════════════════════════════════════╗")
        self.log("║ 🤡 CAPTAIN HOWDY IS WATCHING THE WEATHER       ║")
        self.log("║ 🛰️  StormCrow is deployed. Sky tracking is HOT ║")
        self.log("║ 🧠 Reflexes armed. Sirens ready.               ║")
        self.log("╚════════════════════════════════════════════════╝")

    def worker(self, config: dict = None, identity:IdentityObject = None):
        try:

            self._emit_beacon()
            if isinstance(config, dict) and bool(config.get("push_live_config", 0)):
                self.log(f"[STORM_CROW] 🔁 Live config update detected: {config}")
                self.log(f"config loaded: {config}")
                self._private_config = config
                self._initialized_from_tree = False

            if self.is_agent_tree_loaded and not self._initialized_from_tree:
                self.cmd_update_agent_config()

            alerts= {}
            if self.is_agent_tree_loaded:
                alerts = self.fetch_alerts()

            if self.is_agent_tree_loaded and (not alerts):
                self.log("[STORMCROW] ✅ NWS returned no alerts.")
            for item in alerts:
                alert_id = item.get("id")
                props = item.get("properties", {})
                event = props.get("event")
                severity = props.get("severity")
                area = props.get("areaDesc")
                headline = props.get("headline")
                issued = props.get("sent")
                description = self.sanitize_alert_text(props.get("description", ""), 1500)
                instruction = self.sanitize_alert_text(props.get("instruction", ""), 1000)
                headline = self.sanitize_alert_text(props.get("headline", ""), 300)
                area = self.sanitize_alert_text(props.get("areaDesc", ""), 300)
                event = self.sanitize_alert_text(props.get("event", ""), 100)
                severity = self.sanitize_alert_text(props.get("severity", ""), 50)

                msg = (
                    f"{event} | {severity} | {area}\n"
                    f"📰 {headline}\n"
                )
                if description:
                    msg += f"📖 {description}\n"
                if instruction:
                    msg += f"📢 {instruction}\n"
                msg += f"📅 Issued: {issued}"

                if alert_id not in self.last_alert_ids:
                    self.last_alert_ids.add(alert_id)
                    self.log(f"[STORMCROW] ⚠️ NEW ALERT: {event} | {severity} | {area}")
                    self.log(f"[STORMCROW] 📰 {headline} (Issued: {issued})")
                    # Send FULL sanitized alert
                    self.alert_operator(event, msg)

        except Exception as e:
            self.log(error=e, block="main_try")
        if self.is_agent_tree_loaded:
            interruptible_sleep(self, self.interval)
        else:
            interruptible_sleep(self, 20)

    def fetch_alerts(self):
        try:
            resp = requests.get(self.alert_endpoint, headers={"User-Agent": "StormCrow-Agent"}, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            features = data.get("features")
            if not isinstance(features, list):
                self.log(f"Unexpected response shape: {data}")
                return []
            return features
        except requests.exceptions.RequestException as e:
            self.log(error=e, block="main_try")

        except Exception as e:
            self.log(error=e, block="main_try")

        return []

    def alert_operator(self, title, message):
        pk1 = self.get_delivery_packet("standard.command.packet")
        pk1.set_data({"handler": "cmd_send_alert_msg"})

        try:
            server_ip = requests.get("https://api.ipify.org").text.strip()
        except Exception:
            server_ip = "Unknown"

        pk2 = self.get_delivery_packet("notify.alert.general")
        pk2.set_data({
            "server_ip": server_ip,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "universal_id": self.command_line_args.get("universal_id", "unknown"),
            "level": "warning",
            "msg": message,
            "formatted_msg": f"🌩 {title}\n{message}",
            "cause": "StormCrow Severe Weather Alert",
            "origin": self.command_line_args.get("universal_id", "unknown")
        })

        pk1.set_packet(pk2, "content")

        endpoints = self.get_nodes_by_role(self._private_config.get("alert_to_role", "hive.alert"))
        if not endpoints:
            self.log("No alert-compatible agents found.")
            return

        for ep in endpoints:
            pk1.set_payload_item("handler", ep.get_handler())
            self.pass_packet(pk1, ep.get_universal_id())

    def sanitize_alert_text(self, text, max_len=1200):
        if not isinstance(text, str):
            return ""

        # Normalize unicode (kills RTL tricks)
        text = unicodedata.normalize("NFKC", text)

        # Remove control characters
        text = re.sub(r"[\x00-\x1F\x7F]", "", text)

        # Collapse excessive whitespace
        text = re.sub(r"\s{3,}", "  ", text)

        # Hard length cap
        return text.strip()[:max_len]

    def resolve_zip_to_latlon(self, zip_code):
        try:
            url = f"http://api.zippopotam.us/us/{zip_code}"
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            data = resp.json()
            coords = data["places"][0]
            lat = coords["latitude"]
            lon = coords["longitude"]
            self.log(f"[STORMCROW] ZIP {zip_code} resolved to {lat},{lon}")
            return lat, lon
        except Exception as e:
            self.log(f"Could not resolve ZIP {zip_code}", error=e, block="main_try")
            return self._private_config.get("weather_latitude", "38.9152945"), self._private_config.get("weather_longitude", "-77.0827632")

    def worker_post(self):
        self.log("[STORMCROW] Worker loop scanning for severe weather alerts...")

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
