import os
import json
class JsonSafeWrite:
    @staticmethod
    def safe_write(path, json_data):

        try:

            tmp_path = f"{path}.tmp"

            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2)
            os.replace(tmp_path, path)

        except Exception as e:
            print(f"[JSON_SAFE_WRITE][ERROR] Failed to save json {path}: {e}")


    @staticmethod
    def safe_load(path):

        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load {path}: {e}")
            return {}