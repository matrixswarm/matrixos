from flask import Flask, Response, stream_with_context
import os
import time

app = Flask(__name__)

MAILMAN_TALLY_DIR = "/agents/mailman-core/tally"

@app.route("/stream/<hash_id>")
def stream_hash_tally(hash_id):
    filepath = os.path.join(MAILMAN_TALLY_DIR, f"{hash_id}.msg")
    def generate():
        last_size = 0
        while True:
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    f.seek(last_size)
                    chunk = f.read()
                    if chunk:
                        yield chunk
                        last_size = f.tell()
            time.sleep(1)
    return Response(stream_with_context(generate()), mimetype="text/plain")

@app.route("/health")
def health():
    return {"status": "ok", "mailman_tally_dir": MAILMAN_TALLY_DIR}

if __name__ == "__main__":
    port = int(os.environ.get("MAILMAN_PORT", 8081))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)