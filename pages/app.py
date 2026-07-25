"""
app.py

Minimal Flask API wrapping the sandboxed C tracer. One endpoint:

    POST /run
    body: {"code": "<C source as a string>"}
    response: same shape sandbox_run.run_sandboxed() returns, e.g.
              {"ok": true, "steps": [...], "truncated": false}
           or {"ok": false, "error": "compile_error", "detail": "..."}

Run with: python3 app.py
Defaults to http://0.0.0.0:5001

Note on concurrency: each request currently runs its own sandboxed
subprocess synchronously — fine for a personal/demo deployment, but a
public-facing version needs a request queue and a cap on concurrent
sandboxed runs (see README.md) so one slow/malicious request can't starve
everyone else.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sandbox_run
import traceback

app = Flask(__name__)
CORS(app)  # allow the static frontend (different origin) to call this

MAX_SOURCE_LENGTH = 20_000  # characters — plenty for a student program


@app.route("/run", methods=["POST"])
def run_code():
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")

    if not isinstance(code, str) or not code.strip():
        return jsonify({"ok": False, "error": "bad_request", "detail": "No code provided."}), 400

    if len(code) > MAX_SOURCE_LENGTH:
        return jsonify({
            "ok": False, "error": "bad_request",
            "detail": f"Source too long ({len(code)} chars, max {MAX_SOURCE_LENGTH})."
        }), 400

    # Debugging aid: catch EVERYTHING here and return the full traceback,
    # rather than letting an uncaught exception fall through to Flask's
    # generic error handling (which would hide exactly where it happened).
    try:
        result = sandbox_run.run_sandboxed(code)
        return jsonify(result)
    except Exception as e:
        tb = traceback.format_exc()
        print("\n=== UNCAUGHT EXCEPTION IN /run ===")
        print(tb)
        print("=== END TRACEBACK ===\n")
        return jsonify({
            "ok": False,
            "error": "unhandled_exception",
            "detail": f"{type(e).__name__}: {e}",
            "traceback": tb,
        }), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)