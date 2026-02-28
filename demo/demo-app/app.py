import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

API_TOKEN = "hardcoded-demo-token-1234567890"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.getoutput(f"ping -c 1 {host}")


@app.route("/debug")
def debug():
    return {"status": "ok", "db_password": os.getenv("DB_PASSWORD", "SuperSecretPassword123!")}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
