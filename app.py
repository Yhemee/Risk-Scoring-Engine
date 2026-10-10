"""Flask wrapper around the risk engine: access decisions, audit log, TOTP step-up.

Endpoints
  POST /access      JSON: user_id, user_role, device_posture, location, access_time (ISO), failed_attempts
  POST /mfa/verify  JSON: user_id, code
  GET  /audit       last 50 audit records (research/demo only)

Synthetic data only. Never point this at real users or credentials.
"""
import json
import sqlite3
from datetime import datetime, timezone

import pyotp
from flask import Flask, jsonify, request

from risk_engine import AccessRequest, evaluate, STEP_UP

DB_PATH = "audit.db"
app = Flask(__name__)
_totp_secrets = {}  # synthetic per-user TOTP secrets (in memory, demo only)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS audit (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ts TEXT, event TEXT, user_id TEXT,
               inputs TEXT, score INTEGER, decision TEXT, reasons TEXT)"""
    )
    return conn


def log(event, user_id, inputs, score=None, decision=None, reasons=None):
    with db() as conn:
        conn.execute(
            "INSERT INTO audit (ts, event, user_id, inputs, score, decision, reasons) VALUES (?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), event, user_id,
             json.dumps(inputs), score, decision, json.dumps(reasons or [])),
        )


@app.post("/access")
def access():
    data = request.get_json(silent=True) or {}
    try:
        user_id = str(data["user_id"])
        req = AccessRequest(
            user_role=data["user_role"],
            device_posture=data["device_posture"],
            location=data["location"],
            access_time=datetime.fromisoformat(data["access_time"]),
            failed_attempts=int(data["failed_attempts"]),
        )
        result = evaluate(req)
    except (KeyError, ValueError, TypeError) as exc:
        return jsonify(error=f"invalid request: {exc}"), 400

    log("access_decision", user_id, data, result.score, result.decision, result.reasons)
    body = {"decision": result.decision, "score": result.score, "reasons": result.reasons}
    if result.decision == STEP_UP:
        secret = _totp_secrets.setdefault(user_id, pyotp.random_base32())
        body["mfa_provisioning_uri"] = pyotp.TOTP(secret).provisioning_uri(user_id, issuer_name="IAM-PoC")
    return jsonify(body)


@app.post("/mfa/verify")
def mfa_verify():
    data = request.get_json(silent=True) or {}
    user_id, code = str(data.get("user_id", "")), str(data.get("code", ""))
    secret = _totp_secrets.get(user_id)
    ok = bool(secret) and pyotp.TOTP(secret).verify(code, valid_window=1)
    log("mfa_verify", user_id, {"code_supplied": bool(code)}, decision="PERMIT" if ok else "DENY")
    return jsonify(decision="PERMIT" if ok else "DENY"), (200 if ok else 401)


@app.get("/audit")
def audit():
    with db() as conn:
        rows = conn.execute(
            "SELECT ts, event, user_id, inputs, score, decision, reasons FROM audit ORDER BY id DESC LIMIT 50"
        ).fetchall()
    keys = ["ts", "event", "user_id", "inputs", "score", "decision", "reasons"]
    return jsonify([dict(zip(keys, r)) for r in rows])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)