# webhook.py
import os
import time
import hmac
import hashlib
import base64
import json
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, abort
import requests
from urllib.parse import urljoin

# ---------- Config from environment ----------
COINBASE_API_KEY = os.environ.get("COINBASE_API_KEY", "")
COINBASE_API_SECRET = os.environ.get("COINBASE_API_SECRET", "")  # base64 secret returned by Coinbase
COINBASE_PASSPHRASE = os.environ.get("COINBASE_API_PASSPHRASE", "")
ALERT_SECRET = os.environ.get("ALERT_SECRET", "changeme")
MAX_USD_PER_ORDER = float(os.environ.get("MAX_USD_PER_ORDER", "100"))
MIN_SECONDS_BETWEEN_ORDERS = int(os.environ.get("MIN_SECONDS_BETWEEN_ORDERS", "1"))
COINBASE_API_BASE = os.environ.get("COINBASE_API_BASE", "https://api-public.sandbox.pro.coinbase.com")
USE_SANDBOX = os.environ.get("USE_SANDBOX", "true").lower() in ("1", "true", "yes")

# ---------- Local DB (sqlite) for idempotency and logs ----------
DB_PATH = os.environ.get("DB_PATH", "alerts.db")

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tv_id TEXT,
            raw TEXT,
            symbol TEXT,
            action TEXT,
            amount REAL,
            status TEXT,
            response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()
    return conn

db = init_db()

# Last order timestamp (fallback if meta row doesn't exist)
def get_last_order_ts():
    cur = db.cursor()
    cur.execute("SELECT value FROM meta WHERE key = 'last_order_ts'")
    row = cur.fetchone()
    if row:
        try:
            return float(row[0])
        except:
            return 0.0
    return 0.0

def set_last_order_ts(ts):
    cur = db.cursor()
    cur.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('last_order_ts', ?)", (str(ts),))
    db.commit()

# ---------- Flask app ----------
app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok", "time": datetime.utcnow().isoformat()})

def cb_auth_headers(method, path, body=""):
    # Coinbase signature for Exchange API
    timestamp = str(int(time.time()))
    message = timestamp + method.upper() + path + (body or "")
    # Coinbase expects secret decoded from base64
    secret = base64.b64decode(COINBASE_API_SECRET)
    signature = base64.b64encode(hmac.new(secret, message.encode('utf-8'), hashlib.sha256).digest()).decode()
    return {
        "CB-ACCESS-KEY": COINBASE_API_KEY,
        "CB-ACCESS-SIGN": signature,
        "CB-ACCESS-TIMESTAMP": timestamp,
        "CB-ACCESS-PASSPHRASE": COINBASE_PASSPHRASE,
        "Content-Type": "application/json"
    }

def parse_alert_text(txt):
    # Accepts forms like:
    # "secret: MY_SECRET; symbol: BTC-USD; action: buy; amount: 10.0; tv_id: 123456"
    # or plain "symbol: BTC-USD; action: buy; amount: 10.0"
    parts = {}
    for p in txt.split(";"):
        if ":" in p:
            k, v = p.split(":", 1)
            parts[k.strip().lower()] = v.strip()
    return parts

def insert_alert(tv_id, raw, symbol, action, amount, status, response):
    cur = db.cursor()
    cur.execute("""
        INSERT INTO alerts (tv_id, raw, symbol, action, amount, status, response)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (tv_id, raw, symbol, action, amount, status, json.dumps(response)))
    db.commit()
    return cur.lastrowid

def already_processed(tv_id):
    if not tv_id:
        return False
    cur = db.cursor()
    cur.execute("SELECT 1 FROM alerts WHERE tv_id = ? LIMIT 1", (tv_id,))
    return cur.fetchone() is not None

def place_market_order_by_funds(product_id, side, usd_amount):
    # POST /orders with "funds" is supported to express quote currency amount for market orders
    path = "/orders"
    body = json.dumps({
        "type": "market",
        "side": side,
        "product_id": product_id,
        "funds": str(round(usd_amount, 2))
    })
    url = urljoin(COINBASE_API_BASE, path)
    headers = cb_auth_headers("POST", path, body)
    r = requests.post(url, headers=headers, data=body, timeout=15)
    try:
        return r.status_code, r.json()
    except:
        return r.status_code, r.text

@app.route("/webhook/tradingview", methods=["POST"])
def tradingview_webhook():
    raw = request.get_data(as_text=True).strip()
    if not raw:
        return jsonify({"error":"empty body"}), 400

    data = parse_alert_text(raw)

    # Require secret verification
    if data.get("secret", "") != ALERT_SECRET:
        return jsonify({"error":"invalid secret"}), 401

    tv_id = data.get("tv_id") or data.get("id") or None  # optional id for idempotency
    if tv_id and already_processed(tv_id):
        return jsonify({"error":"duplicate alert", "tv_id": tv_id}), 409

    symbol = data.get("symbol")
    action = data.get("action")
    amount = data.get("amount")

    if not symbol or not action or not amount:
        return jsonify({"error":"missing fields", "received": data}), 400

    try:
        usd_amount = float(amount)
    except:
        return jsonify({"error":"invalid amount"}, 400)

    # Safety checks
    if usd_amount <= 0 or usd_amount > MAX_USD_PER_ORDER:
        return jsonify({"error":"amount out of bounds", "max_allowed": MAX_USD_PER_ORDER}), 400

    # rate-limiting
    last_ts = get_last_order_ts()
    now_ts = time.time()
    if now_ts - last_ts < MIN_SECONDS_BETWEEN_ORDERS:
        return jsonify({"error":"rate limit", "min_seconds": MIN_SECONDS_BETWEEN_ORDERS}), 429

    # place order
    side = "buy" if action.lower().startswith("buy") else "sell"
    status_code, resp = place_market_order_by_funds(product_id=symbol, side=side, usd_amount=usd_amount)

    # record alert in DB for audit / idempotency
    insert_alert(tv_id, raw, symbol, action, usd_amount, "attempted" if status_code not in (200,201) else "placed", resp)

    # update last order timestamp on attempt (or only on success if you prefer)
    set_last_order_ts(now_ts)

    if status_code in (200, 201):
        return jsonify({"status":"ok", "code": status_code, "response": resp}), 200
    else:
        return jsonify({"status":"error", "code": status_code, "response": resp}), 500

if __name__ == "__main__":
    # For Render, gunicorn will be used; this is for local testing only.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
