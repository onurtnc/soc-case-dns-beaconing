#!/usr/bin/env python3
"""
Lightweight REST API exposing the DNS beaconing and EDR detection engines.

Endpoints:
    GET  /health                      -> liveness check
    POST /api/analyze/dns-beaconing   -> body: {"logfile": "path/to/log"}
    POST /api/analyze/edr             -> body: {"events_file": "path/to/events.jsonl"}

Run:
    pip install -r requirements.txt
    python3 api/app.py
    curl -X POST http://127.0.0.1:5000/api/analyze/dns-beaconing \
         -H "Content-Type: application/json" \
         -d '{"logfile": "automation/sample_dns.log"}'
"""

import os
import sys
from dataclasses import asdict

from flask import Flask, jsonify, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "automation"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "edr"))

from dns_beaconing_detector import detect_beaconing  # noqa: E402
from edr_detection import load_events, detect_edr_alerts  # noqa: E402

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/analyze/dns-beaconing")
def analyze_dns_beaconing():
    data = request.get_json(silent=True) or {}
    logfile = data.get("logfile", "automation/sample_dns.log")
    threshold = int(data.get("threshold", 20))

    if not os.path.exists(logfile):
        return jsonify({"error": f"log file not found: {logfile}"}), 404

    results = detect_beaconing(logfile, threshold)
    return jsonify([asdict(r) for r in results])


@app.post("/api/analyze/edr")
def analyze_edr():
    data = request.get_json(silent=True) or {}
    events_file = data.get("events_file", "edr/sample_edr_events.jsonl")

    if not os.path.exists(events_file):
        return jsonify({"error": f"events file not found: {events_file}"}), 404

    events = load_events(events_file)
    alerts = detect_edr_alerts(events)
    return jsonify([a.__dict__ for a in alerts])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
