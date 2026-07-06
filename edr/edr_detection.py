#!/usr/bin/env python3
"""
EDR-Style Process Detection Engine

Analyzes endpoint process-creation telemetry (Sysmon-like JSONL events) and
flags suspicious behavior using a small library of independent detection
rules, each contributing to a severity score. Designed to be easy to extend:
add a new rule function and register it in DETECTION_RULES.

Usage:
    python3 edr_detection.py
    python3 edr_detection.py --events sample_edr_events.jsonl --format json
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List

# ---------------------------------------------------------------------------
# Detection primitives
# ---------------------------------------------------------------------------

# Office/scripting parent -> LOLBin child relationships.
SUSPICIOUS_CHAINS = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "wscript.exe"),
    ("excel.exe", "mshta.exe"),
]

# Living-off-the-land binaries commonly abused for execution/download.
LOLBINS = {
    "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe",
    "wscript.exe", "cscript.exe", "bitsadmin.exe",
}

ENCODED_PS_REGEX = re.compile(r"(?i)-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}")
DOWNLOAD_CRADLE_REGEX = re.compile(
    r"(?i)(iwr|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient)"
)
CERTUTIL_DOWNLOAD_REGEX = re.compile(r"(?i)certutil(\.exe)?\s+.*-urlcache")


@dataclass
class Alert:
    alert_name: str
    severity: str
    score: int
    host: str
    user: str
    parent_image: str
    image: str
    command_line: str
    reasons: List[str]
    mitre: List[Dict[str, str]] = field(default_factory=list)


def load_events(file_path: str) -> List[dict]:
    """Load endpoint events from a JSONL file (one JSON object per line)."""
    events = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _basename_lower(path: str) -> str:
    return os.path.basename(path or "").lower()


# ---------------------------------------------------------------------------
# Individual detection rules
# Each rule takes an event dict and returns (score, reason, mitre) or None.
# ---------------------------------------------------------------------------

def rule_office_to_scripting(event: dict) -> tuple | None:
    parent = _basename_lower(event.get("parent_image", ""))
    child = _basename_lower(event.get("image", ""))
    for p, c in SUSPICIOUS_CHAINS:
        if parent.endswith(p) and child.endswith(c):
            return (
                40,
                "Office application spawning a scripting/shell interpreter",
                {"tactic": "Execution", "technique": "Command and Scripting Interpreter",
                 "technique_id": "T1059"},
            )
    return None


def rule_encoded_powershell(event: dict) -> tuple | None:
    image = _basename_lower(event.get("image", ""))
    cmd = event.get("command_line", "") or ""
    if image.endswith("powershell.exe") and ENCODED_PS_REGEX.search(cmd):
        return (
            35,
            "Base64-encoded PowerShell command execution",
            {"tactic": "Defense Evasion", "technique": "Obfuscated Files or Information",
             "technique_id": "T1027"},
        )
    return None


def rule_download_cradle(event: dict) -> tuple | None:
    cmd = event.get("command_line", "") or ""
    if DOWNLOAD_CRADLE_REGEX.search(cmd):
        return (
            30,
            "PowerShell download cradle pattern detected",
            {"tactic": "Command and Control", "technique": "Ingress Tool Transfer",
             "technique_id": "T1105"},
        )
    return None


def rule_lolbin_execution(event: dict) -> tuple | None:
    image = _basename_lower(event.get("image", ""))
    if image in LOLBINS:
        return (
            20,
            f"Execution of a living-off-the-land binary ({image})",
            {"tactic": "Defense Evasion", "technique": "System Binary Proxy Execution",
             "technique_id": "T1218"},
        )
    return None


def rule_certutil_download(event: dict) -> tuple | None:
    cmd = event.get("command_line", "") or ""
    if CERTUTIL_DOWNLOAD_REGEX.search(cmd):
        return (
            30,
            "certutil used to download a remote file (LOLBin abuse)",
            {"tactic": "Command and Control", "technique": "Ingress Tool Transfer",
             "technique_id": "T1105"},
        )
    return None


DETECTION_RULES: List[Callable[[dict], tuple | None]] = [
    rule_office_to_scripting,
    rule_encoded_powershell,
    rule_download_cradle,
    rule_lolbin_execution,
    rule_certutil_download,
]


def score_to_severity(score: int) -> str:
    if score >= 60:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def detect_edr_alerts(events: List[dict]) -> List[Alert]:
    alerts: List[Alert] = []

    for event in events:
        if event.get("event_type") != "process_create":
            continue

        total_score = 0
        reasons: List[str] = []
        mitre_hits: List[Dict[str, str]] = []

        for rule in DETECTION_RULES:
            result = rule(event)
            if result:
                score, reason, mitre = result
                total_score += score
                reasons.append(reason)
                if mitre not in mitre_hits:
                    mitre_hits.append(mitre)

        if reasons:
            alerts.append(Alert(
                alert_name="Suspicious Process Behavior (EDR)",
                severity=score_to_severity(total_score),
                score=total_score,
                host=event.get("host", "unknown"),
                user=event.get("user", "unknown"),
                parent_image=event.get("parent_image", ""),
                image=event.get("image", ""),
                command_line=event.get("command_line", ""),
                reasons=reasons,
                mitre=mitre_hits,
            ))

    alerts.sort(key=lambda a: a.score, reverse=True)
    return alerts


def print_text_report(alerts: List[Alert]) -> None:
    print("=== EDR Detection Output ===\n")

    if not alerts:
        print("No suspicious endpoint activity detected.")
        return

    for i, alert in enumerate(alerts, 1):
        print(f"[{i}] {alert.alert_name} | Severity: {alert.severity} (score={alert.score})")
        print(f"    Host: {alert.host} | User: {alert.user}")
        print(f"    Parent -> Child: {alert.parent_image} -> {alert.image}")
        print(f"    Command Line: {alert.command_line}")
        print(f"    Reasons: {', '.join(alert.reasons)}")
        for m in alert.mitre:
            print(f"    MITRE: {m['tactic']} - {m['technique']} ({m['technique_id']})")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="EDR-style process detection engine")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_events = os.path.join(script_dir, "sample_edr_events.jsonl")
    parser.add_argument("--events", default=default_events, help="Path to a JSONL file of process-create events")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()

    events = load_events(args.events)
    alerts = detect_edr_alerts(events)

    if args.format == "json":
        print(json.dumps([alert.__dict__ for alert in alerts], indent=2))
    else:
        print_text_report(alerts)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
