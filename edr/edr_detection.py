import json
import re

# Suspicious parent -> child process relationships (EDR logic)
SUSPICIOUS_CHAINS = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"),
]

# Regex to detect encoded PowerShell commands
ENCODED_PS_REGEX = re.compile(r"(?i)-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}")

def load_events(file_path):
    """
    Loads endpoint events from a JSONL file (one JSON object per line).
    """
    events = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events

def is_suspicious_chain(parent, child):
    parent = parent.lower()
    child = child.lower()
    for p, c in SUSPICIOUS_CHAINS:
        if parent.endswith(p) and child.endswith(c):
            return True
    return False

def detect_edr_alerts(events):
    """
    Detects suspicious endpoint behavior similar to EDR logic:
    - Office application spawning PowerShell
    - Encoded PowerShell command execution
    """
    alerts = []

    for event in events:
        if event.get("event_type") != "process_create":
            continue

        host = event.get("host", "unknown")
        user = event.get("user", "unknown")
        image = event.get("image", "")
        parent_image = event.get("parent_image", "")
        command_line = event.get("command_line", "")

        reasons = []

        # Office -> PowerShell detection
        if is_suspicious_chain(parent_image, image):
            reasons.append("Office application spawning PowerShell")

        # Encoded PowerShell detection
        if image.lower().endswith("powershell.exe") and ENCODED_PS_REGEX.search(command_line):
            reasons.append("Encoded PowerShell command detected")

        if reasons:
            alerts.append({
                "alert_name": "Suspicious Process Behavior (EDR)",
                "severity": "High",
                "host": host,
                "user": user,
                "parent_image": parent_image,
                "image": image,
                "command_line": command_line,
                "reasons": reasons,
                "mitre": {
                    "tactic": "Execution",
                    "technique": "Command and Scripting Interpreter: PowerShell",
                    "technique_id": "T1059.001"
                }
            })

    return alerts

def main():
    events = load_events("edr/sample_edr_events.jsonl")
    alerts = detect_edr_alerts(events)

    print("=== EDR Detection Output ===\n")

    if not alerts:
        print("No suspicious endpoint activity detected.")
        return

    for i, alert in enumerate(alerts, 1):
        print(f"[{i}] {alert['alert_name']} | Severity: {alert['severity']}")
        print(f"    Host: {alert['host']} | User: {alert['user']}")
        print(f"    Parent -> Child: {alert['parent_image']} -> {alert['image']}")
        print(f"    Command Line: {alert['command_line']}")
        print(f"    Reasons: {', '.join(alert['reasons'])}")
        print(f"    MITRE: {alert['mitre']['tactic']} - {alert['mitre']['technique']} ({alert['mitre']['technique_id']})\n")

if __name__ == "__main__":
    main()
