# SOC Case Study: DNS Beaconing Detection

A hands-on SOC case study simulating detection, investigation, and response
to suspicious DNS beaconing activity (potential command-and-control traffic),
including working Python detection engines and an optional REST API.

## Project Structure
```text
.
├── automation/
│   ├── dns_beaconing_detector.py   # DNS beaconing detection engine (CLI)
│   └── sample_dns.log              # Sample DNS query log
├── edr/
│   ├── edr_detection.py            # EDR-style process detection engine (CLI)
│   └── sample_edr_events.jsonl     # Sample Sysmon-like process events
├── api/
│   └── app.py                      # Optional Flask REST API over both engines
├── siem/
│   ├── dns_beaconing_detection_rule.md
│   └── example_alert.txt
├── incident-response/
│   └── incident_response_report.pdf
├── mitre/
│   └── mitre_attack_mapping_report.pdf
└── requirements.txt
```

## Detection Engines

### 1. DNS Beaconing Detector (`automation/dns_beaconing_detector.py`)
Analyzes a DNS query log and scores each domain using three independent
signals combined into a single risk score (0-100):
- **Frequency** — how many times the domain was queried.
- **Interval regularity** — how evenly spaced the queries are (a coefficient-
  of-variation based score; malware beacons on a fixed timer, humans don't).
- **Domain entropy** — Shannon entropy of the domain label, flagging
  randomly-generated / DGA-style domains.

```bash
python3 automation/dns_beaconing_detector.py automation/sample_dns.log
python3 automation/dns_beaconing_detector.py automation/sample_dns.log --threshold 15 --format json
```

### 2. EDR-Style Process Detector (`edr/edr_detection.py`)
Analyzes Sysmon-like process-creation events (JSONL) against a small,
extensible library of independent rules, each contributing to a severity
score:
- Office application spawning a scripting/shell interpreter
- Base64-encoded PowerShell execution
- PowerShell download-cradle patterns (`IWR`, `DownloadString`, ...)
- Living-off-the-land binary execution (`mshta`, `certutil`, `rundll32`, ...)
- `certutil` used as a download utility

```bash
python3 edr/edr_detection.py
python3 edr/edr_detection.py --events edr/sample_edr_events.jsonl --format json
```

New rules can be added by writing a `rule_*` function and registering it in
`DETECTION_RULES`.

### 3. Optional REST API (`api/app.py`)
Wraps both engines behind a small Flask API so they can be called by other
tools instead of the CLI.

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python3 api/app.py
```

```bash
curl -X POST http://127.0.0.1:5000/api/analyze/dns-beaconing \
     -H "Content-Type: application/json" \
     -d '{"logfile": "automation/sample_dns.log"}'

curl -X POST http://127.0.0.1:5000/api/analyze/edr \
     -H "Content-Type: application/json" \
     -d '{"events_file": "edr/sample_edr_events.jsonl"}'
```

> The CLI scripts themselves need no third-party packages — `requirements.txt`
> is only required for the optional API layer.

## Incident Response Workflow
This case study follows a standard SOC incident response lifecycle:
Detection → Containment → Eradication → Recovery.

The workflow demonstrates how suspicious DNS beaconing activity was detected,
contained, analyzed, and mitigated using a SOC-oriented approach. See
[`incident-response/incident_response_report.pdf`](incident-response/incident_response_report.pdf).

## SIEM Detection Engineering
This case study includes a custom SIEM detection rule
([`siem/dns_beaconing_detection_rule.md`](siem/dns_beaconing_detection_rule.md))
designed to identify suspicious DNS beaconing activity based on repetitive
query patterns, monitoring high-frequency DNS queries from the same host
within a short time window.

## MITRE ATT&CK Mapping
Observed DNS and HTTP beaconing behaviors were mapped to MITRE ATT&CK
techniques (T1071.004, T1071.001, T1046) using behavior-based analysis. See
[`mitre/mitre_attack_mapping_report.pdf`](mitre/mitre_attack_mapping_report.pdf).
