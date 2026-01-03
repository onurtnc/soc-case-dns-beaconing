### MITRE ATT&CK Mapping
Observed DNS and HTTP beaconing behaviors were mapped to MITRE ATT&CK techniques
(T1071.004, T1071.001, T1046) using behavior-based analysis.

## Incident Response Workflow
This case study follows a standard SOC incident response lifecycle:
Detection → Containment → Eradication → Recovery.

The workflow demonstrates how suspicious DNS beaconing activity was detected,
contained, analyzed, and mitigated using a SOC-oriented approach.

## SIEM Detection Engineering

This case study includes a custom SIEM detection rule designed to identify
suspicious DNS beaconing activity based on repetitive query patterns.

The rule focuses on detecting potential command-and-control (C2) behavior by
monitoring high-frequency DNS queries from the same host within a short
time window.

Detection logic was mapped to the MITRE ATT&CK framework and integrated
into a SOC-style incident response workflow.
