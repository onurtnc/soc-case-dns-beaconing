# SIEM Detection Rule – DNS Beaconing

## Rule Name
Suspicious DNS Beaconing Detected

## Description
This detection rule identifies repetitive DNS queries from the same host
to the same domain within a short time window, which may indicate
command-and-control (C2) beaconing behavior.

## Detection Logic
Trigger an alert when:
- A single host queries the same domain
- More than 20 times
- Within a 2-minute time window

## Example SIEM Logic
