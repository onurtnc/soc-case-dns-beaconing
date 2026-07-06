#!/usr/bin/env python3
"""
DNS Beaconing Detector

Analyzes DNS query logs to identify command-and-control (C2) beaconing
behavior using three independent signals:

1. Frequency       - how many times a domain was queried.
2. Interval regularity - how consistent the time gaps between queries are
                         (beaconing malware calls home on a fixed timer;
                         human browsing does not).
3. Domain entropy  - how "random-looking" a domain name is (many
                     info-stealers/C2 frameworks use algorithmically
                     generated domains).

Usage:
    python3 dns_beaconing_detector.py sample_dns.log
    python3 dns_beaconing_detector.py sample_dns.log --threshold 15 --window 120
    python3 dns_beaconing_detector.py sample_dns.log --format json --out report.json
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Optional

LOG_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass
class DomainActivity:
    domain: str
    query_count: int
    first_seen: str
    last_seen: str
    avg_interval_seconds: Optional[float]
    interval_stdev_seconds: Optional[float]
    regularity_score: float          # 0.0 (irregular) - 1.0 (perfectly regular)
    entropy: float                   # Shannon entropy of the domain string
    risk_score: float                # 0-100 combined score
    verdict: str                     # "suspicious" | "normal"
    reasons: List[str] = field(default_factory=list)


def parse_log(path: str) -> Dict[str, List[datetime]]:
    """Parse a DNS log file into {domain: [timestamps]}."""
    domain_hits: Dict[str, List[datetime]] = defaultdict(list)

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if "DNS query" not in line:
                continue

            parts = line.split()
            domain = parts[-1]

            ts = None
            if len(parts) >= 2:
                try:
                    ts = datetime.strptime(f"{parts[0]} {parts[1]}", LOG_TIMESTAMP_FORMAT)
                except ValueError:
                    ts = None

            domain_hits[domain].append(ts)

    return domain_hits


def shannon_entropy(s: str) -> float:
    """Compute the Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def compute_regularity(timestamps: List[datetime]) -> tuple[Optional[float], Optional[float], float]:
    """
    Returns (avg_interval, stdev_interval, regularity_score).
    regularity_score is 1.0 for perfectly evenly-spaced queries (classic
    beaconing) and approaches 0.0 as intervals become more random.
    """
    valid = sorted(t for t in timestamps if t is not None)
    if len(valid) < 3:
        return None, None, 0.0

    intervals = [
        (valid[i + 1] - valid[i]).total_seconds()
        for i in range(len(valid) - 1)
    ]
    avg = statistics.mean(intervals)
    stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0

    if avg == 0:
        return avg, stdev, 0.0

    # Coefficient of variation: lower = more regular (more beacon-like).
    coefficient_of_variation = stdev / avg
    regularity_score = max(0.0, 1.0 - min(coefficient_of_variation, 1.0))
    return avg, stdev, regularity_score


def analyze_domain(domain: str, timestamps: List[datetime], threshold: int) -> DomainActivity:
    valid_timestamps = [t for t in timestamps if t is not None]
    count = len(timestamps)

    avg_interval, stdev_interval, regularity = compute_regularity(timestamps)
    entropy = shannon_entropy(domain.split(".")[0])  # score the subdomain/label, not the TLD

    reasons: List[str] = []
    if count >= threshold:
        reasons.append(f"High query frequency ({count} queries)")
    if regularity >= 0.85:
        reasons.append(f"Highly regular query interval (score={regularity:.2f})")
    if entropy >= 3.5:
        reasons.append(f"High domain-name entropy ({entropy:.2f} bits/char)")

    # Weighted composite score (0-100).
    frequency_component = min(count / threshold, 1.0) * 50 if threshold else 0
    regularity_component = regularity * 35
    entropy_component = min(entropy / 4.5, 1.0) * 15
    risk_score = round(frequency_component + regularity_component + entropy_component, 1)

    verdict = "suspicious" if risk_score >= 60 or count >= threshold else "normal"

    return DomainActivity(
        domain=domain,
        query_count=count,
        first_seen=(min(valid_timestamps).isoformat() if valid_timestamps else "unknown"),
        last_seen=(max(valid_timestamps).isoformat() if valid_timestamps else "unknown"),
        avg_interval_seconds=round(avg_interval, 2) if avg_interval is not None else None,
        interval_stdev_seconds=round(stdev_interval, 2) if stdev_interval is not None else None,
        regularity_score=round(regularity, 2),
        entropy=round(entropy, 2),
        risk_score=risk_score,
        verdict=verdict,
        reasons=reasons,
    )


def detect_beaconing(path: str, threshold: int = 20) -> List[DomainActivity]:
    domain_hits = parse_log(path)
    results = [analyze_domain(domain, timestamps, threshold) for domain, timestamps in domain_hits.items()]
    results.sort(key=lambda r: r.risk_score, reverse=True)
    return results


def print_text_report(results: List[DomainActivity]) -> None:
    print("=== DNS Beaconing Detection Report ===\n")
    suspicious = [r for r in results if r.verdict == "suspicious"]

    if not suspicious:
        print("No suspicious beaconing activity detected.")
    else:
        for r in suspicious:
            print(f"[!] {r.domain}")
            print(f"    Queries: {r.query_count} | Risk score: {r.risk_score}/100")
            print(f"    Avg interval: {r.avg_interval_seconds}s | Regularity: {r.regularity_score} | Entropy: {r.entropy}")
            for reason in r.reasons:
                print(f"    - {reason}")
            print()

    print(f"Total domains analyzed: {len(results)} | Suspicious: {len(suspicious)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="DNS Beaconing Detector")
    parser.add_argument("logfile", nargs="?", default="sample_dns.log", help="Path to the DNS log file")
    parser.add_argument("--threshold", type=int, default=20, help="Query count threshold to flag a domain (default: 20)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--out", default=None, help="Write output to this file instead of stdout")
    args = parser.parse_args()

    try:
        results = detect_beaconing(args.logfile, args.threshold)
    except FileNotFoundError:
        print(f"[!] Log file not found: {args.logfile}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload = json.dumps([asdict(r) for r in results], indent=2)
        if args.out:
            with open(args.out, "w") as f:
                f.write(payload)
            print(f"[+] Report written to {args.out}")
        else:
            print(payload)
    else:
        if args.out:
            import contextlib
            with open(args.out, "w") as f, contextlib.redirect_stdout(f):
                print_text_report(results)
            print(f"[+] Report written to {args.out}")
        else:
            print_text_report(results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
