from collections import Counter

def analyze_dns_logs(log_file, threshold=20):
    """
    Analyzes DNS logs to detect repetitive query patterns
    that may indicate beaconing or C2 activity.
    """
    try:
        with open(log_file, "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        print("Log file not found.")
        return

    domains = []

    for line in lines:
        if "DNS query" in line:
            domain = line.strip().split()[-1]
            domains.append(domain)

    domain_counts = Counter(domains)

    print("=== Suspicious DNS Activity Report ===\n")
    for domain, count in domain_counts.items():
        if count >= threshold:
            print(f"[!] {domain} --> {count} queries detected")

    if not any(count >= threshold for count in domain_counts.values()):
        print("No suspicious activity detected.")

if __name__ == "__main__":
    analyze_dns_logs("sample_dns.log")
