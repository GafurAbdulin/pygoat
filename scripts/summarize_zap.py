"""Summarize real ZAP JSON reports; no third-party dependencies required."""
import json
import sys
from collections import Counter
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
sites = report.get("site", [])
if isinstance(sites, dict):
    sites = [sites]
alerts = [alert for site in sites for alert in site.get("alerts", [])]
counts = Counter(str(alert.get("riskcode", "unknown")) for alert in alerts)
print("## ZAP baseline results\n")
print("Counts represent alert types, not individual affected URLs.\n")
for code, label in [("3", "High"), ("2", "Medium"), ("1", "Low"), ("0", "Informational")]:
    print(f"- {label}: {counts[code]}")
print("\n| Alert | Risk | Instances | CWE |\n|---|---|---:|---|")
for alert in alerts:
    name = str(alert.get("alert", alert.get("name", "Unknown"))).replace("|", "\\|")
    print(f"| {name} | {alert.get('riskdesc', '')} | {len(alert.get('instances', []))} | {alert.get('cweid', '')} |")
print("\nScope: unauthenticated spider and passive checks of the main Django application.")
print("Isolated exercise containers and authenticated pages are outside this scan's coverage.")
