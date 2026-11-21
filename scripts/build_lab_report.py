"""Render an English, printable lab report from saved evidence."""
import html
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
REPOSITORY = "https://github.com/GafurAbdulin/pygoat"


def read(name):
    path = EVIDENCE / name
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else None


def table(headers, rows):
    def row(values, tag):
        return "<tr>" + "".join(f"<{tag}>{html.escape(str(v))}</{tag}>" for v in values) + "</tr>"
    return "<table>" + row(headers, "th") + "".join(row(values, "td") for values in rows) + "</table>"


before = read("bandit-before-all.json")
after = read("bandit-after-all.json")
before_gate = read("bandit-before.json")
after_gate = read("bandit-after.json")
parts = ["""<!doctype html><html lang="en"><meta charset="utf-8">
<title>Lab 5 — DevSecOps | PyGoat</title><style>
body{font:16px/1.6 system-ui,sans-serif;color:#172033;max-width:1000px;margin:48px auto;padding:0 24px}
h1,h2,h3{line-height:1.2}h1{font-size:36px}h2{margin-top:40px;border-bottom:2px solid #dbe3ee;padding-bottom:10px}
a{color:#174eb6}table{border-collapse:collapse;width:100%;margin:20px 0;font-size:14px}
th,td{text-align:left;vertical-align:top;border:1px solid #ccd5e2;padding:10px}th{background:#eef3fa}
code,pre{font-family:Consolas,monospace;background:#f1f4f8}pre{padding:16px;overflow-wrap:anywhere;white-space:pre-wrap}
.note{border-left:4px solid #d18b12;padding:12px 18px;background:#fff7e5}
@media print{body{margin:0;max-width:none;font-size:11pt}h2,h3{break-after:avoid}tr{break-inside:avoid}a{color:inherit}}
</style><h1>Lab 5 — DevSecOps</h1><p>Security scanning and remediation of PyGoat with GitHub Actions.</p>"""]
parts += [f'<p><strong>Repository:</strong> <a href="{REPOSITORY}">{REPOSITORY}</a><br>',
          '<strong>Team:</strong> Gafur Abdulin; three team member names pending confirmation.<br>',
          '<strong>Upstream baseline:</strong> <code>2aa4cc14f251e4a780e94e200aed6b36a5b15c21</code><br>',
          f'<strong>Report generated:</strong> {datetime.now(timezone.utc).isoformat(timespec="seconds")}</p>']
parts += ['<h2>1. Repository and scope</h2>',
          '<p>A public fork was created under GafurAbdulin. The application deliberately contains security weaknesses. The current upstream version separates practical exercises into Flask containers; the main website uses Django. Source scanning covers both. The unauthenticated DAST scan covers only the main website, not every exercise container.</p>',
          '<h2>2. CI pipeline</h2>',
          '<p>The workflow is stored in <code>.github/workflows/devsecops.yml</code>, runs on every push, and supports manual dispatch. Every job uses <code>ubuntu-latest</code>.</p>']
parts += [table(["Job", "Purpose", "Evidence"], [
    ["sast_scan", "Bandit 1.9.4; medium/high severity with medium/high confidence gate; supplemental report at all confidence levels", "bandit-findings artifact"],
    ["image_scan", "Build own Dockerfile; Docker Scout critical/high CVE gate", "docker-scout-findings SARIF artifact"],
    ["dast_scan", "Build own image; migrate and seed database; wait for HTTP readiness; run ZAP baseline", "zap-findings HTML/JSON/Markdown and application logs"],
    ["patch_verification", "Exercise actual SQL lab login using an isolated SQLite database", "Job log with structured regression results"],
])]
parts += ['<p>The DAST job has no <code>needs</code> dependency, so Bandit or Scout findings do not prevent it from running. Reports upload with <code>if: always()</code>. ZAP exit codes 1/2 represent findings; code 3 is treated as an execution failure. A finding gate may fail as expected; build, authentication, or scan-engine errors must be resolved separately.</p>',
          '<p>Docker Scout uses repository secrets <code>DOCKERHUB_USERNAME</code> and <code>DOCKERHUB_PASSWORD</code>. The latter can contain a DockerHub access token. The image is scanned locally on the runner and does not need to be published.</p>',
          '<p>Build compatibility adjustment: PyYAML was changed from 5.1 to 6.0.2 to use a Python 3.11-compatible wheel. This dependency change is separate from the code-level bonus fix. Other vulnerable dependencies remain available for scan analysis.</p>',
          '<h3>Pipeline run evidence</h3>']
runs = read("github-runs.json")
if runs and runs.get("workflow_runs"):
    parts.append('<ul>')
    for run in runs["workflow_runs"]:
        url = html.escape(run["html_url"], quote=True)
        label = html.escape(f"Run {run['run_number']}: {run.get('display_title', '')} — {run.get('conclusion') or run['status']}")
        parts.append(f'<li><a href="{url}">{label}</a>; commit <code>{run["head_sha"]}</code></li>')
    parts.append('</ul>')
else:
    parts.append('<p class="note">Pending: GitHub Actions run links. Local evidence below does not substitute for the required pipeline-run evidence.</p>')
parts += ['<h3>Local SAST evidence</h3>']
parts.append(table(["Report", "Before", "After"], [
    ["Medium/high findings, all confidence levels", len(before["results"]), len(after["results"])],
    ["Medium/high findings, medium/high confidence gate", len(before_gate["results"]), len(after_gate["results"])],
    ["SQL injection findings (B608)", sum(x["test_id"] == "B608" for x in before["results"]), sum(x["test_id"] == "B608" for x in after["results"])],
]))
parts += ['<p>The original SQL finding has LOW Bandit confidence, so the required <code>-ll -ii</code> report excludes it. The supplemental <code>-ll</code> report preserves it. The route-level regression confirms that this particular finding is exploitable, rather than relying only on a heuristic warning.</p>',
          '<h2>3. Dynamic application security testing</h2>']
parts.insert(-1, '<h3>Local Docker Scout evidence</h3>')
scout = read("scout-local.sarif")
if scout:
    scan = scout["runs"][0]
    results = scan.get("results", [])
    rules = {rule["id"]: rule for rule in scan["tool"]["driver"].get("rules", [])}
    cves = {result["ruleId"] for result in results}
    severities = Counter(rules[cve].get("properties", {}).get("cvssV3_severity", "Unspecified") for cve in cves)
    parts.insert(-1, table(["Metric", "Count"], [
        ["SARIF result entries (including repeated CVEs)", len(results)],
        ["Distinct CVE identifiers", len(cves)],
        *[[f"Distinct {severity} CVEs", count] for severity, count in sorted(severities.items())],
    ]))
    parts.insert(-1, '<p>Counts come from the saved SARIF report. A CVE can appear against multiple packages or locations. Affected versions do not prove every vulnerable code path is reachable. The local scan completed; the CI action separately gates critical/high findings.</p>')
else:
    parts.insert(-1, '<p class="note">Docker Scout report pending.</p>')
zap = read("zap-local/zap-report.json") or read("zap-pipeline/zap-report.json")
if zap:
    sites = zap.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    alerts = [a for site in sites for a in site.get("alerts", [])]
    parts.append(table(["Alert", "Risk", "Instances", "CWE"], [
        [a.get("alert", a.get("name")), a.get("riskdesc"), len(a.get("instances", [])), a.get("cweid")] for a in alerts]))
    parts.append('<p>These are actual ZAP alert types; instance counts describe affected requests or locations. Header and cookie findings identify browser-side hardening gaps. Passive warnings require context and do not prove SQL injection or remote code execution. The full report contains evidence URLs and remediation advice.</p>')
else:
    parts.append('<p class="note">Pending: actual ZAP scan output. No DAST findings are claimed until a report is available.</p>')
parts += ['<h2>4. Four distinct vulnerability analyses</h2>',
          '<p>All four selected findings have MEDIUM severity in Bandit. CVSS scores below are analyst estimates for the stated direct-access exercise scenario, not scores published by CWE or assigned CVEs. CWE entries classify weaknesses and do not supply a universal CVSS score. For the proxied multi-user deployment, authentication and isolation change exposure; an ordinary authenticated account may be required to start/access an exercise.</p>',
          '<p>Shared CVSS assumptions: network reachable endpoint (AV:N), low attack complexity (AC:L), no prior application privileges in the directly exposed exercise (PR:N), no victim interaction (UI:N), and unchanged security authority (S:U). The source routes themselves have no authentication decorator. The reverse-proxy deployment should be assessed separately.</p>']
analyses = [
    ("Member 1 — SQL injection", "B608", "dockerized_labs/sql_injection_lab/app.py", 51, "89", "8.2 (High)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
     "POST /lab interpolated username and password into a SELECT statement. A username containing an SQL comment changed the WHERE clause and bypassed the password comparison. The regression test confirmed that the vulnerable route displayed a successful login with an incorrect password.",
     "Confidentiality is High because query manipulation can disclose the local users table. Integrity is Low because identity presentation can be forged. Availability is None in this conservative model: this path executes one SELECT, and destructive multi-statement execution was not demonstrated. The page displays a successful identity; the test does not claim it establishes a persistent authenticated session.",
     "Use SQLite placeholders and bind the credentials separately. The bonus patch implements this change. No prior privileges are needed when this exercise is exposed directly."),
    ("Member 2 — Evaluation of untrusted Python", "B307", "dockerized_labs/command_injection_lab/app.py", 49, "95", "9.8 (Critical)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "POST /lab2 passes the user-controlled val field to eval(expression). Python expressions can invoke functions, so a field intended for calculation can run code with the Flask process's permissions.",
     "Potential consequences include reading application secrets, modifying writable application data, and stopping the process. Confidentiality, Integrity, and Availability are therefore High in the direct-access scenario. Container execution does not automatically imply host compromise.",
     "Use a restricted arithmetic parser with an explicit operator allowlist. ast.literal_eval is suitable only if the feature should accept literal data, not arbitrary arithmetic. No prior privileges are needed at the directly exposed route."),
    ("Member 3 — Pickle cookie deserialization", "B301", "dockerized_labs/software_integrity_lab/app.py", 44, "502", "9.8 (Critical)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "GET /lab1 base64-decodes the client-controlled token cookie and passes it to pickle.loads. Base64 provides encoding, not authenticity. Pickle can invoke callable objects during deserialization before the later admin attribute check.",
     "An attacker could execute code as the application process, disclose secrets, alter writable data, or deny service. This supports High impact for all three impact metrics. The attacker needs control of their own HTTP cookie, not a valid administrator account.",
     "Replace pickle with a safe data format and retain authorization state on the server. If client data must be signed, use a managed secret and validate the data schema; never restore untrusted Python objects."),
    ("Member 4 — Unsafe YAML object construction", "B506", "dockerized_labs/a9_uckv_lab/app.py", 62, "502", "9.8 (Critical)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "POST /upload_yaml accepts a YAML file and calls yaml.load(file.stream, Loader=yaml.Loader). This loader can construct Python objects from YAML tags. Filename-extension validation and the 16 MB upload limit do not restrict those tags.",
     "Object construction can lead to code execution with the service's privileges. Potential impact includes data disclosure, tampering, and service interruption. This is a separate upload endpoint and parser from the pickle-cookie vulnerability, despite sharing CWE-502.",
     "Use yaml.safe_load and enforce a schema containing only permitted scalar, list, and mapping values. A newer PyYAML version alone does not make an explicit unsafe Loader safe. Direct endpoint access requires no application privileges."),
]
for title, test, filename, line, cwe, score, vector, mechanism, impact, mitigation in analyses:
    parts.append(f'<h3>{html.escape(title)}</h3><p><strong>Evidence:</strong> {test}, MEDIUM; baseline <code>{filename}:{line}</code>. ')
    parts.append(f'<a href="https://cwe.mitre.org/data/definitions/{cwe}.html">CWE-{cwe}</a>.</p>')
    parts.append(f'<p><strong>Estimated CVSS v3.1:</strong> {score}<br><code>{vector}</code></p>')
    parts += [f'<p>{html.escape(text)}</p>' for text in (mechanism, impact, mitigation)]
parts += ['<p>For the three code-execution scenarios, changing only PR:N to PR:L for an authenticated proxy reduces the estimated base score from 9.8 to 8.8. Deployment-specific access controls must be considered rather than treating the direct-container estimate as universal.</p>',
          '<h2>5. Bonus: code-level SQL injection fix</h2>',
          '<p>The vulnerable f-string query was replaced by a constant SQL statement containing two <code>?</code> placeholders. Credentials are passed as a separate tuple to <code>execute</code>. A closing context ensures the SQLite connection is released on both success and failure.</p>',
          '<pre>sql_query = "SELECT * FROM users WHERE username=? AND password=?"\nwith closing(sqlite3.connect("database.db")) as conn:\n    result = conn.execute(sql_query, (username, password)).fetchone()</pre>',
          '<p>The regression invokes the actual Flask route against a temporary database. It checks a correct login, an incorrect password, an injection attempt, and an apostrophe in an ordinary username. Before the fix the injection succeeds; after the fix it is treated as data and rejected.</p>']
parts.append(table(["Check", "Before", "After"], [
    [key, read("sql-before.json").get(key), read("sql-after.json").get(key)] for key in
    ["valid_login_succeeds", "incorrect_password_rejected", "sql_injection_bypasses_login", "apostrophe_handled_as_data", "result"]]))
parts += ['<p>Bandit still fails because other intentional weaknesses remain. Its confidence-filtered gate need not change when a LOW-confidence finding is fixed; the all-confidence report shows the removal. Docker Scout inventories dependency/OS CVEs, so a parameterized SQL query does not remove those CVEs. ZAP scanning only the main website cannot validate a route inside an unstarted exercise container; the separate route regression provides that functional evidence.</p>',
          '<h2>6. Evidence files and remaining submission items</h2><ul>']
for path in sorted(EVIDENCE.rglob("*")):
    if path.is_file() and path.suffix in {".json", ".sarif", ".html"}:
        relative = path.relative_to(ROOT).as_posix()
        parts.append(f'<li><a href="../{relative}">{relative}</a></li>')
parts += ['</ul><p>Before submission: fill in the remaining three names; ensure each member reviews their assigned analysis; include completed baseline and patched GitHub Actions run links and their artifacts. Pending entries are explicitly marked and must not be represented as completed scans.</p>',
          '<h2>References</h2><ul>',
          '<li><a href="https://github.com/adeyosemanputra/pygoat">PyGoat upstream source and installation instructions</a></li>',
          '<li><a href="https://github.com/docker/scout-action">Docker Scout Action inputs</a></li>',
          '<li><a href="https://www.zaproxy.org/docs/docker/baseline-scan/">ZAP baseline behavior and exit codes</a></li>',
          '<li><a href="https://www.first.org/cvss/v3.1/specification-document">FIRST CVSS v3.1 specification</a></li>',
          '</ul></html>']
destination = ROOT / "docs/lab5-report.html"
destination.parent.mkdir(exist_ok=True)
destination.write_text("\n".join(parts), encoding="utf-8")
print(destination)
