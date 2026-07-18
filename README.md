<div align="center">

<img src="https://raw.githubusercontent.com/sh0dmonov/cyberscan/main/ui/static/logo.png" alt="CyberScan Logo" width="80" height="80" onerror="this.style.display='none'"/>

# 🛡️ CyberScan

**An async, plugin-based web application security scanner built with Python.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://img.shields.io/badge/Tests-30%20passed-brightgreen)](tests/)
[![Scanners](https://img.shields.io/badge/Scanners-33%20modules-orange)](agent/modules/scanners/)

[Features](#-features) · [Quick Start](#-quick-start) · [Scanners](#-scanner-modules) · [Web UI](#-web-ui) · [Contributing](#-contributing)

</div>

---

## 🔍 What is CyberScan?

**CyberScan** is an open-source, asynchronous web application security scanner designed to automatically detect, classify and report common vulnerabilities — aligned with **OWASP Top 10** and **CVSS v3.1** standards.

Built on a **plugin architecture**, each scanner is an independent module. Adding a new scanner takes less than 20 lines of code.

```
┌─────────────────────────────────────────────────────┐
│                    CyberScan v1.0                   │
├─────────────┬───────────────────┬───────────────────┤
│   CLI Mode  │   Web UI (FastAPI)│   Report Engine   │
├─────────────┴───────────────────┴───────────────────┤
│              Orchestrator + Rate Limiter             │
├──────────────────────────────────────────────────────┤
│  Plugin Registry → 33 Scanner Modules               │
│  XSS │ SQLi │ CORS │ CSRF │ Headers │ DNS │ SSL ... │
└──────────────────────────────────────────────────────┘
```

---

## ✨ Features

- 🔌 **Plugin Architecture** — 33 independent scanner modules, easy to extend
- ⚡ **Fully Async** — `asyncio` + `httpx`, concurrent scanning with `Semaphore` rate limiting
- 🎯 **3 Scan Depths** — `quick` (7 scanners), `standard` (31), `deep` (33)
- 🖥️ **Dual Interface** — CLI for automation, Web UI for visual monitoring
- 📊 **CVSS v3.1 Scoring** — Every finding scored with vector string
- 🔒 **Scope Enforcer** — Never scans outside the target domain (IPv4/IPv6)
- 🔐 **Web UI Auth** — HTTP Basic Authentication out of the box
- 📝 **HTML Reports** — Interactive, filterable, offline-capable
- 🗄️ **Database** — SQLAlchemy async ORM (SQLite default, PostgreSQL ready)
- ✅ **30 Unit Tests** — pytest + pytest-asyncio

---

## 🚀 Quick Start

### Requirements

- Python 3.11+
- `nmap` (optional, for port scanning)

### Installation

```bash
# 1. Clone
git clone https://github.com/sh0dmonov/cyberscan.git
cd cyberscan

# 2. Virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Dependencies
pip install -r requirements.txt

# 4. Configure
cp .env.example .env
# Edit .env — set AUTH_PASSWORD and SECRET_KEY !
```

### CLI Scan

```bash
# Quick scan
python scan.py scan --url https://example.com

# Standard scan with auto-confirm
python scan.py scan --url https://example.com --depth standard --yes

# Deep scan (all 33 modules)
python scan.py scan --url https://example.com --depth deep --yes
```

### Web UI

```bash
python -m uvicorn ui.main:app --host 127.0.0.1 --port 8000 --reload
```

Open **http://localhost:8000** — login with credentials from `.env`

---

## 🔬 Scanner Modules

CyberScan includes **33 scanner modules** across 7 categories:

### 🌐 Reconnaissance
| # | Module | Description |
|---|--------|-------------|
| 1 | Tech Fingerprint | Detects CMS, frameworks, languages |
| 2 | Robots.txt Parser | Finds sensitive disallowed paths |
| 3 | Sitemap Analyzer | Maps site structure |

### 🔗 DNS & Email Security
| # | Module | Description |
|---|--------|-------------|
| 4 | DNS SPF Auditor | Email spoofing protection check |
| 5 | DNS DMARC Auditor | DMARC policy existence & strictness |
| 6 | DNS MX Checker | Mail server enumeration |
| 7 | DNS Zone Transfer | AXFR vulnerability check |

### 🛡️ HTTP Security Headers
| # | Module | CWE |
|---|--------|-----|
| 8 | Content-Security-Policy | CWE-693 |
| 9 | Strict-Transport-Security | CWE-319 |
| 10 | X-Frame-Options | CWE-1021 |
| 11 | X-Content-Type-Options | CWE-116 |
| 12 | Referrer-Policy | CWE-200 |
| 13 | Permissions-Policy | CWE-284 |
| 14 | Server Banner | CWE-200 |
| 15 | X-Powered-By | CWE-200 |

### 🔐 SSL/TLS
| # | Module | Description |
|---|--------|-------------|
| 16 | SSL Certificate | Expiry, CA, validity |
| 17 | SSL Protocol | Detects SSLv2/3, TLS 1.0/1.1 |

### 📁 Information Disclosure
| # | Module | Finds |
|---|--------|-------|
| 18 | .env File Scanner | Leaked credentials |
| 19 | .git Folder Scanner | Exposed source code |
| 20 | Backup Archives | `.zip`, `.sql`, `.tar.gz` |
| 21 | PHPInfo Exposure | PHP configuration leaks |
| 22 | PHPMyAdmin | Exposed DB admin panel |
| 23 | Swagger / OpenAPI | Exposed API documentation |
| 24 | Spring Boot Actuator | Internal system info leaks |

### 💉 Injection & Authentication
| # | Module | CWE | Method |
|---|--------|-----|--------|
| 25 | CORS Misconfiguration | CWE-942 | Wildcard + credential test |
| 26 | Reflected XSS | CWE-79 | URL params + form inputs |
| 27 | SQLi Error-Based | CWE-89 | URL params + HTML forms |
| 28 | SQLi Boolean-Based Blind | CWE-89 | URL params + HTML forms |
| 29 | CSRF Token Checker | CWE-352 | POST form analysis |
| 30 | Cookie Security Flags | CWE-614 | HttpOnly, Secure, SameSite |

### 🔎 Deep Scan Only
| # | Module | CWE | Description |
|---|--------|-----|-------------|
| 31 | HTTP Method Scanner | CWE-650 | PUT, DELETE, TRACE detection |
| 32 | Open Redirect | CWE-601 | URL parameter redirect test |
| 33 | Nmap Port Scanner | CWE-284 | Full port + service detection |

---

## 🖥️ Web UI

The web interface provides:

- 📡 Real-time scan progress (Server-Sent Events)
- 📋 Interactive findings table with severity filters
- 🗂️ Scan history with session management
- 🔐 HTTP Basic Authentication (configurable)

```bash
# Start server
python -m uvicorn ui.main:app --reload

# Default credentials (change in .env!):
# Username: admin
# Password: changeme
```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure:

```env
# Database
DATABASE_URL=sqlite+aiosqlite:///./audit.db

# Scanner Settings
REQUEST_DELAY=0.5           # Seconds between requests
MAX_CONCURRENT_REQUESTS=5   # asyncio.Semaphore limit
REQUEST_TIMEOUT=10          # Per-request timeout
VERIFY_SSL=false            # Skip SSL cert verification

# Web UI Auth
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_PASSWORD=changeme      # ← CHANGE THIS!
SECRET_KEY=change-this      # ← CHANGE THIS!

# Tool Paths
NMAP_PATH=nmap
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
# 30 passed in ~1.2s
```

Tests cover:
- `ScopeEnforcer` — domain, subdomain, IP, IPv6
- `CvssScorer` — CVSS v3.1 scoring and vector
- `Verifier` — confidence scoring
- `ScannerRegistry` — module integrity checks

---

## 🔌 Adding a Custom Scanner

Extend `BaseScanner` in just a few lines:

```python
# agent/modules/scanners/my_scanner.py
from agent.modules.base_scanner import BaseScanner, ScanTarget, RawFinding

class MyScanner(BaseScanner):
    name = "My-Custom-Scanner"
    description = "Checks for my custom vulnerability"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        response = await self.get(target.url)
        if not response:
            return []

        findings = []
        if "vulnerable_pattern" in response.text:
            findings.append(self._make_finding(
                target_url=target.url,
                vulnerability_name="My Custom Vulnerability",
                severity="HIGH",
                description="Found vulnerable pattern in response",
                evidence=response.text[:200],
                cwe_id="CWE-XXX",
                cvss_score=7.5,
                remediation="How to fix it.",
                confidence="HIGH",
            ))
        return findings
```

Then register it in [`agent/scanner_registry.py`](agent/scanner_registry.py).

---

## 🗺️ Roadmap

### v1.0 (Current — Open Source)
- [x] 33 scanner modules
- [x] CLI + Web UI
- [x] CVSS v3.1 scoring
- [x] HTML reports
- [x] HTTP Auth
- [x] 30 unit tests

### v2.0 (Planned — Cloud API)
- [ ] AI-powered analysis (Claude/GPT remediation suggestions)
- [ ] Professional PDF reports
- [ ] Real-time CVE database integration
- [ ] Scheduled scans & alerting (Telegram/Slack)
- [ ] Multi-target scanning dashboard
- [ ] API key authentication
- [ ] Team collaboration features

---

## 🤝 Contributing

Contributions are welcome!

```bash
# Fork → Clone → Branch → Code → Test → PR
git checkout -b feature/my-new-scanner
pytest tests/ -v   # Must pass
```

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

---

## ⚠️ Legal Disclaimer

> **IMPORTANT:** This tool is intended **only** for security research, authorized penetration testing, and auditing systems you own or have explicit written permission to test.
>
> Unauthorized use against systems you do not own is **illegal** and may result in criminal prosecution. The authors assume **no liability** for misuse.

---

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See [LICENSE](LICENSE) for details.

---

<div align="center">

Made with ❤️ for the cybersecurity community

**[⭐ Star this repo](https://github.com/sh0dmonov/cyberscan)** if you find it useful!

</div>
