# vulnscan

Web vulnerability scanner built from scratch in Python. Checks for common misconfigurations and security issues without relying on third-party scanning frameworks.

## What it checks

| Check | Severity | Description |
|---|---|---|
| Security headers | Medium | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc. |
| Info disclosure headers | Low | Server, X-Powered-By, X-AspNet-Version |
| Cookie flags | Medium | Secure, HttpOnly, SameSite |
| CORS misconfiguration | Medium / High | Wildcard origin, origin reflection with credentials |
| Exposed paths | Low / Medium | .git, .env, admin panels, debug endpoints, backups |

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python -m vulnscan.cli https://example.com

# JSON output
python -m vulnscan.cli https://example.com --json
```

## Example output

```
Target: https://example.com  [200]
Findings: 0 high  3 medium  2 low

[MEDIUM]   Strict-Transport-Security
           Missing HSTS — forces HTTPS
[MEDIUM]   Content-Security-Policy
           Missing — XSS protection weakened
[LOW]      Server
           Exposes server software and version: Apache/2.4.41
```

## Project structure

```
vulnscan/
├── vulnscan/
│   ├── scanner.py       — orchestrates all checks
│   ├── cli.py           — argument parsing and report output
│   └── checks/
│       ├── headers.py   — security and info disclosure headers
│       ├── cookies.py   — cookie flag analysis
│       ├── cors.py      — CORS misconfiguration
│       └── directories.py — common exposed paths
└── requirements.txt
```

## Roadmap

- [ ] XSS reflection detection
- [ ] SQL injection basic probing
- [ ] Subdomain enumeration
- [ ] HTML report output
- [ ] Rate limiting / delay between requests
- [ ] Auth support (Bearer token, Basic auth)
