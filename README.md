# vulnscan

Web vulnerability scanner built from scratch in Python. Checks for common misconfigurations and security issues without relying on third-party scanning frameworks.

## What it checks

| Check | Severity | Description |
|---|---|---|
| Security headers | Medium | HSTS, CSP, X-Content-Type-Options, Referrer-Policy, etc. |
| Info disclosure headers | Low | Server, X-Powered-By, X-AspNet-Version |
| Cookie flags | Medium | Secure, HttpOnly, SameSite (case-insensitive, RFC 6265) |
| CORS misconfiguration | Medium / High | Wildcard origin, origin reflection with credentials |
| Clickjacking | Medium | Framable page — no X-Frame-Options and no CSP frame-ancestors |
| Dangerous HTTP methods | Medium | PUT, DELETE, TRACE/TRACK, CONNECT, PATCH advertised via OPTIONS |
| Open redirect | Medium | Redirect params (next, url…) that bounce to an external host |
| Exposed paths | Low / Medium | .git, .env, admin panels, debug endpoints, backups |
| Reflected XSS | Medium | Query params echoed back into the page unescaped |
| SQL injection | High | DB error signatures triggered by injecting a quote into params |
| TLS / certificate | Medium / High | Expired/expiring cert, failed verification, obsolete protocol |
| security.txt | Low | Missing /.well-known/security.txt (RFC 9116) |
| Subdomains | Low | Common subdomains (api, dev, staging…) that resolve via DNS |

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # installs the `vulnscan` command
```

For development (linting, types, tests) install the dev extras instead:

```bash
pip install -e ".[dev]"
pre-commit install
```

## Usage

```bash
# Basic scan
vulnscan https://example.com

# JSON output
vulnscan https://example.com --json

# Checks run concurrently by default (8 workers); tune or serialise it
vulnscan https://example.com --workers 16
vulnscan https://example.com --workers 1          # fully sequential

# Be polite: wait 0.5s between requests and cap each request at 5s
# (--delay forces sequential execution so the pacing is actually respected)
vulnscan https://example.com --delay 0.5 --timeout 5

# Scan behind authentication
vulnscan https://example.com --bearer "$TOKEN"
vulnscan https://example.com --basic admin:s3cret
vulnscan https://example.com --header "Cookie: session=abc123"

# Write a self-contained HTML report
vulnscan https://example.com --html report.html
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

## Architecture

Checks are **pluggable**. Each one is a small function registered with
`@register`, and the scanner discovers them through a registry — so adding a
check never requires touching `scanner.py`.

```
vulnscan/
├── vulnscan/
│   ├── cli.py            — argument parsing and report output
│   ├── scanner.py        — fetches the page, runs every registered check
│   ├── auth.py           — builds the HTTP session (Bearer / Basic / headers)
│   ├── report.py         — self-contained HTML report rendering
│   ├── types.py          — Severity, Finding, ScanResult
│   └── checks/
│       ├── base.py       — ScanContext (+ throttled request) + @register registry
│       ├── headers.py    — security and info disclosure headers
│       ├── cookies.py    — cookie flag analysis
│       ├── cors.py       — CORS misconfiguration
│       ├── clickjacking.py — X-Frame-Options / CSP frame-ancestors
│       ├── methods.py    — dangerous HTTP methods (OPTIONS/Allow)
│       ├── redirects.py  — open redirect probing
│       ├── directories.py — common exposed paths
│       ├── xss.py         — reflected XSS probing
│       ├── sqli.py        — error-based SQL injection probing
│       ├── tls.py         — certificate validity / protocol version
│       ├── security_txt.py — RFC 9116 security.txt presence
│       └── subdomains.py  — DNS subdomain enumeration
├── tests/                — pytest suite (HTTP mocked, no real network)
└── pyproject.toml        — packaging + ruff/mypy/pytest config
```

Want to add a check? See [CONTRIBUTING.md](CONTRIBUTING.md) — it's three steps.

## Development

```bash
ruff check vulnscan/ tests/    # lint
mypy vulnscan/ tests/          # static types (strict)
pytest                         # tests + coverage
```

## Roadmap

- [x] XSS reflection detection
- [x] SQL injection basic probing
- [x] Subdomain enumeration
- [x] HTML report output
- [x] Rate limiting / delay between requests
- [x] Auth support (Bearer token, Basic auth)
