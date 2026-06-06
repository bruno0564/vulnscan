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
│   ├── types.py          — Severity, Finding, ScanResult
│   └── checks/
│       ├── base.py       — ScanContext + @register registry
│       ├── headers.py    — security and info disclosure headers
│       ├── cookies.py    — cookie flag analysis
│       ├── cors.py       — CORS misconfiguration
│       └── directories.py — common exposed paths
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

- [ ] XSS reflection detection
- [ ] SQL injection basic probing
- [ ] Subdomain enumeration
- [ ] HTML report output
- [ ] Rate limiting / delay between requests
- [ ] Auth support (Bearer token, Basic auth)
