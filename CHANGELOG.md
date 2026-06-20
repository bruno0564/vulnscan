# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Clickjacking check: flags framable pages, considering **both** `X-Frame-Options`
  and the modern CSP `frame-ancestors` directive (so a CSP-protected site is not
  a false positive). `X-Frame-Options` moved here out of the generic headers check.
- Dangerous HTTP methods check: reads the `Allow` header via `OPTIONS` and flags
  PUT/DELETE/TRACE/TRACK/CONNECT/PATCH. Non-destructive — never issues them.
- Open redirect check: injects an attacker-controlled URL into common redirect
  parameters (`next`, `url`, `redirect`…) and flags 3xx responses that bounce to
  an external host.
- TLS / certificate check: opens a TLS connection and reports expired/expiring
  certificates, verification failures (self-signed, hostname mismatch) and
  obsolete protocol versions (SSLv3 / TLS 1.0 / 1.1). Evaluation logic is split
  from the socket so it's unit-tested without real network.
- security.txt check: reports a missing `/.well-known/security.txt` (RFC 9116).
- HTML report output: `--html FILE` writes a self-contained, styled report
  (inline CSS, severity badges, summary). All dynamic content is HTML-escaped —
  a scanner must not inject the very payloads it finds into its own report.
- Subdomain enumeration check: resolves a wordlist of common subdomains
  (api, dev, staging, admin…) against the target domain via DNS and reports the
  live ones as LOW. Honours `--delay`.
- Error-based SQL injection check: injects a quote into each query parameter
  and flags DB error signatures (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) that
  weren't already present in the baseline response. Reports HIGH.
- Reflected XSS check: injects a unique marker into each query parameter and
  flags it when the metacharacters come back unescaped in the response body.
  Detection of reflection (not execution), so it reports MEDIUM.
- Authentication: `--bearer`, `--basic user:pass` and repeatable `--header
  'Name: value'`. Credentials are baked into the `requests.Session` up front
  (new `auth.build_session`), so every request — main page and probes — carries
  them.
- Rate limiting: `--delay` waits N seconds between requests and `--timeout`
  caps each request. Both flow through a new `ScanContext.request()` helper —
  a single choke point used by every check that makes extra HTTP calls.
- Packaging via `pyproject.toml` with a `vulnscan` console entry point.
- Quality tooling: ruff (lint + format), mypy (strict), pytest with coverage.
- `pre-commit` hooks and a GitHub Actions CI workflow.
- Full type annotations across the codebase (`Finding`/`ScanResult` TypedDicts).
- `Severity` enum replacing magic severity strings.
- Pluggable **check registry** (`@register` + `ScanContext`): new checks are
  discovered automatically without modifying the scanner.
- Test suite with mocked HTTP (`responses`).
- Project docs: `LICENSE` (MIT), `CONTRIBUTING.md`, `.editorconfig`, issue/PR
  templates.

### Changed
- Checks now share a uniform signature `(ScanContext) -> list[Finding]`.
- Network errors are caught as specific `requests.RequestException` instead of
  bare `except Exception`.

### Fixed
- Exposed-paths check no longer floods false positives on catch-all / soft-404
  servers that answer 200 to everything: it now probes a random nonexistent path
  as a baseline and only reports paths whose response differs from it.
- Cookie check: `HttpOnly`/`SameSite` are matched case-insensitively (RFC 6265).
  The previous case-sensitive lookup reported false positives against servers
  sending the flags in lowercase.
- Subdomain enumeration check is now actually registered, so it runs as part of
  a scan (it was implemented but never wired into the registry).

## [0.1.0] - initial

### Added
- Initial scanner with checks for security headers, cookie flags, CORS
  misconfiguration and exposed paths. CLI with coloured and JSON output.
