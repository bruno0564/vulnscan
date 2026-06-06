# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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

## [0.1.0] - initial

### Added
- Initial scanner with checks for security headers, cookie flags, CORS
  misconfiguration and exposed paths. CLI with coloured and JSON output.
