# Contributing to vulnscan

Thanks for your interest in improving vulnscan! This guide gets you from zero to
a merged pull request.

## Development setup

```bash
git clone https://github.com/bruno0564/vulnscan
cd vulnscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install          # installs the git hooks (ruff + mypy on every commit)
```

## Quality gates

Every change must pass the same checks CI runs. Run them locally before pushing:

```bash
ruff check vulnscan/ tests/        # lint
ruff format vulnscan/ tests/       # format
mypy vulnscan/ tests/              # static types (strict)
pytest                             # tests + coverage
```

The pre-commit hooks run ruff and mypy automatically on `git commit`, so a dirty
commit is blocked before it ever leaves your machine.

## Project layout

```
vulnscan/
├── cli.py        — CLI entry point and report rendering
├── scanner.py    — orchestrator: fetches the page and runs every registered check
├── types.py      — shared types: Severity, Finding, ScanResult
└── checks/
    ├── base.py   — ScanContext + the @register registry
    └── *.py      — one module per check, self-registered
```

## Adding a new check (the important part)

The scanner discovers checks through a **registry**, so you never edit
`scanner.py` to add one. Three steps:

1. Create `vulnscan/checks/your_check.py`:

   ```python
   from ..types import Finding, Severity
   from .base import ScanContext, register


   @register
   def check_your_thing(ctx: ScanContext) -> list[Finding]:
       findings: list[Finding] = []
       # ctx.response  -> the main page response
       # ctx.session   -> a requests.Session for extra requests
       # ctx.url       -> the normalised target URL
       ...
       return findings
   ```

2. Register the module for import in `vulnscan/checks/__init__.py`:

   ```python
   from . import cookies, cors, directories, headers, your_check  # noqa: F401
   ```

3. Add tests in `tests/test_your_check.py` (mock HTTP with `responses`, never hit
   the real network).

That's it — the scanner picks it up automatically.

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
`fix:`, `refactor:`, `test:`, `chore:`, `docs:`. One logical change per commit.

## Ethics & scope

vulnscan is for **authorised** security testing and education only. Only scan
systems you own or have explicit permission to test.
