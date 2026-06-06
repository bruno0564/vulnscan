"""Tests del registro de checks — el contrato que hace el proyecto escalable."""

import vulnscan.checks as checks


def test_all_known_checks_are_registered() -> None:
    names = {fn.__name__ for fn in checks.all_checks()}
    assert {
        "check_headers",
        "check_cookies",
        "check_cors",
        "check_directories",
    } <= names


def test_register_adds_and_returns_the_check() -> None:
    before = len(checks.all_checks())

    @checks.register
    def _dummy_check(ctx: checks.ScanContext) -> list:  # type: ignore[type-arg]
        return []

    after = checks.all_checks()
    assert len(after) == before + 1
    assert _dummy_check in after
