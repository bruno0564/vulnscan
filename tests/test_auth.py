"""Tests de la construcción de sesión autenticada (auth.build_session)."""

import base64

import pytest

from vulnscan.auth import USER_AGENT, build_session


def test_default_session_has_user_agent_and_no_auth() -> None:
    session = build_session()
    assert session.headers["User-Agent"] == USER_AGENT
    assert "Authorization" not in session.headers


def test_bearer_sets_authorization_header() -> None:
    session = build_session(bearer="abc123")
    assert session.headers["Authorization"] == "Bearer abc123"


def test_basic_is_base64_encoded() -> None:
    session = build_session(basic="admin:s3cret")
    expected = base64.b64encode(b"admin:s3cret").decode()
    assert session.headers["Authorization"] == f"Basic {expected}"


def test_basic_without_colon_is_rejected() -> None:
    with pytest.raises(ValueError, match="user:password"):
        build_session(basic="noseparator")


def test_bearer_and_basic_are_mutually_exclusive() -> None:
    with pytest.raises(ValueError, match="not both"):
        build_session(bearer="x", basic="a:b")


def test_custom_headers_are_added_and_trimmed() -> None:
    session = build_session(headers=["Cookie: session=abc", "X-Api-Key:  key123  "])
    assert session.headers["Cookie"] == "session=abc"
    assert session.headers["X-Api-Key"] == "key123"


def test_malformed_header_is_rejected() -> None:
    with pytest.raises(ValueError, match="Name: value"):
        build_session(headers=["no-colon-here"])


def test_empty_header_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="name is empty"):
        build_session(headers=[": value"])
