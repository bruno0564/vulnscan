"""Construcción de la sesión HTTP, con autenticación opcional.

El escáner trabaja sobre una `requests.Session`; aquí se centraliza cómo se
crea y qué cabeceras de autenticación lleva, para que `scanner.py` no tenga que
saber nada de tokens ni de Basic auth. La CLL construye la sesión y se la pasa a
`scan(session=...)`.
"""

import base64
from collections.abc import Iterable

import requests

USER_AGENT = "vulnscan/0.1 (security scanner)"


def build_session(
    *,
    bearer: str | None = None,
    basic: str | None = None,
    headers: Iterable[str] = (),
) -> requests.Session:
    """Crea una sesión con el User-Agent del escáner y la autenticación indicada.

    - `bearer`: token para `Authorization: Bearer <token>`.
    - `basic`: cadena `usuario:contraseña` para `Authorization: Basic <b64>`.
    - `headers`: cabeceras sueltas en formato `Nombre: valor` (p.ej. una cookie
      de sesión o un API key propietario).

    Lanza `ValueError` si algún valor está mal formado; la CLI lo traduce a un
    error de uso legible.
    """
    if bearer and basic:
        raise ValueError("use either --bearer or --basic, not both")

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    if bearer:
        session.headers["Authorization"] = f"Bearer {bearer}"

    if basic:
        if ":" not in basic:
            raise ValueError("--basic expects 'user:password'")
        token = base64.b64encode(basic.encode()).decode()
        session.headers["Authorization"] = f"Basic {token}"

    for raw in headers:
        if ":" not in raw:
            raise ValueError(f"invalid --header {raw!r}, expected 'Name: value'")
        name, _, value = raw.partition(":")
        name = name.strip()
        if not name:
            raise ValueError(f"invalid --header {raw!r}, header name is empty")
        session.headers[name] = value.strip()

    return session
