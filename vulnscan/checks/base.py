"""Infraestructura común de los checks: contexto y registro.

Cada check es una función con la misma firma — `(ScanContext) -> list[Finding]` —
y se da de alta con el decorador `@register`. El scanner los descubre llamando a
`all_checks()`, así que añadir un check nuevo NO requiere tocar el scanner:
basta con crear el módulo, decorar la función e importarlo en `checks/__init__.py`.
"""

from collections.abc import Callable
from dataclasses import dataclass

import requests

from ..types import Finding


@dataclass(frozen=True)
class ScanContext:
    """Todo lo que un check necesita para ejecutarse.

    Se construye una sola vez por escaneo y se pasa a cada check, evitando que
    cada uno tenga que volver a pedir la respuesta principal o crear sesiones.
    """

    url: str
    session: requests.Session
    response: requests.Response


# Firma que debe cumplir todo check.
Check = Callable[[ScanContext], list[Finding]]

_REGISTRY: list[Check] = []


def register(check: Check) -> Check:
    """Decorador que da de alta un check en el registro global."""
    _REGISTRY.append(check)
    return check


def all_checks() -> list[Check]:
    """Devuelve una copia de los checks registrados, en orden de registro."""
    return list(_REGISTRY)
