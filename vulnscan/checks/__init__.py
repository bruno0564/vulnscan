"""Paquete de checks.

Importa cada módulo de check para que su decorador `@register` se ejecute y el
check quede dado de alta en el registro. Añadir un check nuevo = crear el módulo
y añadir su import aquí.
"""

from . import (  # noqa: F401  (import con efecto: registro)
    clickjacking,
    cookies,
    cors,
    directories,
    headers,
    methods,
    redirects,
    security_txt,
    sqli,
    subdomains,
    tls,
    xss,
)
from .base import Check, ScanContext, all_checks, register

__all__ = ["Check", "ScanContext", "all_checks", "register"]
