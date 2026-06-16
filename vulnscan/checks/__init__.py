"""Paquete de checks.

Importa cada módulo de check para que su decorador `@register` se ejecute y el
check quede dado de alta en el registro. Añadir un check nuevo = crear el módulo
y añadir su import aquí.
"""

from . import (  # noqa: F401  (import con efecto: registro)
    cookies,
    cors,
    directories,
    headers,
    sqli,
    xss,
)
from .base import ScanContext, all_checks, register

__all__ = ["ScanContext", "all_checks", "register"]
