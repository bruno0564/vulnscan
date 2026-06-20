"""Orquestador del escaneo: hace la petición principal y ejecuta los checks.

No conoce los checks concretos: los descubre desde el registro (`all_checks`),
de modo que añadir uno nuevo no requiere modificar este archivo.

Los checks son independientes entre sí (cada uno recibe el mismo `ScanContext`
de solo lectura y devuelve su lista de hallazgos), así que se pueden ejecutar en
paralelo. La mayoría del tiempo de un escaneo se va en esperar I/O de red, donde
los hilos rinden bien pese al GIL.
"""

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

from .auth import USER_AGENT
from .checks import Check, ScanContext, all_checks
from .types import SEVERITY_ORDER, Finding, ScanResult, Severity, Summary


def _run_checks(checks: list[Check], ctx: ScanContext, workers: int) -> list[Finding]:
    """Ejecuta los checks (en paralelo si procede) y concatena sus hallazgos.

    El resultado es DETERMINISTA: se preserva el orden de registro de los checks
    sin importar en qué orden terminen los hilos, recolectando cada lista en su
    posición y aplanando al final. Así dos escaneos del mismo objetivo producen
    exactamente el mismo informe, con uno o con varios workers.
    """
    if workers <= 1 or len(checks) <= 1:
        return [finding for check in checks for finding in check(ctx)]

    per_check: list[list[Finding]] = [[] for _ in checks]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check, ctx): i for i, check in enumerate(checks)}
        for future in futures:
            per_check[futures[future]] = future.result()
    return [finding for group in per_check for finding in group]


def scan(
    url: str,
    *,
    timeout: float = 8.0,
    delay: float = 0.0,
    workers: int = 8,
    session: requests.Session | None = None,
) -> ScanResult:
    if not urlparse(url).scheme:
        url = "https://" + url

    if session is None:
        session = requests.Session()
        session.headers["User-Agent"] = USER_AGENT

    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        return {"error": str(e), "url": url, "findings": []}

    ctx = ScanContext(
        url=url,
        session=session,
        response=response,
        timeout=timeout,
        delay=delay,
    )

    # Con `--delay` el usuario pide ir despacio por cortesía; paralelizar
    # multiplicaría el ritmo real de peticiones y lo contradiría. En ese caso
    # forzamos ejecución secuencial.
    effective_workers = 1 if delay > 0 else workers
    findings = _run_checks(all_checks(), ctx, effective_workers)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    summary: Summary = {
        "high": sum(1 for f in findings if f["severity"] == Severity.HIGH),
        "medium": sum(1 for f in findings if f["severity"] == Severity.MEDIUM),
        "low": sum(1 for f in findings if f["severity"] == Severity.LOW),
    }

    return {
        "url": response.url,
        "status": response.status_code,
        "findings": findings,
        "summary": summary,
    }
