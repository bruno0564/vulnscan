"""Exporta un `ScanResult` a SARIF 2.1.0.

SARIF (Static Analysis Results Interchange Format) es el formato estándar que
entiende GitHub Code Scanning: si subes este JSON con
`github/codeql-action/upload-sarif`, los hallazgos aparecen como alertas en la
pestaña *Security* del repositorio, con su nivel de gravedad.

Mapeo de gravedad a nivel SARIF:
    high -> error    medium -> warning    low -> note
"""

import json
from importlib.metadata import PackageNotFoundError, version

from .types import Finding, ScanResult

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_URI = "https://github.com/bruno0564/vulnscan"
_LEVEL: dict[str, str] = {"high": "error", "medium": "warning", "low": "note"}


def _tool_version() -> str:
    try:
        return version("vulnscan")
    except PackageNotFoundError:  # pragma: no cover - solo si no está instalado
        return "0.0.0"


def _rule_name(rule_id: str) -> str:
    """`missing_header` -> `Missing Header`, para mostrarlo legible."""
    return rule_id.replace("_", " ").title()


def _level(finding: Finding) -> str:
    return _LEVEL.get(finding.get("severity", ""), "warning")


def render_sarif(result: ScanResult) -> str:
    """Serializa el resultado de un escaneo a un documento SARIF 2.1.0 (JSON)."""
    findings = result.get("findings", [])
    target = result.get("url", "")

    # Un "rule" SARIF por cada tipo de hallazgo distinto, en orden de aparición.
    # SARIF pide declarar las reglas una vez y que cada resultado las referencie.
    rule_index: dict[str, int] = {}
    rules: list[dict[str, object]] = []
    for finding in findings:
        rule_id = finding.get("type", "finding")
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "name": _rule_name(rule_id),
                    "shortDescription": {"text": _rule_name(rule_id)},
                    "defaultConfiguration": {"level": _level(finding)},
                }
            )

    results: list[dict[str, object]] = []
    for finding in findings:
        rule_id = finding.get("type", "finding")
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": _level(finding),
                "message": {"text": finding.get("detail") or _rule_name(rule_id)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": target}}}],
            }
        )

    document = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnscan",
                        "informationUri": _TOOL_URI,
                        "version": _tool_version(),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
