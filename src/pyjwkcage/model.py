"""Immutable audit result types."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

from .errors import JwkCageError

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2, "critical": 3}


@dataclass(frozen=True)
class Finding:
    """One machine readable audit finding."""

    code: str
    message: str
    field: Optional[str] = None
    key_index: Optional[int] = None
    severity: str = "error"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError("unknown finding severity")
        if not self.code or not isinstance(self.code, str):
            raise ValueError("finding code must be a non-empty string")
        if not self.message or not isinstance(self.message, str):
            raise ValueError("finding message must be a non-empty string")

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
        if self.field is not None:
            result["field"] = self.field
        if self.key_index is not None:
            result["key_index"] = self.key_index
        return result


@dataclass(frozen=True)
class AuditReport:
    """Result returned by audit functions."""

    subject: str
    findings: Tuple[Finding, ...]
    details: Tuple[Tuple[str, Any], ...] = ()

    @property
    def ok(self) -> bool:
        return not any(
            SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER["error"]
            for finding in self.findings
        )

    @property
    def error_codes(self) -> Tuple[str, ...]:
        return tuple(
            finding.code
            for finding in self.findings
            if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER["error"]
        )

    def raise_for_errors(self) -> None:
        for finding in self.findings:
            if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER["error"]:
                raise JwkCageError(finding.code, finding.message, finding.field)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "ok": self.ok,
            "findings": [finding.to_dict() for finding in self.findings],
            "error_codes": list(self.error_codes),
            "details": dict(self.details),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def make_findings(items: Iterable[Finding]) -> Tuple[Finding, ...]:
    return tuple(items)


def make_report(subject: str, findings: Iterable[Finding], **details: Any) -> AuditReport:
    safe_details = []
    for name in sorted(details):
        value = details[name]
        if isinstance(value, (str, int, bool)) or value is None:
            safe_details.append((name, value))
        elif isinstance(value, (tuple, list)) and all(isinstance(item, (str, int, bool)) for item in value):
            safe_details.append((name, tuple(value)))
        else:
            safe_details.append((name, str(type(value).__name__)))
    return AuditReport(subject=subject, findings=make_findings(findings), details=tuple(safe_details))


__all__ = ["AuditReport", "Finding", "SEVERITY_ORDER", "make_report"]
