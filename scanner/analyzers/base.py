from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Iterable, Iterator

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_TO_SARIF = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


@dataclass(frozen=True, order=True)
class Step:
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    label: str
    snippet: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    cwe: str
    message: str
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    signature: str
    path: tuple[Step, ...] = ()
    snippet: str = ""
    fingerprint: str = ""

    @property
    def sort_key(self) -> tuple:
        return (self.file, self.line, self.col, self.rule_id, self.signature)

    def with_fingerprint(self, value: str) -> "Finding":
        return replace(self, fingerprint=value)


class AbstractAnalyzer:
    kind = ""

    def __init__(self, rules: list, context) -> None:
        self.rules = rules
        self.context = context

    def analyze(self, module) -> Iterator[Finding]:
        raise NotImplementedError


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key)


def meets_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)
