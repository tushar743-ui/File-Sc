from __future__ import annotations

import sys

from ..analyzers.base import SEVERITY_ORDER, Finding

COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
}
DIM = "\033[2m"
RESET = "\033[0m"


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def render(findings: list[Finding], stream=None) -> str:
    color = bool(stream and hasattr(stream, "isatty") and stream.isatty())
    if not findings:
        return "No findings.\n"

    rows = [
        (
            finding.severity.upper(),
            finding.rule_id,
            f"{finding.file}:{finding.line}:{finding.col}",
            finding,
        )
        for finding in findings
    ]
    width_severity = max(len(row[0]) for row in rows)
    width_rule = max(len(row[1]) for row in rows)
    width_location = max(len(row[2]) for row in rows)

    lines = [
        "  ".join(
            [
                "SEVERITY".ljust(width_severity),
                "RULE".ljust(width_rule),
                "LOCATION".ljust(width_location),
                "MESSAGE",
            ]
        ),
        "  ".join(
            [
                "-" * width_severity,
                "-" * width_rule,
                "-" * width_location,
                "-" * 40,
            ]
        ),
    ]

    for severity, rule_id, place, finding in rows:
        lines.append(
            "  ".join(
                [
                    _paint(severity.ljust(width_severity), COLORS.get(finding.severity, ""), color),
                    rule_id.ljust(width_rule),
                    place.ljust(width_location),
                    finding.message,
                ]
            )
        )
        for index, step in enumerate(finding.path):
            arrow = "entry" if index == 0 else ("sink " if index == len(finding.path) - 1 else "step ")
            detail = f"      {arrow} {step.file}:{step.line}  {step.label}"
            lines.append(_paint(detail, DIM, color))
            if step.snippet:
                lines.append(_paint(f"            {step.snippet}", DIM, color))
        lines.append("")

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(
        f"{counts[key]} {key}"
        for key in sorted(counts, key=lambda s: -SEVERITY_ORDER.get(s, 0))
    )
    lines.append(f"{len(findings)} finding(s): {summary}")
    return "\n".join(lines) + "\n"
