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


def _counts_block(findings: list[Finding], key) -> list[str]:
    counts: dict[str, int] = {}
    for finding in findings:
        name = key(finding)
        counts[name] = counts.get(name, 0) + 1
    width = max(len(name) for name in counts)
    return [
        f"  {name.ljust(width)}  {counts[name]}"
        for name in sorted(counts, key=lambda n: (-counts[n], n))
    ]


def render_summary(findings: list[Finding], stream=None) -> str:
    color = bool(stream and hasattr(stream, "isatty") and stream.isatty())
    if not findings:
        return "No findings.\n"
    lines = ["BY RULE"]
    lines.extend(_counts_block(findings, lambda f: f.rule_id))
    lines.append("")
    lines.append("BY SEVERITY")
    lines.extend(_counts_block(findings, lambda f: f.severity))
    lines.append("")
    lines.append("BY FILE")
    top = _counts_block(findings, lambda f: f.file)
    lines.extend(top[:20])
    if len(top) > 20:
        lines.append(f"  ... {len(top) - 20} more file(s)")
    lines.append("")
    sinks: dict[tuple, list[Finding]] = {}
    for finding in findings:
        sinks.setdefault((finding.rule_id, finding.file, finding.line, finding.col), []).append(finding)
    width_severity = max(len(f.severity) for f in findings)
    width_rule = max(len(f.rule_id) for f in findings)
    for (rule_id, file, line, col), group in sinks.items():
        finding = group[0]
        hops = max(len(f.path) for f in group)
        trail = f"  ({hops} hops)" if hops > 2 else ""
        entries = f"  x{len(group)} entry points" if len(group) > 1 else ""
        lines.append(
            "  ".join(
                [
                    _paint(
                        finding.severity.upper().ljust(width_severity),
                        COLORS.get(finding.severity, ""),
                        color,
                    ),
                    rule_id.ljust(width_rule),
                    f"{file}:{line}:{col}" + trail + entries,
                ]
            )
        )
    lines.append("")
    lines.append(
        f"{len(sinks)} sink(s) in {len(set(f.file for f in findings))} file(s), "
        f"{len(findings)} finding(s) counting entry points"
    )
    return "\n".join(lines) + "\n"


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
