from __future__ import annotations

import io
import tokenize
from dataclasses import dataclass

from .analyzers.base import Finding
from .rules import Rule, match_glob

MARKERS = ("taintscan:", "codity:")
ACTION = "ignore"

NO_REASON_RULE = Rule(
    id="taintscan.suppression-without-reason",
    severity="low",
    cwe="CWE-1164",
    message="Suppression comment has no reason text",
    kind="meta",
    spec={},
)


@dataclass(frozen=True)
class Suppression:
    line: int
    col: int
    own_line: bool
    rule_ids: tuple[str, ...]
    reason: str
    raw: str


def _parse_comment(text: str) -> tuple[tuple[str, ...], str] | None:
    body = text.lstrip("#").strip()
    marker = next((m for m in MARKERS if body.startswith(m)), None)
    if marker is None:
        return None
    body = body[len(marker) :].strip()
    if not body.startswith(ACTION):
        return None
    body = body[len(ACTION) :]
    rule_ids: tuple[str, ...] = ()
    if body.startswith("["):
        end = body.find("]")
        if end == -1:
            return None
        rule_ids = tuple(
            part.strip() for part in body[1:end].split(",") if part.strip()
        )
        body = body[end + 1 :]
    return rule_ids, body.strip(" :-\t")


def parse_suppressions(source: str) -> list[Suppression]:
    out: list[Suppression] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            parsed = _parse_comment(token.string)
            if parsed is None:
                continue
            rule_ids, reason = parsed
            out.append(
                Suppression(
                    line=token.start[0],
                    col=token.start[1] + 1,
                    own_line=not token.line[: token.start[1]].strip(),
                    rule_ids=rule_ids,
                    reason=reason,
                    raw=token.string.strip(),
                )
            )
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return out
    return out


def _covers(suppression: Suppression, finding: Finding) -> bool:
    if suppression.own_line:
        if suppression.line + 1 != finding.line:
            return False
    elif not (finding.line <= suppression.line <= max(finding.line, finding.end_line)):
        return False
    if not suppression.rule_ids:
        return True
    return any(match_glob(pattern, finding.rule_id) for pattern in suppression.rule_ids)


def apply_suppressions(
    findings: list[Finding], source: str, rel_path: str, lines: tuple[str, ...]
) -> list[Finding]:
    suppressions = parse_suppressions(source)
    if not suppressions:
        return findings
    kept: list[Finding] = []
    used: set[int] = set()
    for finding in findings:
        hit = next((s for s in suppressions if _covers(s, finding)), None)
        if hit is None:
            kept.append(finding)
        else:
            used.add(hit.line)
    for suppression in suppressions:
        if suppression.reason:
            continue
        snippet = lines[suppression.line - 1].strip() if suppression.line <= len(lines) else ""
        kept.append(
            Finding(
                rule_id=NO_REASON_RULE.id,
                severity=NO_REASON_RULE.severity,
                cwe=NO_REASON_RULE.cwe,
                message=NO_REASON_RULE.message,
                file=rel_path,
                line=suppression.line,
                col=suppression.col,
                end_line=suppression.line,
                end_col=suppression.col + len(suppression.raw),
                signature=f"suppression|{suppression.raw}",
                snippet=snippet,
            )
        )
    return kept
