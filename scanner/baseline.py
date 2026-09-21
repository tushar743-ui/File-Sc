from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .analyzers.base import Finding, sort_findings

BASELINE_VERSION = 1
FINGERPRINT_KEY = "taintscanFindingId/v1"


def _digest(*parts: str) -> str:
    joined = "\x00".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]


def scoped_fingerprint(finding: Finding, ordinal: int) -> str:
    return _digest(finding.rule_id, finding.file, finding.signature, str(ordinal))


def floating_fingerprint(finding: Finding, ordinal: int) -> str:
    return _digest(finding.rule_id, finding.signature, str(ordinal))


def assign_fingerprints(findings: list[Finding]) -> list[Finding]:
    counters: dict[tuple, int] = {}
    out: list[Finding] = []
    for finding in sort_findings(findings):
        key = (finding.rule_id, finding.file, finding.signature)
        ordinal = counters.get(key, 0)
        counters[key] = ordinal + 1
        out.append(finding.with_fingerprint(scoped_fingerprint(finding, ordinal)))
    return out


def build_baseline(findings: list[Finding]) -> dict:
    counters: dict[tuple, int] = {}
    entries = []
    for finding in sort_findings(findings):
        key = (finding.rule_id, finding.file, finding.signature)
        ordinal = counters.get(key, 0)
        counters[key] = ordinal + 1
        entries.append(
            {
                "id": scoped_fingerprint(finding, ordinal),
                "floating": floating_fingerprint(finding, ordinal),
                "rule": finding.rule_id,
                "file": finding.file,
            }
        )
    return {"version": BASELINE_VERSION, "findings": entries}


def load_baseline(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise ValueError(f"{path}: unsupported baseline format")
    return data


def filter_new(findings: list[Finding], baseline: dict, scanned_files: set[str]) -> list[Finding]:
    entries = baseline.get("findings", [])
    known = {entry["id"] for entry in entries}
    moved = {
        entry["floating"]
        for entry in entries
        if entry.get("floating") and entry.get("file") not in scanned_files
    }
    counters: dict[tuple, int] = {}
    out: list[Finding] = []
    for finding in sort_findings(findings):
        key = (finding.rule_id, finding.file, finding.signature)
        ordinal = counters.get(key, 0)
        counters[key] = ordinal + 1
        if scoped_fingerprint(finding, ordinal) in known:
            continue
        if floating_fingerprint(finding, ordinal) in moved:
            continue
        out.append(finding)
    return out


def dumps(baseline: dict) -> str:
    return json.dumps(baseline, indent=2, sort_keys=True) + "\n"
