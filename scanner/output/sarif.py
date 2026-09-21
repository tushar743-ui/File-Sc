from __future__ import annotations

import json
from pathlib import Path

from ..analyzers.base import SEVERITY_TO_SARIF, Finding
from ..baseline import FINGERPRINT_KEY
from ..rules import Rule
from ..suppression import NO_REASON_RULE

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
TOOL_NAME = "codity-scanner"
TOOL_URI = "https://github.com/codity/scanner"
SRCROOT = "%SRCROOT%"

SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def _uri(path: str) -> str:
    return Path(path).as_posix()


def _region(finding_or_step) -> dict:
    region = {
        "startLine": max(1, finding_or_step.line),
        "startColumn": max(1, finding_or_step.col),
        "endLine": max(1, finding_or_step.end_line),
        "endColumn": max(1, finding_or_step.end_col),
    }
    snippet = getattr(finding_or_step, "snippet", "")
    if snippet:
        region["snippet"] = {"text": snippet}
    return region


def _physical(path: str, item) -> dict:
    return {
        "artifactLocation": {"uri": _uri(path), "uriBaseId": SRCROOT},
        "region": _region(item),
    }


def _rule_descriptor(rule: Rule) -> dict:
    tags = ["security"]
    if rule.cwe:
        number = rule.cwe.split("-")[-1]
        tags.append(f"external/cwe/cwe-{number}")
    descriptor = {
        "id": rule.id,
        "shortDescription": {"text": rule.message},
        "fullDescription": {"text": rule.message},
        "defaultConfiguration": {"level": SEVERITY_TO_SARIF.get(rule.severity, "warning")},
        "properties": {
            "tags": tags,
            "precision": "high",
            "problem.severity": rule.severity,
            "security-severity": SECURITY_SEVERITY.get(rule.severity, "5.0"),
        },
    }
    if rule.cwe:
        descriptor["properties"]["cwe"] = rule.cwe
        descriptor["help"] = {
            "text": f"{rule.message} ({rule.cwe})",
            "markdown": f"{rule.message}\n\nSee [{rule.cwe}](https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[-1]}.html).",
        }
    return descriptor


def _code_flows(finding: Finding) -> list:
    if len(finding.path) < 2:
        return []
    locations = []
    for order, step in enumerate(finding.path):
        locations.append(
            {
                "location": {
                    "physicalLocation": _physical(step.file, step),
                    "message": {"text": step.label},
                },
                "nestingLevel": 0,
                "executionOrder": order,
            }
        )
    return [{"threadFlows": [{"locations": locations}]}]


def build_sarif(findings: list[Finding], rules: list[Rule], root: str) -> dict:
    known = list(rules)
    if any(f.rule_id == NO_REASON_RULE.id for f in findings):
        known = known + [NO_REASON_RULE]
    descriptors = [_rule_descriptor(rule) for rule in known]
    index_of = {rule.id: position for position, rule in enumerate(known)}

    results = []
    for finding in findings:
        result = {
            "ruleId": finding.rule_id,
            "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [{"physicalLocation": _physical(finding.file, finding)}],
        }
        if finding.rule_id in index_of:
            result["ruleIndex"] = index_of[finding.rule_id]
        if finding.fingerprint:
            result["partialFingerprints"] = {FINGERPRINT_KEY: finding.fingerprint}
        flows = _code_flows(finding)
        if flows:
            result["codeFlows"] = flows
        results.append(result)

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "semanticVersion": _version(),
                        "version": _version(),
                        "rules": descriptors,
                    }
                },
                "originalUriBaseIds": {
                    SRCROOT: {"uri": Path(root).resolve().as_uri() + "/"}
                },
                "columnKind": "unicodeCodePoints",
                "results": results,
            }
        ],
    }


def _version() -> str:
    from .. import __version__

    return __version__


def render(findings: list[Finding], rules: list[Rule], root: str) -> str:
    return json.dumps(build_sarif(findings, rules, root), indent=2, sort_keys=True) + "\n"
