import pytest
import yaml

from scanner.engine import ScanContext, build_analyzers
from scanner.rules import PatternIndex, PatternSpec, RuleError, match_dotted, parse_rules


def test_star_matches_exactly_one_segment():
    assert match_dotted("*.execute", "?.execute")
    assert match_dotted("flask.request.form.*", "flask.request.form.get")
    assert not match_dotted("*.execute", "a.b.execute")
    assert not match_dotted("os.system", "myapp.os.system")


def test_index_returns_every_matching_spec():
    index = PatternIndex([PatternSpec("*.execute", 0, "a"), PatternSpec("db.execute", 0, "b")])
    hits = index.lookup(("db.execute", "?.execute"))
    assert {spec.payload for spec in hits} == {"a", "b"}


def test_duplicate_rule_id_is_rejected():
    document = {
        "rules": [
            {"id": "x", "severity": "high", "message": "m", "kind": "pattern", "match": {}},
            {"id": "x", "severity": "low", "message": "m", "kind": "pattern", "match": {}},
        ]
    }
    with pytest.raises(RuleError, match="duplicate"):
        parse_rules(document)


def test_unknown_severity_is_rejected():
    document = {"rules": [{"id": "x", "severity": "spicy", "message": "m", "kind": "taint"}]}
    with pytest.raises(RuleError, match="severity"):
        parse_rules(document)


def test_unknown_kind_fails_at_analyzer_construction(tmp_path):
    rules = parse_rules({"rules": [{"id": "x", "severity": "low", "message": "m", "kind": "graph"}]})
    with pytest.raises(RuleError, match="unknown rule kind"):
        build_analyzers(rules, ScanContext(tmp_path, {}))


def test_a_new_kind_needs_only_a_registry_entry(tmp_path):
    from scanner.analyzers.base import AbstractAnalyzer
    from scanner.engine import KIND_REGISTRY

    class Counting(AbstractAnalyzer):
        kind = "counting"

        def analyze(self, module):
            return iter(())

    KIND_REGISTRY["counting"] = Counting
    try:
        rules = parse_rules(
            {"rules": [{"id": "c", "severity": "low", "message": "m", "kind": "counting"}]}
        )
        analyzers = build_analyzers(rules, ScanContext(tmp_path, {}))
        assert isinstance(analyzers[0], Counting)
    finally:
        del KIND_REGISTRY["counting"]


def test_shipped_rules_cover_the_required_classes(shipped_rules):
    ids = {rule.id for rule in shipped_rules}
    assert {
        "py.sql-injection",
        "py.command-injection",
        "py.path-traversal",
        "py.ssrf",
        "py.unsafe-html",
        "py.insecure-deserialization",
        "py.hardcoded-secret",
    } <= ids
    assert all(rule.cwe.startswith("CWE-") for rule in shipped_rules)


GUARDED = """
import os

from flask import request

from myapp.security import is_clean_host


def f():
    host = request.args.get("host", "")
    if not is_clean_host(host):
        return None
    os.system("ping " + host)
"""

GUARD_RULE = {
    "rules": [
        {
            "id": "py.command-injection",
            "severity": "critical",
            "cwe": "CWE-78",
            "message": "Untrusted input reaches a shell command",
            "kind": "taint",
            "sources": [{"pattern": "flask.request.args.get"}],
            "sinks": [{"pattern": "os.system", "arg": 0}],
        }
    ]
}


def test_a_custom_guard_declared_in_yaml_kills_taint(run_scan):
    from copy import deepcopy

    without = parse_rules(deepcopy(GUARD_RULE), "rules.yaml")
    assert [f.rule_id for f in run_scan({"app.py": GUARDED}, without)] == [
        "py.command-injection"
    ]

    spec = deepcopy(GUARD_RULE)
    spec["rules"][0]["guards"] = [{"pattern": "myapp.security.is_clean_host"}]
    assert run_scan({"app.py": GUARDED}, parse_rules(spec, "rules.yaml")) == []
