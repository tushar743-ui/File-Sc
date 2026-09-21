from scanner.suppression import NO_REASON_RULE

BASE = """
from flask import request


def lookup(cursor):
    name = request.args.get("name")
    {line}
"""

SINK = 'cursor.execute("SELECT \'" + name + "\'")'


def build(suffix="", above=None):
    body = SINK + suffix
    if above:
        body = above + "\n    " + body
    return BASE.format(line=body)


def test_unsuppressed_finding_is_reported(run_scan, shipped_rules):
    findings = run_scan({"app.py": build()}, shipped_rules)
    assert [f.rule_id for f in findings] == ["py.sql-injection"]


def test_trailing_comment_suppresses(run_scan, shipped_rules):
    source = build(suffix="  # codity: ignore[py.sql-injection] name is allowlisted")
    assert run_scan({"app.py": source}, shipped_rules) == []


def test_comment_on_the_line_above_suppresses(run_scan, shipped_rules):
    source = build(above="# codity: ignore[py.sql-injection] name is allowlisted")
    assert run_scan({"app.py": source}, shipped_rules) == []


def test_bare_ignore_suppresses_every_rule(run_scan, shipped_rules):
    source = build(suffix="  # codity: ignore reviewed by security 2026-09")
    assert run_scan({"app.py": source}, shipped_rules) == []


def test_other_rule_id_does_not_suppress(run_scan, shipped_rules):
    source = build(suffix="  # codity: ignore[py.ssrf] wrong rule")
    assert [f.rule_id for f in run_scan({"app.py": source}, shipped_rules)] == [
        "py.sql-injection"
    ]


def test_suppression_without_a_reason_is_itself_reported(run_scan, shipped_rules):
    source = build(suffix="  # codity: ignore[py.sql-injection]")
    findings = run_scan({"app.py": source}, shipped_rules)
    assert [f.rule_id for f in findings] == [NO_REASON_RULE.id]
    assert findings[0].severity == "low"


def test_reasoned_suppression_produces_no_meta_finding(run_scan, shipped_rules):
    source = build(suffix="  # codity: ignore[py.sql-injection] checked against an allowlist")
    assert run_scan({"app.py": source}, shipped_rules) == []
