from scanner.baseline import build_baseline, filter_new

VULNERABLE = """
from flask import request


def lookup(cursor):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE n = '" + name + "'")
"""


def baseline_for(findings):
    return build_baseline(findings)


def test_baseline_captures_current_findings(run_scan, shipped_rules):
    findings = run_scan({"app.py": VULNERABLE}, shipped_rules)
    assert len(findings) == 1
    assert len(baseline_for(findings)["findings"]) == 1


def test_finding_survives_lines_added_above(run_scan, shipped_rules):
    before = run_scan({"app.py": VULNERABLE}, shipped_rules)
    shifted = "\n".join(f"HEADER_{i} = {i}" for i in range(20)) + "\n" + VULNERABLE
    after = run_scan({"app.py": shifted}, shipped_rules)

    assert after[0].line != before[0].line
    assert filter_new(after, baseline_for(before), {"app.py"}) == []


def test_finding_survives_a_function_rename(run_scan, shipped_rules):
    before = run_scan({"app.py": VULNERABLE}, shipped_rules)
    renamed = VULNERABLE.replace("def lookup(", "def fetch_user_row(")
    after = run_scan({"app.py": renamed}, shipped_rules)

    assert filter_new(after, baseline_for(before), {"app.py"}) == []


def test_finding_survives_reformatting(run_scan, shipped_rules):
    before = run_scan({"app.py": VULNERABLE}, shipped_rules)
    reformatted = VULNERABLE.replace(
        'cursor.execute("SELECT * FROM users WHERE n = \'" + name + "\'")',
        'cursor.execute(\n        "SELECT * FROM users WHERE n = \'" + name + "\'"\n    )',
    )
    after = run_scan({"app.py": reformatted}, shipped_rules)

    assert len(after) == 1
    assert filter_new(after, baseline_for(before), {"app.py"}) == []


def test_finding_survives_a_file_rename(run_scan, shipped_rules):
    before = run_scan({"app.py": VULNERABLE}, shipped_rules)
    after = run_scan({"views.py": VULNERABLE}, shipped_rules)

    assert filter_new(after, baseline_for(before), {"views.py"}) == []


def test_a_genuinely_new_finding_is_reported(run_scan, shipped_rules):
    before = run_scan({"app.py": VULNERABLE}, shipped_rules)
    extended = VULNERABLE + """

def second(cursor):
    other = request.args.get("other")
    cursor.execute("SELECT * FROM audit WHERE a = '" + other + "'")
"""
    after = run_scan({"app.py": extended}, shipped_rules)

    new = filter_new(after, baseline_for(before), {"app.py"})
    assert len(new) == 1
    assert "audit" in new[0].snippet


def test_duplicate_findings_keep_distinct_identities(run_scan, shipped_rules):
    twice = """
from flask import request


def a(cursor):
    cursor.execute("SELECT '" + request.args.get("n") + "'")


def b(cursor):
    cursor.execute("SELECT '" + request.args.get("n") + "'")
"""
    findings = run_scan({"app.py": twice}, shipped_rules)
    assert len(findings) == 2
    entries = baseline_for(findings)["findings"]
    assert len({entry["id"] for entry in entries}) == 2
