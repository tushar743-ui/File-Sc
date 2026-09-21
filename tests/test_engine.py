import time

from scanner.engine import ScanConfig, discover, scan

SAMPLE = """
from flask import request
import os


def handler_{n}(cursor):
    value = request.args.get("q")
    helper_{n}(cursor, value)


def helper_{n}(cursor, value):
    cursor.execute("SELECT * FROM t WHERE c = '" + value + "'")


def safe_{n}(cursor):
    cursor.execute("SELECT * FROM t WHERE c = ?", (request.args.get("q"),))
"""


def test_scan_is_deterministic(run_scan, shipped_rules, project):
    files = {f"pkg/mod_{n}.py": SAMPLE.format(n=n) for n in range(30)}
    root = project(files)
    serial = scan(ScanConfig(target=root, rules=shipped_rules, jobs=1, root=root))
    parallel = scan(ScanConfig(target=root, rules=shipped_rules, jobs=4, root=root))
    assert [f.sort_key for f in serial] == [f.sort_key for f in parallel]
    assert len(serial) == 30


def test_excluded_directories_are_skipped(project, shipped_rules):
    root = project(
        {
            "app.py": SAMPLE.format(n=0),
            "node_modules/vendor.py": SAMPLE.format(n=1),
            ".venv/lib/pkg.py": SAMPLE.format(n=2),
        }
    )
    files = discover(root, (".git", "node_modules", ".venv"))
    assert [f.split("/")[-1] for f in files] == ["app.py"]


def test_syntax_errors_do_not_stop_the_scan(project, shipped_rules):
    root = project({"broken.py": "def f(:\n", "ok.py": SAMPLE.format(n=0)})
    findings = scan(ScanConfig(target=root, rules=shipped_rules, jobs=1, root=root))
    assert len(findings) == 1


def test_five_hundred_files_scan_within_the_budget(project, shipped_rules):
    files = {f"pkg/sub{n % 20}/mod_{n}.py": SAMPLE.format(n=n) for n in range(500)}
    root = project(files)
    started = time.perf_counter()
    findings = scan(ScanConfig(target=root, rules=shipped_rules, root=root))
    elapsed = time.perf_counter() - started
    assert len(findings) == 500
    assert elapsed < 60.0, f"took {elapsed:.1f}s"


HELPER = """
def run_query(cursor, sql):
    cursor.execute(sql)
"""

CALLER = """
from flask import request

from helpers import run_query


def view_{n}(cursor):
    run_query(cursor, "SELECT * FROM t WHERE c = '" + request.args.get("{n}") + "'")
"""


def test_cross_file_findings_are_reported_at_the_sink(run_scan, shipped_rules):
    findings = run_scan(
        {
            "helpers.py": HELPER,
            "a.py": CALLER.format(n="a"),
            "b.py": CALLER.format(n="b"),
            "c.py": CALLER.format(n="c"),
        },
        shipped_rules,
    )
    assert {f.file for f in findings} == {"helpers.py"}
    assert {f.line for f in findings} == {2}
    assert sorted(f.path[0].file for f in findings) == ["a.py", "b.py", "c.py"]


def test_one_entry_point_reaching_a_sink_twice_reports_once(run_scan, shipped_rules):
    findings = run_scan(
        {
            "helpers.py": HELPER,
            "a.py": CALLER.format(n="a") + """

def again(cursor):
    return view_a(cursor)
""",
        },
        shipped_rules,
    )
    assert [(f.file, f.line) for f in findings] == [("helpers.py", 2)]


def test_suppression_in_the_sink_file_covers_cross_file_findings(run_scan, shipped_rules):
    findings = run_scan(
        {
            "helpers.py": """
def run_query(cursor, sql):
    cursor.execute(sql)  # taintscan: ignore[py.sql-injection] callers parameterize
""",
            "a.py": CALLER.format(n="a"),
        },
        shipped_rules,
    )
    assert findings == []
