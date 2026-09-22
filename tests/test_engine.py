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


def test_summary_format_is_compact_and_grouped(project, shipped_rules, capsys):
    from scanner.cli import main

    root = project({"a.py": CALLER.format(n="a"), "helpers.py": HELPER})
    code = main(["scan", str(root), "--rules", "rules.yaml", "--format", "summary"])
    out = capsys.readouterr()

    assert code == 0
    assert "BY RULE" in out.out and "BY SEVERITY" in out.out and "BY FILE" in out.out
    assert "py.sql-injection" in out.out
    assert "      entry " not in out.out
    assert "      sink " not in out.out
    assert len(out.out.splitlines()) < len(
        _table_output(main, root, capsys).splitlines()
    )


def test_summary_clusters_one_line_per_sink(project, shipped_rules, capsys):
    from scanner.cli import main

    root = project({"a.py": TWO_ENTRIES})
    main(["scan", str(root), "--rules", "rules.yaml", "--format", "summary"])
    out = capsys.readouterr().out

    sink_lines = [l for l in out.splitlines() if "py.sql-injection" in l and ".py:" in l]
    assert len(sink_lines) == 1
    assert "x2 entry points" in sink_lines[0]
    assert "1 sink(s)" in out and "2 finding(s)" in out


TWO_ENTRIES = """
from flask import request


def run(cursor, value):
    cursor.execute("SELECT * FROM t WHERE c = '" + value + "'")


def first(cursor):
    run(cursor, request.args.get("a"))


def second(cursor):
    run(cursor, request.form.get("b"))
"""


def _table_output(main, root, capsys):
    main(["scan", str(root), "--rules", "rules.yaml", "--format", "table"])
    return capsys.readouterr().out


def test_progress_goes_to_stderr_and_quiet_silences_it(project, shipped_rules, capsys):
    from scanner.cli import main

    root = project({"a.py": CALLER.format(n="a"), "helpers.py": HELPER})

    main(["scan", str(root), "--rules", "rules.yaml", "--format", "sarif"])
    noisy = capsys.readouterr()
    assert "python file(s) to scan" in noisy.err and "finding(s)" in noisy.err
    assert noisy.out.startswith("{")

    main(["scan", str(root), "--rules", "rules.yaml", "--format", "sarif", "--quiet"])
    quiet = capsys.readouterr()
    assert quiet.err == ""
    assert quiet.out.startswith("{")


def test_module_cache_is_bounded_and_results_unchanged(project, shipped_rules, monkeypatch):
    import scanner.engine as eng

    files = {f"pkg/mod_{n}.py": SAMPLE.format(n=n) for n in range(40)}
    root = project(files)
    unbounded = scan(ScanConfig(target=root, rules=shipped_rules, jobs=1, root=root))

    monkeypatch.setattr(eng, "MODULE_CACHE_SIZE", 4)
    seen = []
    original = eng.ScanContext.load

    def watched(self, path):
        module = original(self, path)
        seen.append(len(self._cache))
        return module

    monkeypatch.setattr(eng.ScanContext, "load", watched)
    bounded = scan(ScanConfig(target=root, rules=shipped_rules, jobs=1, root=root))

    assert max(seen) <= 4
    assert [f.sort_key for f in bounded] == [f.sort_key for f in unbounded]


def test_progress_reports_every_file_batch_and_total(project, shipped_rules):
    files = {f"pkg/mod_{n}.py": SAMPLE.format(n=n) for n in range(30)}
    root = project(files)
    calls = []
    scan(
        ScanConfig(target=root, rules=shipped_rules, jobs=1, root=root),
        progress=lambda done, total: calls.append((done, total)),
    )
    assert calls[0] == (0, 30)
    assert calls[-1] == (30, 30)
