import pytest

HEADER = "from flask import request\nimport os, pickle, subprocess\n"


def scan_body(run_scan, rules, body):
    findings = run_scan({"app.py": HEADER + body}, rules)
    return [f.rule_id for f in findings]


PROPAGATES = {
    "direct assignment": """
def f(cursor):
    a = request.args.get("q")
    b = a
    c = b
    cursor.execute("SELECT " + c)
""",
    "fstring": """
def f(cursor):
    a = request.args.get("q")
    cursor.execute(f"SELECT {a}")
""",
    "percent": """
def f(cursor):
    a = request.args.get("q")
    cursor.execute("SELECT %s" % a)
""",
    "format": """
def f(cursor):
    a = request.args.get("q")
    cursor.execute("SELECT {}".format(a))
""",
    "list element": """
def f(cursor):
    items = [request.args.get("q")]
    cursor.execute("SELECT " + items[0])
""",
    "dict value": """
def f(cursor):
    d = {}
    d["k"] = request.args.get("q")
    cursor.execute("SELECT " + d["k"])
""",
    "tuple unpack": """
def f(cursor):
    a, b = request.args.get("q"), "x"
    cursor.execute("SELECT " + a)
""",
    "object attribute": """
def f(cursor, holder):
    holder.value = request.args.get("q")
    cursor.execute("SELECT " + holder.value)
""",
    "call return value": """
def clean_looking(x):
    return x.upper()

def f(cursor):
    cursor.execute("SELECT " + clean_looking(request.args.get("q")))
""",
    "branch then": """
def f(cursor, flag):
    v = "safe"
    if flag:
        v = request.args.get("q")
    cursor.execute("SELECT " + v)
""",
    "branch else": """
def f(cursor, flag):
    if flag:
        v = "safe"
    else:
        v = request.args.get("q")
    cursor.execute("SELECT " + v)
""",
    "loop accumulation": """
def f(cursor):
    out = ""
    for part in request.args.getlist("q"):
        out = out + part
    cursor.execute("SELECT " + out)
""",
    "augmented assignment": """
def f(cursor):
    out = "SELECT "
    out += request.args.get("q")
    cursor.execute(out)
""",
    "comprehension": """
def f(cursor):
    parts = [p for p in request.args.getlist("q")]
    cursor.execute("SELECT " + parts[0])
""",
    "with statement": """
def f(cursor):
    with request.args.get("q") as value:
        cursor.execute("SELECT " + value)
""",
    "walrus": """
def f(cursor):
    if (v := request.args.get("q")):
        cursor.execute("SELECT " + v)
""",
    "try body": """
def f(cursor):
    try:
        v = request.args.get("q")
    except ValueError:
        v = "safe"
    cursor.execute("SELECT " + v)
""",
    "ternary": """
def f(cursor, flag):
    v = request.args.get("q") if flag else "safe"
    cursor.execute("SELECT " + v)
""",
}

KILLED = {
    "reassignment": """
def f(cursor):
    v = request.args.get("q")
    v = "constant"
    cursor.execute("SELECT " + v)
""",
    "sanitizer": """
import shlex
def f():
    v = request.args.get("q")
    os.system("ls " + shlex.quote(v))
""",
    "provably constant": """
COLUMNS = {"a": "col_a", "b": "col_b"}
def f(cursor):
    key = request.args.get("q")
    cursor.execute("SELECT " + COLUMNS.get(key, "col_a"))
""",
    "constant subscript": """
COLUMNS = ("col_a", "col_b")
def f(cursor):
    _ = request.args.get("q")
    cursor.execute("SELECT " + COLUMNS[0])
""",
    "int coercion": """
def f(cursor):
    n = int(request.args.get("q"))
    cursor.execute("SELECT %d" % n)
""",
    "parameterized": """
def f(cursor):
    v = request.args.get("q")
    cursor.execute("SELECT * FROM t WHERE c = ?", (v,))
""",
    "subprocess without shell": """
def f():
    v = request.args.get("q")
    subprocess.run(["ls", v], check=True)
""",
    "yaml with loader": """
import yaml
def f():
    yaml.load(request.data, Loader=yaml.SafeLoader)
""",
    "constant only": """
def f(cursor):
    cursor.execute("SELECT 1")
""",
}


@pytest.mark.parametrize("name", sorted(PROPAGATES))
def test_taint_propagates(run_scan, shipped_rules, rule_ids, name):
    assert scan_body(run_scan, shipped_rules, PROPAGATES[name]), name


@pytest.mark.parametrize("name", sorted(KILLED))
def test_taint_is_killed(run_scan, shipped_rules, name):
    assert scan_body(run_scan, shipped_rules, KILLED[name]) == [], name


def test_finding_reports_the_whole_route(run_scan, shipped_rules):
    findings = run_scan({"app.py": HEADER + PROPAGATES["direct assignment"]}, shipped_rules)
    assert len(findings) == 1
    labels = [step.label for step in findings[0].path]
    assert "untrusted input" in labels[0]
    assert "execute" in labels[-1]
    assert len(findings[0].path) >= 3


def test_interprocedural_within_one_file(run_scan, shipped_rules):
    findings = run_scan(
        {
            "app.py": HEADER
            + """
def wrap(value):
    return "SELECT " + value

def f(cursor):
    cursor.execute(wrap(request.args.get("q")))
"""
        },
        shipped_rules,
    )
    assert [f.rule_id for f in findings] == ["py.sql-injection"]
    assert any("wrap" in step.label for step in findings[0].path)


def test_interprocedural_across_files(run_scan, shipped_rules):
    findings = run_scan(
        {
            "pkg/__init__.py": "",
            "pkg/helpers.py": "def run(cursor, sql):\n    cursor.execute(sql)\n",
            "pkg/views.py": "from flask import request\nfrom pkg.helpers import run\n\n"
            "def view(cursor):\n    run(cursor, 'SELECT ' + request.args.get('q'))\n",
        },
        shipped_rules,
    )
    assert [f.rule_id for f in findings] == ["py.sql-injection"]
    assert any(step.file.endswith("helpers.py") for step in findings[0].path)


def test_sanitizer_in_another_file_kills_taint(run_scan, shipped_rules):
    findings = run_scan(
        {
            "pkg/__init__.py": "",
            "pkg/safe.py": "from werkzeug.utils import secure_filename\n\n"
            "def clean(name):\n    return secure_filename(name)\n",
            "pkg/views.py": "from flask import request\nfrom pkg.safe import clean\n\n"
            "def view():\n    return open('/srv/' + clean(request.args.get('f'))).read()\n",
        },
        shipped_rules,
    )
    assert findings == []


def test_recursion_terminates(run_scan, shipped_rules):
    findings = run_scan(
        {
            "app.py": HEADER
            + """
def loop(value, depth):
    if depth <= 0:
        return value
    return loop(value + "x", depth - 1)

def f(cursor):
    cursor.execute(loop(request.args.get("q"), 5))
"""
        },
        shipped_rules,
    )
    assert [f.rule_id for f in findings] == ["py.sql-injection"]


def test_aliased_import_is_followed(run_scan, shipped_rules):
    findings = run_scan(
        {"app.py": "from flask import request as rq\nimport os as operating\n\n"
         "def f():\n    operating.system('ls ' + rq.args.get('d'))\n"},
        shipped_rules,
    )
    assert [f.rule_id for f in findings] == ["py.command-injection"]


def test_local_name_shadowing_a_builtin_source_is_not_a_source(run_scan, shipped_rules):
    findings = run_scan(
        {
            "app.py": "import pickle\n\n"
            "def check(input):\n    return pickle.loads(input)\n\n"
            "def real():\n    return pickle.loads(input())\n"
        },
        shipped_rules,
    )
    assert [f.line for f in findings] == [7]


def test_taint_reaches_a_sink_through_an_object_field_set_elsewhere(run_scan, shipped_rules):
    findings = run_scan(
        {
            "app.py": "from flask import request\n\n"
            "class View:\n"
            "    def load(self):\n        self.term = request.args.get('q')\n\n"
            "    def run(self, cursor):\n"
            "        cursor.execute(\"SELECT '\" + self.term + \"'\")\n"
        },
        shipped_rules,
    )
    assert [f.rule_id for f in findings] == ["py.sql-injection"]


def test_taint_reaches_a_sink_through_a_module_global(run_scan, shipped_rules):
    findings = run_scan(
        {
            "app.py": "import os\nfrom flask import request\n\nPENDING = {}\n\n"
            "def accept():\n    PENDING['cmd'] = request.args.get('cmd')\n\n"
            "def drain():\n    os.system('env ' + PENDING['cmd'])\n"
        },
        shipped_rules,
    )
    assert [f.rule_id for f in findings] == ["py.command-injection"]
