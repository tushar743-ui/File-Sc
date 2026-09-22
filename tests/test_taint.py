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


KILLED_BY_GUARD = {
    "regex fullmatch guard": """
HOST = re.compile(r"\\A[a-z]+\\Z")


def f():
    host = request.args.get("host", "")
    if not HOST.fullmatch(host):
        raise ValueError("bad")
    os.system("ping " + host)
""",
    "containment guard": """
def f():
    name = request.args.get("name", "")
    full = os.path.abspath(os.path.join("/srv", name))
    if not full.startswith("/srv/"):
        raise ValueError("outside")
    return open(full, "rb").read()
""",
    "allowlist membership guard": """
ALLOWED = ("a", "b")


def f(cursor):
    column = request.args.get("c", "")
    if column not in ALLOWED:
        raise ValueError("bad column")
    cursor.execute("SELECT " + column + " FROM t")
""",
}


@pytest.mark.parametrize("name", sorted(KILLED_BY_GUARD))
def test_validation_guard_that_exits_kills_taint(name, run_scan, shipped_rules):
    body = "import re\n" + KILLED_BY_GUARD[name]
    assert scan_body(run_scan, shipped_rules, body) == []


def test_presence_check_does_not_kill_taint(run_scan, shipped_rules):
    body = """
def f(cursor):
    name = request.args.get("name")
    if not name:
        raise ValueError("missing")
    cursor.execute("SELECT '" + name + "'")
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.sql-injection"]


def test_taint_survives_a_branch_that_does_not_exit(run_scan, shipped_rules):
    body = """
def f(cursor):
    name = request.args.get("name")
    if name.startswith("x"):
        name = name.upper()
    cursor.execute("SELECT '" + name + "'")
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.sql-injection"]


def test_taint_flows_through_a_mutated_argument(run_scan, shipped_rules):
    body = """
def collect(bucket, value):
    bucket.append(value)


def f(cursor):
    parts = []
    collect(parts, request.args.get("q"))
    cursor.execute("SELECT '" + parts[0] + "'")
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.sql-injection"]


def test_taint_flows_through_a_locally_mutated_container(run_scan, shipped_rules):
    body = """
def f(cursor):
    parts = []
    parts.append(request.args.get("q"))
    cursor.execute("SELECT '" + parts[0] + "'")
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.sql-injection"]


def test_sink_reached_through_getattr_dispatch(run_scan, shipped_rules):
    body = """
def f():
    command = request.args.get("cmd")
    runner = getattr(os, "system")
    runner("echo " + command)
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.command-injection"]


def test_sink_reached_through_a_local_callable_alias(run_scan, shipped_rules):
    body = """
def f():
    command = request.args.get("cmd")
    runner = os.system
    runner("echo " + command)
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.command-injection"]


def test_sink_reached_through_a_lambda_parameter(run_scan, shipped_rules):
    body = """
def f():
    command = request.args.get("cmd")
    run = lambda value: os.system("echo " + value)
    return run(command)
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.command-injection"]


def test_taint_enters_through_a_constructor_argument(run_scan, shipped_rules):
    body = """
class Repo:
    def __init__(self, source):
        self.term = source.args.get("term")

    def run(self, cursor):
        cursor.execute("SELECT '" + self.term + "'")


def f(cursor):
    return Repo(request).run(cursor)
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.sql-injection"]


def test_clean_constructor_field_is_not_reported(run_scan, shipped_rules):
    body = """
class Repo:
    def __init__(self, source):
        self.term = source.args.get("term")
        self.table = "users"

    def run(self, cursor):
        cursor.execute("SELECT * FROM " + self.table)


def f(cursor):
    return Repo(request).run(cursor)
"""
    assert scan_body(run_scan, shipped_rules, body) == []


def test_source_named_only_at_the_call_site(run_scan, shipped_rules):
    body = """
def read(source):
    return source.args.get("q")


def f(cursor):
    cursor.execute("SELECT '" + read(request) + "'")
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.sql-injection"]


def test_sink_reached_through_an_inherited_method(run_scan, shipped_rules):
    body = """
class BaseRunner:
    def execute_now(self, command):
        os.system(command)


class Runner(BaseRunner):
    pass


def f():
    Runner().execute_now(request.args.get("cmd"))
"""
    assert scan_body(run_scan, shipped_rules, body) == ["py.command-injection"]


def test_sink_reached_through_a_base_class_in_another_file(run_scan, shipped_rules):
    findings = run_scan(
        {
            "base.py": "import os\n\n\nclass BaseRunner:\n"
            "    def execute_now(self, command):\n        os.system(command)\n",
            "child.py": "from flask import request\n\nfrom base import BaseRunner\n\n\n"
            "class Runner(BaseRunner):\n    pass\n\n\n"
            "def go():\n    Runner().execute_now(request.args.get('cmd'))\n",
        },
        shipped_rules,
    )
    assert [(f.rule_id, f.file) for f in findings] == [("py.command-injection", "base.py")]


def test_inherited_method_that_sanitizes_is_not_reported(run_scan, shipped_rules):
    body = """
import subprocess


class BaseRunner:
    def execute_now(self, command):
        subprocess.run(["echo", command], shell=False, check=False)


class Runner(BaseRunner):
    pass


def f():
    Runner().execute_now(request.args.get("cmd"))
"""
    assert scan_body(run_scan, shipped_rules, body) == []


MULTI_PARAM = """
from flask import request


def query(cursor, table, term):
    cursor.execute("SELECT * FROM " + table + " WHERE x = '" + term + "'")


def handler(cursor):
    query(cursor, "reports", request.args.get("q"))
"""

MULTI_FIELD = """
from flask import request


class Repo:
    def __init__(self, source):
        self.term = source.args.get("term")
        self.table = "reports"

    def run(self, cursor):
        cursor.execute("SELECT * FROM " + self.table + " WHERE x = '" + self.term + "'")


def handler(cursor):
    return Repo(request).run(cursor)
"""


def test_summary_keeps_every_param_flow_not_only_the_first(run_scan, shipped_rules):
    findings = run_scan({"a.py": MULTI_PARAM}, shipped_rules)
    assert [f.rule_id for f in findings] == ["py.sql-injection"]


def test_summary_keeps_every_field_flow_not_only_the_first(run_scan, shipped_rules):
    findings = run_scan({"b.py": MULTI_FIELD}, shipped_rules)
    assert [f.rule_id for f in findings] == ["py.sql-injection"]
