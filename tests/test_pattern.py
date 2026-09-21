import pytest

from scanner.analyzers.pattern import shannon_entropy


def test_entropy_ranks_random_strings_above_repeated_ones():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("sk_live_51H8xQ2KmZvR7tYbNp")


FLAGGED = {
    "module constant": 'API_KEY = "sk_live_51H8xQ2KmZvR7tYbNpL4wDcEf"\n',
    "class attribute": 'class C:\n    db_password = "Pg7#vQz2Lm9!TrWx"\n',
    "dict literal": 'CONFIG = {"api_secret": "Rk4$mZ9qWx2LpT7vNb3D"}\n',
    "keyword argument": 'connect(password="Rk4$mZ9qWx2LpT7vNb3D")\n',
    "annotated": 'ACCESS_KEY: str = "AKIAJ7Q2ZX9PLMN4TVDB"\n',
}

CLEAN = {
    "from environment": 'import os\nAPI_KEY = os.environ["API_KEY"]\n',
    "placeholder": 'API_KEY = "your-api-key-here"\n',
    "template": 'API_KEY = "${API_KEY}"\n',
    "low entropy": 'API_KEY = "aaaaaaaaaaaa"\n',
    "too short": 'API_KEY = "ab1$"\n',
    "unrelated name": 'GREETING = "Rk4$mZ9qWx2LpT7vNb3D"\n',
    "not a string": "API_KEY = 12345678\n",
}


@pytest.mark.parametrize("name", sorted(FLAGGED))
def test_hardcoded_secret_is_flagged(run_scan, shipped_rules, name):
    findings = run_scan({"conf.py": FLAGGED[name]}, shipped_rules)
    assert [f.rule_id for f in findings] == ["py.hardcoded-secret"], name


@pytest.mark.parametrize("name", sorted(CLEAN))
def test_safe_looking_value_is_not_flagged(run_scan, shipped_rules, name):
    assert run_scan({"conf.py": CLEAN[name]}, shipped_rules) == [], name
