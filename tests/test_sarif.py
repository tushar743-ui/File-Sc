import json

from scanner.baseline import FINGERPRINT_KEY, assign_fingerprints
from scanner.output import sarif

VULNERABLE = """
from flask import request


def lookup(cursor):
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE n = '" + name + "'"
    cursor.execute(query)
"""


def document(run_scan, rules, tmp_path):
    findings = assign_fingerprints(run_scan({"app.py": VULNERABLE}, rules))
    return json.loads(sarif.render(findings, rules, str(tmp_path))), findings


def test_top_level_shape(run_scan, shipped_rules, tmp_path):
    doc, _ = document(run_scan, shipped_rules, tmp_path)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1


def test_rule_metadata_carries_cwe(run_scan, shipped_rules, tmp_path):
    doc, _ = document(run_scan, shipped_rules, tmp_path)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    by_id = {rule["id"]: rule for rule in rules}
    assert by_id["py.sql-injection"]["properties"]["cwe"] == "CWE-89"
    assert "external/cwe/cwe-89" in by_id["py.sql-injection"]["properties"]["tags"]
    assert by_id["py.sql-injection"]["defaultConfiguration"]["level"] == "error"


def test_result_has_every_required_field(run_scan, shipped_rules, tmp_path):
    doc, _ = document(run_scan, shipped_rules, tmp_path)
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "py.sql-injection"
    assert result["level"] == "error"
    assert result["message"]["text"]
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 7 and region["startColumn"] >= 1
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert result["partialFingerprints"][FINGERPRINT_KEY]


def test_taint_path_is_expressed_as_code_flows(run_scan, shipped_rules, tmp_path):
    doc, findings = document(run_scan, shipped_rules, tmp_path)
    locations = doc["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locations) == len(findings[0].path) >= 3
    assert [entry["executionOrder"] for entry in locations] == list(range(len(locations)))
    assert all(entry["location"]["message"]["text"] for entry in locations)
    assert "untrusted input" in locations[0]["location"]["message"]["text"]


def test_rule_index_points_at_the_descriptor(run_scan, shipped_rules, tmp_path):
    doc, _ = document(run_scan, shipped_rules, tmp_path)
    run = doc["runs"][0]
    result = run["results"][0]
    assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]


def test_output_is_byte_identical_across_runs(run_scan, shipped_rules, tmp_path):
    first = sarif.render(assign_fingerprints(run_scan({"app.py": VULNERABLE}, shipped_rules)), shipped_rules, str(tmp_path))
    second = sarif.render(assign_fingerprints(run_scan({"app.py": VULNERABLE}, shipped_rules)), shipped_rules, str(tmp_path))
    assert first == second
