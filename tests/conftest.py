from pathlib import Path

import pytest
import yaml

from scanner.engine import ScanConfig, scan
from scanner.rules import parse_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
SHIPPED_RULES = REPO_ROOT / "rules.yaml"


@pytest.fixture(scope="session")
def shipped_rules():
    return parse_rules(yaml.safe_load(SHIPPED_RULES.read_text()), str(SHIPPED_RULES))


@pytest.fixture
def project(tmp_path):
    def build(files: dict) -> Path:
        for name, body in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body.lstrip("\n"), encoding="utf-8")
        return tmp_path

    return build


@pytest.fixture
def run_scan(project):
    def run(files, rules, jobs: int = 1):
        root = project(files) if isinstance(files, dict) else files
        return scan(ScanConfig(target=root, rules=rules, jobs=jobs, root=root))

    return run


@pytest.fixture
def rule_ids():
    def ids(findings):
        return sorted(f"{f.rule_id}@{f.file}:{f.line}" for f in findings)

    return ids
