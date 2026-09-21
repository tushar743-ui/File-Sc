from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .analyzers.base import Finding


@dataclass
class Score:
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        total = self.true_positive + self.false_positive
        return self.true_positive / total if total else 1.0

    @property
    def recall(self) -> float:
        total = self.true_positive + self.false_negative
        return self.true_positive / total if total else 1.0

    @property
    def f_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class BenchResult:
    overall: Score = field(default_factory=Score)
    per_rule: dict[str, Score] = field(default_factory=dict)
    false_positives: list[Finding] = field(default_factory=list)
    false_negatives: list[tuple[str, str, int]] = field(default_factory=list)
    files: int = 0

    def bucket(self, rule_id: str) -> Score:
        return self.per_rule.setdefault(rule_id, Score())


def load_labels(path: str | Path) -> dict[str, list[tuple[str, int]]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("files", data)
    labels: dict[str, list[tuple[str, int]]] = {}
    for name, spec in entries.items():
        expected = spec.get("expected", []) if isinstance(spec, dict) else spec
        labels[name] = [(item["rule"], int(item["line"])) for item in expected]
    return labels


def evaluate(findings: list[Finding], labels: dict[str, list[tuple[str, int]]]) -> BenchResult:
    result = BenchResult(files=len(labels))
    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)

    for name in sorted(labels):
        expected = list(labels[name])
        matched = [False] * len(expected)
        for finding in by_file.get(name, []):
            hit = -1
            for index, (rule_id, line) in enumerate(expected):
                if matched[index] or rule_id != finding.rule_id:
                    continue
                if finding.line <= line <= max(finding.line, finding.end_line):
                    hit = index
                    break
            if hit >= 0:
                matched[hit] = True
                result.overall.true_positive += 1
                result.bucket(finding.rule_id).true_positive += 1
            else:
                result.overall.false_positive += 1
                result.bucket(finding.rule_id).false_positive += 1
                result.false_positives.append(finding)
        for index, (rule_id, line) in enumerate(expected):
            if not matched[index]:
                result.overall.false_negative += 1
                result.bucket(rule_id).false_negative += 1
                result.false_negatives.append((name, rule_id, line))

    for finding in findings:
        if finding.file not in labels:
            result.overall.false_positive += 1
            result.bucket(finding.rule_id).false_positive += 1
            result.false_positives.append(finding)
    return result


def _rows(result: BenchResult) -> list[tuple[str, str, str, str, str, str, str]]:
    rows = []
    for rule_id in sorted(result.per_rule):
        score = result.per_rule[rule_id]
        rows.append(
            (
                rule_id,
                str(score.true_positive),
                str(score.false_positive),
                str(score.false_negative),
                f"{score.precision:.3f}",
                f"{score.recall:.3f}",
                f"{score.f_score:.3f}",
            )
        )
    overall = result.overall
    rows.append(
        (
            "ALL",
            str(overall.true_positive),
            str(overall.false_positive),
            str(overall.false_negative),
            f"{overall.precision:.3f}",
            f"{overall.recall:.3f}",
            f"{overall.f_score:.3f}",
        )
    )
    return rows


HEADERS = ("RULE", "TP", "FP", "FN", "PRECISION", "RECALL", "F1")


def render_table(result: BenchResult) -> str:
    rows = _rows(result)
    widths = [
        max(len(HEADERS[i]), max(len(row[i]) for row in rows)) for i in range(len(HEADERS))
    ]
    lines = ["  ".join(HEADERS[i].ljust(widths[i]) for i in range(len(HEADERS)))]
    lines.append("  ".join("-" * widths[i] for i in range(len(HEADERS))))
    for row in rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(HEADERS))))
    lines.append("")
    lines.append(f"labelled files: {result.files}")
    if result.false_positives:
        lines.append("")
        lines.append("false positives:")
        for finding in result.false_positives:
            lines.append(f"  {finding.file}:{finding.line} {finding.rule_id}")
    if result.false_negatives:
        lines.append("")
        lines.append("false negatives:")
        for name, rule_id, line in result.false_negatives:
            lines.append(f"  {name}:{line} {rule_id}")
    return "\n".join(lines) + "\n"


def render_markdown(result: BenchResult) -> str:
    rows = _rows(result)
    lines = ["| " + " | ".join(HEADERS) + " |", "|" + "---|" * len(HEADERS)]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append(f"Labelled files: {result.files}")
    if result.false_positives:
        lines.append("")
        lines.append("### False positives")
        lines.append("")
        for finding in result.false_positives:
            lines.append(f"- `{finding.file}:{finding.line}` {finding.rule_id}")
    if result.false_negatives:
        lines.append("")
        lines.append("### False negatives")
        lines.append("")
        for name, rule_id, line in result.false_negatives:
            lines.append(f"- `{name}:{line}` {rule_id}")
    return "\n".join(lines) + "\n"


def run_bench(findings, labels_path, root, rules, output_format: str) -> str:
    labels = load_labels(labels_path)
    result = evaluate(list(findings), labels)
    return render_markdown(result) if output_format == "markdown" else render_table(result)
