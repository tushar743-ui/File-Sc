from __future__ import annotations

import ast
import math
from collections import Counter
from typing import Iterator

from ..ast_utils.visitor import ScopedVisitor, location
from ..rules import RuleError, match_glob
from .base import AbstractAnalyzer, Finding


SEPARATORS = "_-./: "


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total) for count in Counter(value).values()
    )


def is_identifier_path(value: str) -> bool:
    if len(value) > 80:
        return False
    parts = value.split(".")
    if len(parts) < 3:
        return False
    return all(part.isidentifier() and len(part) <= 24 for part in parts)


def charset_classes(value: str) -> int:
    core = [character for character in value if character not in SEPARATORS]
    return sum(
        [
            any(character.islower() for character in core),
            any(character.isupper() for character in core),
            any(character.isdigit() for character in core),
            any(not character.isalnum() for character in core),
        ]
    )


class _Matcher:
    def __init__(self, rule) -> None:
        spec = rule.spec.get("match")
        if not isinstance(spec, dict):
            raise RuleError(f"rule '{rule.id}': pattern rules need a 'match' mapping")
        self.rule = rule
        self.assigned_to = [str(p) for p in spec.get("assigned_to", [])]
        self.value_kind = str(spec.get("value", "any"))
        self.min_entropy = float(spec.get("min_entropy", 0.0))
        self.min_length = int(spec.get("min_length", 0))
        self.min_classes = int(spec.get("min_charset_classes", 0))
        self.exclude = [str(p) for p in spec.get("exclude", [])]
        self.exclude_identifier_path = bool(spec.get("exclude_identifier_path", False))

    def name_matches(self, name: str) -> bool:
        if not self.assigned_to:
            return True
        lowered = name.lower()
        return any(match_glob(pattern.lower(), lowered) for pattern in self.assigned_to)

    def value_matches(self, node: ast.AST) -> str | None:
        if self.value_kind == "literal_string":
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                return None
            value = node.value
        elif isinstance(node, ast.Constant):
            value = str(node.value)
        else:
            return None
        if len(value) < self.min_length:
            return None
        if any(match_glob(pattern, value) for pattern in self.exclude):
            return None
        if self.exclude_identifier_path and is_identifier_path(value):
            return None
        if self.min_classes and charset_classes(value) < self.min_classes:
            return None
        if self.min_entropy and shannon_entropy(value) < self.min_entropy:
            return None
        return value


class _Collector(ScopedVisitor):
    def __init__(self, module, matchers: list[_Matcher]) -> None:
        super().__init__(module)
        self.matchers = matchers
        self.findings: list[Finding] = []

    def _target_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _check(self, name: str | None, value_node: ast.AST, anchor: ast.AST) -> None:
        if name is None:
            return
        for matcher in self.matchers:
            if not matcher.name_matches(name):
                continue
            value = matcher.value_matches(value_node)
            if value is None:
                continue
            line, col, end_line, end_col = location(anchor)
            rule = matcher.rule
            self.findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    cwe=rule.cwe,
                    message=rule.message,
                    file=self.module.rel_path,
                    line=line,
                    col=col,
                    end_line=end_line,
                    end_col=end_col,
                    signature=f"{name}={value}",
                    snippet=self.module.snippet(line),
                )
            )
            break

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check(self._target_name(target), node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check(self._target_name(node.target), node.value, node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if key is not None:
                self._check(self._target_name(key), value, value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg:
                self._check(keyword.arg, keyword.value, keyword.value)
        self.generic_visit(node)


class PatternAnalyzer(AbstractAnalyzer):
    kind = "pattern"

    def __init__(self, rules, context) -> None:
        super().__init__(rules, context)
        self.matchers = [_Matcher(rule) for rule in rules]

    def analyze(self, module) -> Iterator[Finding]:
        collector = _Collector(module, self.matchers)
        collector.run()
        return iter(collector.findings)
