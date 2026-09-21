from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .analyzers.base import SEVERITY_ORDER


class RuleError(ValueError):
    pass


@lru_cache(maxsize=8192)
def match_glob(pattern: str, text: str) -> bool:
    if pattern == "*":
        return True
    if "*" not in pattern and "?" not in pattern and "[" not in pattern:
        return pattern == text
    return fnmatch.fnmatchcase(text, pattern)


@lru_cache(maxsize=8192)
def _split(value: str) -> tuple[str, ...]:
    return tuple(value.split("."))


@lru_cache(maxsize=65536)
def match_dotted(pattern: str, name: str) -> bool:
    pat = _split(pattern)
    seg = _split(name)
    if len(pat) != len(seg):
        return False
    return all(match_glob(p, s) for p, s in zip(pat, seg))


@dataclass(frozen=True)
class PatternSpec:
    pattern: str
    arg: Any = None
    payload: Any = None


def parse_pattern_specs(entries: Any, owner: str, payload: Any = None) -> list[PatternSpec]:
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise RuleError(f"rule '{owner}': expected a list of patterns")
    specs: list[PatternSpec] = []
    flat: list = []
    for entry in entries:
        flat.extend(entry) if isinstance(entry, list) else flat.append(entry)
    for entry in flat:
        if isinstance(entry, str):
            specs.append(PatternSpec(entry, None, payload))
            continue
        if not isinstance(entry, dict) or "pattern" not in entry:
            raise RuleError(f"rule '{owner}': pattern entry needs a 'pattern' field")
        arg = entry.get("arg")
        if arg is not None and arg != "any" and not isinstance(arg, int):
            raise RuleError(f"rule '{owner}': 'arg' must be an integer or 'any'")
        specs.append(PatternSpec(str(entry["pattern"]), arg, payload))
    return specs


_GLOB_CHARS = ("*", "?", "[")

CACHE_LIMIT = 100_000


class PatternIndex:
    def __init__(self, specs: list[PatternSpec] | None = None) -> None:
        self._exact: dict[str, list[PatternSpec]] = {}
        self._wild: list[PatternSpec] = []
        self._empty = True
        self._cache: dict[tuple[str, ...], list[PatternSpec]] = {}
        for spec in specs or []:
            self.add(spec)

    def add(self, spec: PatternSpec) -> None:
        self._empty = False
        self._cache.clear()
        last = spec.pattern.rsplit(".", 1)[-1]
        if any(ch in last for ch in _GLOB_CHARS):
            self._wild.append(spec)
        else:
            self._exact.setdefault(last, []).append(spec)

    def __bool__(self) -> bool:
        return not self._empty

    def lookup(self, names: tuple[str, ...]) -> list[PatternSpec]:
        if self._empty:
            return []
        cached = self._cache.get(names)
        if cached is not None:
            return cached
        hits: list[PatternSpec] = []
        seen: set[int] = set()
        for name in names:
            last = name.rsplit(".", 1)[-1]
            for spec in (*self._exact.get(last, ()), *self._wild):
                if id(spec) not in seen and match_dotted(spec.pattern, name):
                    seen.add(id(spec))
                    hits.append(spec)
        if len(self._cache) < CACHE_LIMIT:
            self._cache[names] = hits
        return hits

    def matches(self, names: tuple[str, ...]) -> bool:
        return bool(self.lookup(names))


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    cwe: str
    message: str
    kind: str
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    spec: dict = field(default_factory=dict, compare=False)

    def applies_to(self, path: str) -> bool:
        if self.include and not any(match_glob(p, path) for p in self.include):
            return False
        return not any(match_glob(p, path) for p in self.exclude)


_COMMON_KEYS = {"id", "severity", "cwe", "message", "kind", "paths"}


def _require(entry: dict, key: str, index: int) -> Any:
    if key not in entry or entry[key] in (None, ""):
        raise RuleError(f"rule #{index}: missing required field '{key}'")
    return entry[key]


def parse_rules(document: Any, origin: str = "<memory>") -> list[Rule]:
    if isinstance(document, dict):
        entries = document.get("rules")
    else:
        entries = document
    if not isinstance(entries, list):
        raise RuleError(f"{origin}: expected a top-level 'rules' list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise RuleError(f"{origin}: rule #{index} is not a mapping")
        rule_id = str(_require(entry, "id", index))
        if rule_id in seen:
            raise RuleError(f"{origin}: duplicate rule id '{rule_id}'")
        seen.add(rule_id)
        severity = str(_require(entry, "severity", index)).lower()
        if severity not in SEVERITY_ORDER:
            raise RuleError(
                f"{origin}: rule '{rule_id}' has unknown severity '{severity}'"
            )
        paths = entry.get("paths") or {}
        if not isinstance(paths, dict):
            raise RuleError(f"{origin}: rule '{rule_id}': 'paths' must be a mapping")
        rules.append(
            Rule(
                id=rule_id,
                severity=severity,
                cwe=str(entry.get("cwe", "")),
                message=str(_require(entry, "message", index)),
                kind=str(_require(entry, "kind", index)),
                include=tuple(str(p) for p in paths.get("include", [])),
                exclude=tuple(str(p) for p in paths.get("exclude", [])),
                spec={k: v for k, v in entry.items() if k not in _COMMON_KEYS},
            )
        )
    return rules


def load_rules(path: str | Path) -> list[Rule]:
    text = Path(path).read_text(encoding="utf-8")
    return parse_rules(yaml.safe_load(text), origin=str(path))
