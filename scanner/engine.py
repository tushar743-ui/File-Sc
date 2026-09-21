from __future__ import annotations

import ast
import multiprocessing
import os
from dataclasses import dataclass, field
from pathlib import Path

from .analyzers.base import Finding, sort_findings
from .analyzers.pattern import PatternAnalyzer
from .analyzers.taint import TaintAnalyzer
from .ast_utils.scope import ModuleInfo, build_module, module_name_for
from .rules import Rule, RuleError
from .suppression import apply_suppressions, filter_suppressed

KIND_REGISTRY = {
    "taint": TaintAnalyzer,
    "pattern": PatternAnalyzer,
}

DEFAULT_EXCLUDES = (
    ".git", "__pycache__", ".venv", "venv", ".env", "node_modules", ".tox",
    ".mypy_cache", ".pytest_cache", ".eggs", "site-packages", ".ruff_cache",
)

MAX_FILE_BYTES = 2_000_000


def discover(target: Path, excludes: tuple[str, ...]) -> list[str]:
    if target.is_file():
        return [str(target.resolve())]
    found: list[str] = []
    skip = set(excludes)
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(filenames):
            if name.endswith(".py"):
                found.append(str(Path(dirpath, name).resolve()))
    return sorted(found)


def build_module_index(root: Path, files: list[str]) -> dict[str, str]:
    index: dict[str, str] = {}
    names: list[tuple[str, str]] = []
    for path in files:
        name = module_name_for(root, Path(path))
        names.append((name, path))
        index[name] = path
    for name, path in names:
        segments = name.split(".")
        for start in range(1, len(segments)):
            index.setdefault(".".join(segments[start:]), path)
    return index


class ScanContext:
    def __init__(self, root: Path, index: dict[str, str]) -> None:
        self.root = str(root)
        self.index = index
        self._cache: dict[str, ModuleInfo | None] = {}

    def __getstate__(self) -> dict:
        state = dict(self.__dict__)
        state["_cache"] = {}
        return state

    def relative(self, path: str) -> str:
        try:
            return str(Path(path).relative_to(self.root))
        except ValueError:
            return path

    def load(self, path: str) -> ModuleInfo | None:
        if path in self._cache:
            return self._cache[path]
        module = None
        try:
            if os.path.getsize(path) <= MAX_FILE_BYTES:
                source = Path(path).read_text(encoding="utf-8", errors="replace")
                module = build_module(
                    path,
                    self.relative(path),
                    module_name_for(Path(self.root), Path(path)),
                    source,
                )
        except (OSError, SyntaxError, ValueError, RecursionError):
            module = None
        self._cache[path] = module
        return module

    def resolve_external(self, module: ModuleInfo, node: ast.Call):
        name = module.resolver.dotted(node.func)
        if not name or "?" in name:
            return None
        segments = name.split(".")
        for split in range(len(segments) - 1, 0, -1):
            target = self.index.get(".".join(segments[:split]))
            if target is None or target == module.path:
                continue
            loaded = self.load(target)
            if loaded is None:
                continue
            rest = ".".join(segments[split:])
            info = loaded.functions.get(rest) or loaded.functions.get(f"{rest}.__init__")
            if info is not None:
                return loaded, info
        return None

    def resolve_class(self, module: ModuleInfo, node: ast.AST):
        name = module.resolver.dotted(node)
        if not name or "?" in name:
            return None
        segments = name.split(".")
        for split in range(len(segments) - 1, 0, -1):
            target = self.index.get(".".join(segments[:split]))
            if target is None or target == module.path:
                continue
            loaded = self.load(target)
            if loaded is None:
                continue
            rest = ".".join(segments[split:])
            if rest in loaded.classes:
                return loaded, rest
        return None


@dataclass
class ScanConfig:
    target: Path
    rules: list[Rule]
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES
    jobs: int = 0
    root: Path | None = None


def build_analyzers(rules: list[Rule], context: ScanContext) -> list:
    grouped: dict[str, list[Rule]] = {}
    for rule in rules:
        grouped.setdefault(rule.kind, []).append(rule)
    analyzers = []
    for kind, group in grouped.items():
        analyzer_cls = KIND_REGISTRY.get(kind)
        if analyzer_cls is None:
            raise RuleError(
                f"unknown rule kind '{kind}' (known kinds: {', '.join(sorted(KIND_REGISTRY))})"
            )
        analyzers.append(analyzer_cls(group, context))
    return analyzers


_WORKER: dict = {}


def _worker_init(rules: list[Rule], context: ScanContext) -> None:
    _WORKER["context"] = context
    _WORKER["analyzers"] = build_analyzers(rules, context)
    _WORKER["scoped"] = {rule.id: rule for rule in rules if rule.include or rule.exclude}


def _scan_one(path: str) -> list[Finding]:
    context: ScanContext = _WORKER["context"]
    module = context.load(path)
    if module is None:
        return []
    findings: list[Finding] = []
    for analyzer in _WORKER["analyzers"]:
        findings.extend(analyzer.analyze(module))
    scoped = _WORKER["scoped"]
    if scoped:
        findings = [
            finding
            for finding in findings
            if finding.rule_id not in scoped
            or scoped[finding.rule_id].applies_to(finding.file)
        ]
    local = [f for f in findings if f.file == module.rel_path]
    foreign = [f for f in findings if f.file != module.rel_path]
    local = apply_suppressions(local, module.source, module.rel_path, module.lines)
    if foreign:
        foreign = _filter_foreign(context, foreign)
    return dedupe(sort_findings(local + foreign))


def _filter_foreign(context: ScanContext, findings: list[Finding]) -> list[Finding]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.file, []).append(finding)
    out: list[Finding] = []
    for rel, group in sorted(grouped.items()):
        module = context.load(os.path.join(context.root, rel))
        out.extend(filter_suppressed(group, module.source) if module else group)
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for finding in findings:
        origin = finding.path[0] if finding.path else None
        key = (
            finding.rule_id,
            finding.file,
            finding.line,
            finding.col,
            finding.end_col,
            (origin.file, origin.line, origin.col) if origin else None,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def scan(config: ScanConfig) -> list[Finding]:
    target = config.target.resolve()
    root = (config.root or (target if target.is_dir() else target.parent)).resolve()
    files = discover(target, config.excludes)
    if not files:
        return []
    context = ScanContext(root, build_module_index(root, files))

    jobs = config.jobs or min(os.cpu_count() or 1, 8)
    if jobs > 1 and len(files) >= 24:
        with multiprocessing.get_context("fork").Pool(
            processes=jobs, initializer=_worker_init, initargs=(config.rules, context)
        ) as pool:
            batches = pool.map(_scan_one, files, chunksize=8)
    else:
        _worker_init(config.rules, context)
        batches = [_scan_one(path) for path in files]

    findings: list[Finding] = []
    for batch in batches:
        findings.extend(batch)
    return dedupe(sort_findings(findings))
