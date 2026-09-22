from __future__ import annotations

import ast
import copy
from functools import lru_cache

UNKNOWN = "?"

MUTATING_METHODS = frozenset(
    {"append", "extend", "insert", "update", "add", "setdefault", "pop", "clear", "remove"}
)

LOOKUP_METHODS = frozenset({"get", "pop", "setdefault"})
READONLY_METHODS = frozenset({"keys", "values", "items", "copy", "index", "count"})


def is_constant_container(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return all(is_constant_container(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and is_constant_container(key) and is_constant_container(value)
            for key, value in zip(node.keys, node.values)
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ("frozenset", "set", "tuple", "list", "dict") and not node.keywords:
            return all(is_constant_container(argument) for argument in node.args)
    return False


@lru_cache(maxsize=65536)
def candidates(name: str) -> tuple[str, ...]:
    if not name:
        return ()
    segments = name.split(".")
    out = [name]
    for index in range(1, len(segments)):
        out.append(UNKNOWN + "." + ".".join(segments[index:]))
    return tuple(out)


def relative_base(package: str, level: int, module: str | None) -> str:
    parts = package.split(".") if package else []
    if level > 1:
        parts = parts[: len(parts) - (level - 1)]
    if module:
        parts = parts + module.split(".")
    return ".".join(p for p in parts if p)


class Resolver:
    def __init__(self, tree: ast.Module, module_name: str = "") -> None:
        self.module_name = module_name
        self.package = module_name.rsplit(".", 1)[0] if "." in module_name else ""
        self.aliases: dict[str, str] = {}
        self.origins: dict[str, tuple[str, str]] = {}
        self.local_defs: set[str] = set()
        self.constants: frozenset[str] = frozenset()
        self._collect(tree)
        self._collect_local_defs(tree)
        self._collect_module_aliases(tree)

    def _collect(self, tree: ast.Module) -> None:
        declared: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and is_constant_container(node.value):
                    declared.add(target.id)
        stores: dict[str, int] = {}
        mutated: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._record_import(node)
            elif not declared:
                continue
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                stores[node.id] = stores.get(node.id, 0) + 1
            elif isinstance(node, (ast.Attribute, ast.Subscript)):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    root = node
                    while isinstance(root, (ast.Attribute, ast.Subscript)):
                        root = root.value
                    if isinstance(root, ast.Name):
                        mutated.add(root.id)
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    if func.attr in MUTATING_METHODS:
                        mutated.add(func.value.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                mutated.add(node.name)
        self.constants = frozenset(
            name
            for name in declared
            if stores.get(name, 0) == 1 and name not in mutated
        )

    def _collect_local_defs(self, tree: ast.Module) -> None:
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name not in self.aliases:
                    self.local_defs.add(node.name)

    def _record_import(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    self.aliases[alias.asname] = alias.name
                    self.origins[alias.asname] = (alias.name, "")
                else:
                    root = alias.name.split(".")[0]
                    self.aliases.setdefault(root, root)
                    self.origins.setdefault(root, (root, ""))
            return
        base = (
            relative_base(self.package, node.level, node.module)
            if node.level
            else (node.module or "")
        )
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            full = f"{base}.{alias.name}" if base else alias.name
            self.aliases[local] = full
            self.origins[local] = (base, alias.name)

    def _collect_module_aliases(self, tree: ast.Module) -> None:
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if not isinstance(node.value, (ast.Name, ast.Attribute)):
                continue
            resolved = self.dotted(node.value)
            if resolved and UNKNOWN not in resolved and target.id not in self.aliases:
                self.aliases[target.id] = resolved

    def extended(self, extra: dict[str, str]) -> "Resolver":
        clone = copy.copy(self)
        clone.aliases = {**self.aliases, **extra}
        return clone

    def dotted(self, node: ast.AST) -> str:
        parts: list[str] = []
        current = node
        while True:
            if isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            elif isinstance(current, ast.Call):
                current = current.func
            elif isinstance(current, ast.Subscript):
                current = current.value
            elif isinstance(current, ast.Await):
                current = current.value
            elif isinstance(current, ast.Name):
                if current.id in self.aliases:
                    parts.append(self.aliases[current.id])
                elif current.id in self.local_defs and self.module_name:
                    parts.append(f"{self.module_name}.{current.id}")
                else:
                    parts.append(current.id)
                break
            else:
                parts.append(UNKNOWN)
                break
        parts.reverse()
        return ".".join(parts)

    def candidates_for(self, node: ast.AST) -> tuple[str, ...]:
        return candidates(self.dotted(node))

    def origin_of(self, node: ast.AST) -> tuple[str, str] | None:
        root = node
        while isinstance(root, (ast.Attribute, ast.Call, ast.Subscript, ast.Await)):
            root = root.func if isinstance(root, ast.Call) else root.value
        if not isinstance(root, ast.Name):
            return None
        return self.origins.get(root.id)
