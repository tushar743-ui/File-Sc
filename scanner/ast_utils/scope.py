from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from .resolver import Resolver

FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass
class FunctionInfo:
    qualname: str
    node: ast.AST
    params: tuple[str, ...]
    owner: str = ""
    is_method: bool = False

    def param_index(self, name: str) -> int:
        return self.params.index(name) if name in self.params else -1


@dataclass
class ModuleInfo:
    path: str
    rel_path: str
    module_name: str
    source: str
    tree: ast.Module
    resolver: Resolver
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    classes: dict[str, ast.ClassDef] = field(default_factory=dict)
    lines: tuple[str, ...] = ()

    def snippet(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()
        return ""


def module_name_for(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(path.name)
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = Path(parts[-1]).stem
    return ".".join(p for p in parts if p and p != ".")


def _index_functions(tree: ast.Module) -> tuple[dict[str, FunctionInfo], dict[str, ast.ClassDef]]:
    functions: dict[str, FunctionInfo] = {}
    classes: dict[str, ast.ClassDef] = {}

    def params_of(node: ast.AST) -> tuple[str, ...]:
        args = node.args
        names = [a.arg for a in args.posonlyargs] + [a.arg for a in args.args]
        if args.vararg:
            names.append(args.vararg.arg)
        names.extend(a.arg for a in args.kwonlyargs)
        if args.kwarg:
            names.append(args.kwarg.arg)
        return tuple(names)

    def walk(body: list, prefix: str, owner: str) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                qual = f"{prefix}{node.name}"
                classes[qual] = node
                walk(node.body, qual + ".", qual)
            elif isinstance(node, FUNCTION_NODES):
                qual = f"{prefix}{node.name}"
                params = params_of(node)
                is_method = bool(owner) and bool(params) and params[0] in ("self", "cls")
                functions[qual] = FunctionInfo(qual, node, params, owner, is_method)
                walk(node.body, qual + ".", "")
            elif isinstance(node, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.While)):
                walk(node.body, prefix, owner)
                walk(getattr(node, "orelse", []), prefix, owner)
                walk(getattr(node, "finalbody", []), prefix, owner)
                for handler in getattr(node, "handlers", []):
                    walk(handler.body, prefix, owner)

    walk(tree.body, "", "")
    return functions, classes


def build_module(path: str, rel_path: str, module_name: str, source: str) -> ModuleInfo:
    tree = ast.parse(source, filename=path)
    functions, classes = _index_functions(tree)
    return ModuleInfo(
        path=path,
        rel_path=rel_path,
        module_name=module_name,
        source=source,
        tree=tree,
        resolver=Resolver(tree, module_name),
        functions=functions,
        classes=classes,
        lines=tuple(source.splitlines()),
    )
