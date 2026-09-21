from __future__ import annotations

import ast

from .scope import FUNCTION_NODES, ModuleInfo


class ScopedVisitor(ast.NodeVisitor):
    def __init__(self, module: ModuleInfo) -> None:
        self.module = module
        self._scope: list[str] = []

    @property
    def qualname(self) -> str:
        return ".".join(self._scope)

    def scoped(self, name: str) -> str:
        return ".".join(self._scope + [name])

    def _enter(self, node: ast.AST) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._enter(node)

    def visit_FunctionDef(self, node: ast.AST) -> None:
        self._enter(node)

    def visit_AsyncFunctionDef(self, node: ast.AST) -> None:
        self._enter(node)

    def run(self) -> None:
        self.visit(self.module.tree)


def location(node: ast.AST) -> tuple[int, int, int, int]:
    line = getattr(node, "lineno", 1)
    col = getattr(node, "col_offset", 0)
    end_line = getattr(node, "end_lineno", None) or line
    end_col = getattr(node, "end_col_offset", None)
    if end_col is None:
        end_col = col + 1
    return line, col + 1, end_line, end_col + 1
