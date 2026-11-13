"""Rewrite thread operations into Mediator calls and embed the client runtime."""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

from .scanner import parse_thread_call

_MEDIATOR = "__mediator__"


@lru_cache(maxsize=1)
def _runtime_statements() -> tuple[ast.stmt, ...]:
    source = Path(__file__).with_name("mediator_runtime.py").read_text(encoding="utf-8")
    # Skip the module docstring so it doesn't become a stray expression.
    return tuple(ast.parse(source).body[1:])


def _mediator_call(method: str, args: list[ast.expr], keywords: list[ast.keyword] | None = None) -> ast.Call:
    return ast.Call(
        func=ast.Attribute(ast.Name(_MEDIATOR, ast.Load()), method, ast.Load()),
        args=args,
        keywords=keywords or [],
    )


class MediatorTransformer(ast.NodeTransformer):
    def __init__(self, rewrite_plan: dict[int, tuple[str, int]], thread_templates: dict[int, str]) -> None:
        self._plan = rewrite_plan
        self._thread_templates = thread_templates

    def visit_Call(self, node: ast.Call) -> ast.expr:
        operation = self._plan.get(id(node))
        self.generic_visit(node)
        if operation is None:
            return node
        kind, index = operation
        if kind == "create":
            parts = parse_thread_call(node)
            keywords = [
                ast.keyword(field, parts[field])
                for field in ("args", "kwargs", "name", "daemon") if field in parts
            ]
            template_id = ast.Constant(self._thread_templates[index])
            replacement = _mediator_call("create_task", [template_id], keywords)
        elif kind == "start":
            replacement = _mediator_call("submit", [node.func.value])
        else:  # join: keep any timeout argument.
            replacement = _mediator_call("wait", [node.func.value, *node.args], node.keywords)
        return ast.copy_location(replacement, node)


def transform(tree: ast.Module, rewrite_plan: dict[int, tuple[str, int]], thread_templates: dict[int, str]) -> ast.Module:
    """Transform ``tree`` in place, avoiding the cost of a deep copy of the AST."""
    MediatorTransformer(rewrite_plan, thread_templates).visit(tree)
    insert_at = 0
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) \
            and isinstance(tree.body[0].value.value, str):
        insert_at = 1
    while insert_at < len(tree.body):
        statement = tree.body[insert_at]
        if not (isinstance(statement, ast.ImportFrom) and statement.module == "__future__"):
            break
        insert_at += 1
    tree.body[insert_at:insert_at] = _runtime_statements()
    ast.fix_missing_locations(tree)
    return tree
