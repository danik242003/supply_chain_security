"""Decide whether a scanned file is safe to run on remote workers.

A worker has no access to the client's memory, so the core question for every
thread target is what it depends on outside its own frame. ``symtable`` answers
that using the compiler's own scoping rules, rather than a hand-rolled analysis.
"""

from __future__ import annotations

import ast
import builtins
import copy
import sys
import symtable
from dataclasses import dataclass, field

from .models import Issue, ScanResult, Severity, ThreadInfo

_BUILTINS = frozenset(dir(builtins))
_IMMUTABLE_SCALARS = (int, float, complex, str, bytes, bool, type(None))
_MUTATORS = frozenset({
    "append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse",
    "update", "setdefault", "popitem", "add", "discard",
})


@dataclass(slots=True)
class TargetDeps:
    """What a target function needs shipped alongside it."""

    function: ast.FunctionDef
    imports: list[ast.stmt] = field(default_factory=list)
    constants: list[ast.stmt] = field(default_factory=list)


@dataclass(slots=True)
class ValidationReport:
    issues: list[Issue] = field(default_factory=list)
    targets: dict[str, TargetDeps] = field(default_factory=dict)

    @property
    def has_errors(self) -> bool:
        return any(i.severity is Severity.ERROR for i in self.issues)

    def error(self, code: str, message: str, lineno: int | None = None) -> None:
        self.issues.append(Issue(Severity.ERROR, code, message, lineno))

    def warn(self, code: str, message: str, lineno: int | None = None) -> None:
        self.issues.append(Issue(Severity.WARNING, code, message, lineno))


def _is_immutable_literal(node: ast.expr) -> bool:
    try:
        value = ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return False

    def immutable(item: object) -> bool:
        if isinstance(item, tuple):
            return all(immutable(i) for i in item)
        return isinstance(item, _IMMUTABLE_SCALARS)

    return immutable(value)


def _module_bindings(tree: ast.Module) -> tuple[dict[str, list[tuple[str, ast.AST]]], bool]:
    """Map each module-level name to how it gets bound."""
    bindings: dict[str, list[tuple[str, ast.AST]]] = {}
    star_import = False

    def bind(name: str, kind: str, node: ast.AST) -> None:
        bindings.setdefault(name, []).append((kind, node))

    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                bound = alias.asname or alias.name.partition(".")[0]
                bind(bound, "import", ast.Import(names=[alias]))
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if alias.name == "*":
                    star_import = True
                    continue
                single = ast.ImportFrom(module=statement.module, names=[alias], level=statement.level)
                bind(alias.asname or alias.name, "import", single)
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bind(statement.name, "function", statement)
        elif isinstance(statement, ast.ClassDef):
            bind(statement.name, "class", statement)
        elif (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and _is_immutable_literal(statement.value)
        ):
            bind(statement.targets[0].id, "constant", statement)
        else:
            for node in ast.walk(statement):
                if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                    bind(node.id, "other", statement)
    # A `global x` anywhere means x can change at runtime, so its initial value
    # can't be treated as a constant and shipped to workers.
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            for name in node.names:
                bind(name, "other", node)
    return bindings, star_import


def _function_table(table: symtable.SymbolTable, node: ast.AST) -> symtable.SymbolTable | None:
    for child in table.get_children():
        if child.get_type() == "function" and child.get_name() == node.name and child.get_lineno() == node.lineno:
            return child
    return None


def _globals_used(table: symtable.SymbolTable) -> tuple[set[str], set[str]]:
    """Return (global names used, names declared `global`) across nested scopes."""
    used: set[str] = set()
    declared: set[str] = set()
    pending = [table]
    while pending:
        current = pending.pop()
        for symbol in current.get_symbols():
            if symbol.is_global():
                used.add(symbol.get_name())
                if symbol.is_declared_global():
                    declared.add(symbol.get_name())
        pending.extend(current.get_children())
    return used, declared


def _signature_names(function: ast.FunctionDef) -> set[str]:
    """Names in defaults and annotations: these resolve at module scope."""
    args = function.args
    roots: list[ast.AST] = [*args.defaults, *(d for d in args.kw_defaults if d)]
    every_arg = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    every_arg += [a for a in (args.vararg, args.kwarg) if a]
    roots += [a.annotation for a in every_arg if a.annotation]
    if function.returns:
        roots.append(function.returns)
    return {
        n.id for root in roots for n in ast.walk(root)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }


def _mutated_params(function: ast.FunctionDef) -> list[tuple[str, int]]:
    args = function.args
    params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    found: list[tuple[str, int]] = []

    def base(node: ast.expr) -> str | None:
        while isinstance(node, (ast.Subscript, ast.Attribute)):
            node = node.value
        return node.id if isinstance(node, ast.Name) and node.id in params else None

    for node in ast.walk(function):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        elif isinstance(node, ast.Delete):
            targets = node.targets
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATORS:
            name = base(node.func.value)
            if name:
                found.append((name, node.lineno))
        for target in targets:
            if isinstance(target, (ast.Subscript, ast.Attribute)):
                name = base(target)
                if name:
                    found.append((name, node.lineno))
    return found


def _check_thread_site(thread: ThreadInfo, scan: ScanResult, report: ValidationReport) -> None:
    line = thread.lineno
    if thread.has_star_args:
        report.error("thread-star-args", "Thread(*args/**kwargs) can't be analysed statically.", line)
    if thread.target is None:
        report.error("thread-no-target", "Thread created without a target function.", line)
    elif thread.target_qualname is None:
        report.error(
            "thread-target-unresolved",
            f"Thread target '{thread.target}' isn't a function defined in this file "
            "(lambdas, methods, imports and variables can't be shipped).",
            line,
        )
    for use in thread.unsupported_uses:
        report.error("thread-unsupported-attr", f"Thread attribute '.{use.name}' isn't supported remotely.", use.lineno)
    for name in thread.arg_names:
        if name in scan.sync_vars:
            report.error(
                "thread-shared-sync",
                f"Argument '{name}' is a lock/queue/event: it can't be shared across machines.",
                line,
            )
    label = thread.var_name or f"Thread at line {line}"
    if not thread.start_lines and thread.var_name and not thread.container:
        report.warn("thread-never-started", f"{label} is never started in a way the scanner can see.", line)
    if not thread.join_lines:
        report.warn(
            "thread-never-joined",
            f"{label} has no visible join(): remote changes to its arguments are only merged when it's joined.",
            line,
        )
    for join_line in thread.timed_join_lines:
        report.warn("thread-timed-join", "join(timeout) may return before the remote result arrives.", join_line)
    if thread.daemon is not None:
        report.warn("thread-daemon", f"{label} sets daemon: remote work isn't cancelled when the client exits.", line)
    if thread.loop_type == "while":
        report.warn("thread-in-while", "Thread created in a while loop: the task count is only known at runtime.", line)
    if thread.escape_lines:
        report.warn(
            "thread-escapes",
            f"{label} is passed around (line {thread.escape_lines[0]}): only start/join/is_alive/name/daemon work on it.",
            thread.escape_lines[0],
        )


def _check_target(
    qualname: str,
    tree: ast.Module,
    scan: ScanResult,
    table: symtable.SymbolTable,
    bindings: dict[str, list[tuple[str, ast.AST]]],
    star_import: bool,
    report: ValidationReport,
) -> None:
    info = next(f for f in scan.functions if f.qualname == qualname)
    line = info.lineno
    bad = len(report.issues)

    if info.classification == "recursive":
        report.error("target-recursive", f"Target '{qualname}' is recursive, which isn't supported yet.", line)
    elif info.classification == "nested":
        detail = f"calls {', '.join(info.user_calls)}" if info.user_calls else "is defined inside another function"
        report.error("target-nested", f"Target '{qualname}' {detail}, which isn't supported yet.", line)
    if info.is_method:
        report.error("target-method", f"Target '{qualname}' is a method.", line)
    if info.is_async:
        report.error("target-async", f"Target '{qualname}' is async: a Thread would never await it.", line)
    if info.is_generator:
        report.error("target-generator", f"Target '{qualname}' is a generator: its body would never run.", line)
    if info.decorators:
        report.error("target-decorated", f"Target '{qualname}' is decorated, which isn't supported yet.", line)
    top_level = info.parent is None
    if qualname in scan.duplicate_functions or (top_level and len(bindings.get(qualname, ())) != 1):
        report.error("target-ambiguous", f"Target '{qualname}' is defined or rebound more than once.", line)
    if star_import:
        report.error("target-star-import", "`from x import *` hides which names a target needs.", line)
    if len(report.issues) != bad or info.is_nested_def or info.is_method:
        return

    function = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == qualname and n.lineno == line
    )
    function_table = _function_table(table, function)
    used, declared = _globals_used(function_table)
    for name in sorted(declared):
        report.error(
            "target-global-write",
            f"Target '{qualname}' writes global '{name}': a worker's copy never reaches the client.",
            line,
        )

    deps = TargetDeps(function)
    for name in sorted((used | _signature_names(function)) - declared):
        bound = bindings.get(name)
        if bound is None:
            if name not in _BUILTINS:
                report.error("target-unknown-global", f"Target '{qualname}' uses undefined name '{name}'.", line)
            continue
        kind, node = bound[0]
        if name == "threading" or (kind == "import" and getattr(node, "module", None) == "threading"):
            report.error("target-uses-threading", f"Target '{qualname}' uses threading itself.", line)
        elif kind == "import" and len({ast.dump(n) for _, n in bound}) == 1 and all(k == "import" for k, _ in bound):
            if getattr(node, "level", 0):
                report.error("target-relative-import", f"Target '{qualname}' needs relative import '{name}'.", line)
                continue
            deps.imports.append(node)
            root = (node.module if isinstance(node, ast.ImportFrom) else node.names[0].name).partition(".")[0]
            if root not in sys.stdlib_module_names:
                report.warn("target-third-party", f"Module '{root}' must be installed on every worker.", line)
        elif kind == "constant" and len(bound) == 1:
            deps.constants.append(copy.deepcopy(node))
        else:
            report.error(
                "target-shared-state",
                f"Target '{qualname}' uses module-level '{name}' ({kind}), which a worker can't share. "
                "Pass it through args=, or make it an immutable constant.",
                line,
            )

    for param, lineno in _mutated_params(function):
        report.warn(
            "target-mutates-arg",
            f"Target '{qualname}' changes argument '{param}': workers get a copy, and changes are merged "
            "back at join(), so threads won't see each other's updates while running.",
            lineno,
        )
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "print":
                report.warn("target-prints", f"Output from '{qualname}' appears at join(), not as it's printed.", node.lineno)
                break
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("open", "input"):
            report.warn(
                "target-io",
                f"'{qualname}' calls {node.func.id}(): this runs on the worker, not the client machine.",
                node.lineno,
            )
    report.targets[qualname] = deps


def validate(tree: ast.Module, scan: ScanResult, source: str | bytes) -> ValidationReport:
    report = ValidationReport()
    if not scan.threads:
        report.issues.append(Issue(
            Severity.INFO, "no-threads", "No threading.Thread creation found: nothing to parallelize."
        ))
        return report

    for subclass in scan.thread_subclasses:
        report.error("thread-subclass", f"Thread subclass '{subclass.name}' can't be shipped.", subclass.lineno)
    for site in scan.other_concurrency:
        report.warn("other-concurrency", f"'{site.name}' isn't analysed and may interact badly with remote threads.", site.lineno)
    for thread in scan.threads:
        _check_thread_site(thread, scan, report)
    by_name = {f.qualname: f for f in scan.functions}
    for thread in scan.threads:
        parent = by_name.get(thread.parent_function or "")
        if parent and parent.is_recursive:
            report.error("thread-in-recursion", f"Thread created inside recursive function '{parent.qualname}'.", thread.lineno)

    table = symtable.symtable(source, scan.filename, "exec")
    bindings, star_import = _module_bindings(tree)
    for qualname in sorted({t.target_qualname for t in scan.threads if t.target_qualname}):
        _check_target(qualname, tree, scan, table, bindings, star_import, report)
    return report
