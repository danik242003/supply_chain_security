"""One-pass structural scan of a Python AST with ``ast.NodeVisitor``.

Besides the public :class:`ScanResult`, the scanner keeps ``rewrite_plan``: the
exact Call nodes the Mediator must replace. Sharing node identity means the
transformer never has to re-derive which ``.join()`` belongs to a thread, and
can't confuse it with ``",".join(...)`` or ``os.path.join(...)``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .models import CallSite, FunctionInfo, LoopInfo, ScanResult, ThreadInfo

MODULE_SCOPE = "<module>"
THREAD_POSITIONAL = ("group", "target", "name", "args", "kwargs")
# Attributes the Mediator's remote task object provides.
SUPPORTED_THREAD_ATTRS = frozenset({"start", "join", "is_alive", "name", "daemon"})
SYNC_CONSTRUCTORS = frozenset({
    "Lock", "RLock", "Semaphore", "BoundedSemaphore", "Event", "Condition", "Barrier",
    "Queue", "LifoQueue", "PriorityQueue", "SimpleQueue",
})
OTHER_CONCURRENCY = frozenset({"multiprocessing", "asyncio", "concurrent", "_thread"})
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def parse_thread_call(call: ast.Call) -> dict[str, ast.expr | bool]:
    """Bind a Thread(...) call's arguments to its parameter names."""
    parts: dict[str, ast.expr | bool] = {}
    for position, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred) or position >= len(THREAD_POSITIONAL):
            parts["star"] = True
        else:
            parts[THREAD_POSITIONAL[position]] = arg
    for keyword in call.keywords:
        if keyword.arg is None:
            parts["star"] = True
        else:
            parts[keyword.arg] = keyword.value
    return parts


def _dotted(node: ast.expr) -> str | None:
    """Return 'a.b.c' for a plain name chain, otherwise None."""
    pieces: list[str] = []
    while isinstance(node, ast.Attribute):
        pieces.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        pieces.append(node.id)
        return ".".join(reversed(pieces))
    return None


def _target_names(node: ast.expr) -> list[str]:
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


@dataclass(slots=True)
class _OpenLoop:
    info: LoopInfo
    assigned: set[str] = field(default_factory=set)
    reads: set[str] = field(default_factory=set)


@dataclass(slots=True)
class _Scope:
    kind: str                          # "module", "function" or "class".
    qualname: str
    parent: "_Scope | None"
    function: FunctionInfo | None = None
    locals: set[str] = field(default_factory=set)
    defs: dict[str, str] = field(default_factory=dict)
    handles: dict[str, set[int]] = field(default_factory=dict)
    containers: dict[str, set[int]] = field(default_factory=dict)
    open_loops: list[_OpenLoop] = field(default_factory=list)
    finished_loops: list[_OpenLoop] = field(default_factory=list)


class AstScanner(ast.NodeVisitor):
    def __init__(self, filename: str = "<input>") -> None:
        self.result = ScanResult(filename=filename)
        # id(Call node) -> (operation, thread index or -1).
        self.rewrite_plan: dict[int, tuple[str, int]] = {}
        self._module = _Scope("module", MODULE_SCOPE, None)
        self._scope = self._module
        self._scopes_by_qualname: dict[str, _Scope] = {MODULE_SCOPE: self._module}
        self._thread_modules: set[str] = set()
        self._thread_names: set[str] = set()
        self._consumed: set[int] = set()
        self._thread_by_call: dict[int, int] = {}
        self._pending_var: dict[int, str] = {}
        self._comp_vars: set[str] = set()
        self._thread_scopes: dict[int, _Scope] = {}

    # ---- Entry point ------------------------------------------------------

    def scan(self, tree: ast.AST) -> ScanResult:
        self.visit(tree)
        self._close_loops(self._module)
        self._resolve_functions()
        self._resolve_thread_targets()
        return self.result

    # ---- Imports ----------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.partition(".")[0]
            bound = alias.asname or root
            self._scope.locals.add(bound)
            if alias.name == "threading":
                self._thread_modules.add(bound)
            elif root in OTHER_CONCURRENCY:
                self.result.other_concurrency.append(CallSite(alias.name, node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        root = (node.module or "").partition(".")[0]
        for alias in node.names:
            self._scope.locals.add(alias.asname or alias.name)
            if node.module == "threading":
                if alias.name in ("Thread", "*"):
                    self._thread_names.add("Thread" if alias.name == "*" else alias.asname or "Thread")
                elif alias.name == "Timer":
                    self.result.other_concurrency.append(CallSite("threading.Timer", node.lineno))
            elif root in OTHER_CONCURRENCY:
                self.result.other_concurrency.append(CallSite(node.module or "", node.lineno))

    # ---- Scopes -----------------------------------------------------------

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        outer = self._scope
        qualname = node.name if outer.kind == "module" else f"{outer.qualname}.{node.name}"
        # Decorators, defaults and annotations are evaluated in the outer scope.
        for expr in node.decorator_list:
            self.visit(expr)
        self.visit(node.args)
        if node.returns:
            self.visit(node.returns)
        outer.locals.add(node.name)
        outer.defs[node.name] = qualname
        for loop in outer.open_loops:
            loop.assigned.add(node.name)

        info = FunctionInfo(
            name=node.name,
            qualname=qualname,
            lineno=node.lineno,
            end_lineno=node.end_lineno or node.lineno,
            parent=None if outer.kind == "module" else outer.qualname,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            is_method=outer.kind == "class",
            is_nested_def=outer.kind == "function",
            decorators=[ast.unparse(d) for d in node.decorator_list],
        )
        if qualname in self._scopes_by_qualname:
            self.result.duplicate_functions.append(qualname)
            self.result.functions = [f for f in self.result.functions if f.qualname != qualname]
        self.result.functions.append(info)

        scope = _Scope("function", qualname, outer, function=info)
        self._scopes_by_qualname[qualname] = scope
        args = node.args
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            scope.locals.add(arg.arg)
        if args.vararg:
            scope.locals.add(args.vararg.arg)
        if args.kwarg:
            scope.locals.add(args.kwarg.arg)

        saved_comp, self._comp_vars = self._comp_vars, set()
        self._scope = scope
        for statement in node.body:
            self.visit(statement)
        self._close_loops(scope)
        self._scope = outer
        self._comp_vars = saved_comp

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        outer = self._scope
        for base in node.bases:
            if self._is_thread_ctor(base):
                self.result.thread_subclasses.append(CallSite(node.name, node.lineno))
        for expr in (*node.decorator_list, *node.bases, *(k.value for k in node.keywords)):
            self.visit(expr)
        outer.locals.add(node.name)
        qualname = node.name if outer.kind == "module" else f"{outer.qualname}.{node.name}"
        scope = _Scope("class", qualname, outer)
        self._scope = scope
        for statement in node.body:
            self.visit(statement)
        self._close_loops(scope)
        self._scope = outer

    def visit_Yield(self, node: ast.Yield) -> None:
        if self._scope.function:
            self._scope.function.is_generator = True
        self.generic_visit(node)

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        if self._scope.function:
            self._scope.function.is_generator = True
        self.generic_visit(node)

    # ---- Comprehensions ---------------------------------------------------

    def _visit_comprehension(self, node: ast.expr) -> None:
        saved = self._comp_vars
        self._comp_vars = saved | {
            name for generator in node.generators for name in _target_names(generator.target)
        }
        self.generic_visit(node)
        self._comp_vars = saved

    visit_ListComp = _visit_comprehension
    visit_SetComp = _visit_comprehension
    visit_DictComp = _visit_comprehension
    visit_GeneratorExp = _visit_comprehension

    # ---- Loops ------------------------------------------------------------

    def _visit_loop(self, node: ast.For | ast.AsyncFor | ast.While, loop_type: str) -> None:
        scope = self._scope
        parent = scope.open_loops[-1] if scope.open_loops else None
        info = LoopInfo(
            loop_type=loop_type,
            lineno=node.lineno,
            end_lineno=node.end_lineno or node.lineno,
            parent_function=scope.function.qualname if scope.function else None,
            parent_loop_lineno=parent.info.lineno if parent else None,
            depth=len(scope.open_loops) + 1,
            is_nested=parent is not None,
            loop_vars=_target_names(node.target) if not isinstance(node, ast.While) else [],
        )
        if parent:
            parent.info.inner_loop_lines.append(node.lineno)
        self.result.loops.append(info)

        opened = _OpenLoop(info)
        scope.open_loops.append(opened)
        if isinstance(node, ast.While):
            self.visit(node.test)
        else:
            self.visit(node.iter)
            self._bind_iteration(node)
            self.visit(node.target)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)
        scope.open_loops.pop()
        scope.finished_loops.append(opened)

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop(node, "for")

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop(node, "async for")

    def visit_While(self, node: ast.While) -> None:
        self._visit_loop(node, "while")

    def _close_loops(self, scope: _Scope) -> None:
        for loop in scope.finished_loops:
            loop.info.assigned_vars = sorted(loop.assigned)
            loop.info.read_vars = sorted(loop.reads & scope.locals)
        scope.finished_loops.clear()

    def _bind_iteration(self, node: ast.For | ast.AsyncFor) -> None:
        """Track `for t in threads` and `for i, t in enumerate(threads)`."""
        iterable, target = node.iter, node.target
        if (
            isinstance(iterable, ast.Call)
            and isinstance(iterable.func, ast.Name)
            and iterable.func.id == "enumerate"
            and iterable.args
            and isinstance(target, ast.Tuple)
            and len(target.elts) == 2
        ):
            iterable, target = iterable.args[0], target.elts[1]
        if not (isinstance(iterable, ast.Name) and isinstance(target, ast.Name)):
            return
        ids = self._lookup(iterable.id, "containers")
        if ids:
            self._scope.handles[target.id] = set(ids)
        else:
            self._scope.handles.pop(target.id, None)

    # ---- Names ------------------------------------------------------------

    def _lookup(self, name: str, table: str) -> set[int]:
        if name in self._comp_vars:
            return set()
        scope: _Scope | None = self._scope
        while scope is not None:
            if name in getattr(scope, table):
                return getattr(scope, table)[name]
            if name in scope.locals and scope.kind == "function":
                return set()  # A local of the same name shadows outer handles.
            scope = scope.parent
        return set()

    def visit_Name(self, node: ast.Name) -> None:
        name = node.id
        if name in self._comp_vars:
            return
        scope = self._scope
        if isinstance(node.ctx, ast.Load):
            for loop in scope.open_loops:
                loop.reads.add(name)
            if id(node) not in self._consumed:
                for index in self._lookup(name, "handles"):
                    self.result.threads[index].escape_lines.append(node.lineno)
        else:
            scope.locals.add(name)
            for loop in scope.open_loops:
                loop.assigned.add(name)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        receiver = node.value
        if isinstance(receiver, ast.Name):
            ids = self._lookup(receiver.id, "handles")
            if ids:
                self._consumed.add(id(receiver))
                if node.attr not in SUPPORTED_THREAD_ATTRS:
                    for index in ids:
                        self.result.threads[index].unsupported_uses.append(
                            CallSite(node.attr, node.lineno)
                        )
        self.generic_visit(node)

    # ---- Assignments ------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        name = node.targets[0].id if isinstance(node.targets[0], ast.Name) else None
        value = node.value
        for call in self._thread_calls_in(value):
            self._pending_var[id(call)] = (
                name if call is value and name else ast.unparse(node.targets[0])
            )
        if isinstance(value, ast.Name) and self._lookup(value.id, "handles"):
            self._consumed.add(id(value))

        self.generic_visit(node)

        if name is None or len(node.targets) != 1:
            return
        self._record_sync_var(name, value, node.lineno)
        scope = self._scope
        scope.handles.pop(name, None)
        scope.containers.pop(name, None)
        if id(value) in self._thread_by_call:
            scope.handles[name] = {self._thread_by_call[id(value)]}
        elif isinstance(value, ast.Name) and self._lookup(value.id, "handles"):
            scope.handles[name] = set(self._lookup(value.id, "handles"))
        else:
            members = {self._thread_by_call[id(c)] for c in self._thread_calls_in(value)}
            if members:
                scope.containers[name] = members
                for index in members:
                    self.result.threads[index].container = name
            elif isinstance(value, (ast.List, ast.ListComp)):
                scope.containers[name] = set()

    def _thread_calls_in(self, value: ast.expr) -> list[ast.Call]:
        """Thread(...) directly assigned, or the elements of a list of them."""
        if self._is_thread_call(value):
            return [value]
        if isinstance(value, ast.ListComp) and self._is_thread_call(value.elt):
            return [value.elt]
        if isinstance(value, (ast.List, ast.Tuple)):
            return [e for e in value.elts if self._is_thread_call(e)]
        return []

    def _record_sync_var(self, name: str, value: ast.expr, lineno: int) -> None:
        if isinstance(value, ast.Call):
            callee = value.func
            attr = callee.attr if isinstance(callee, ast.Attribute) else getattr(callee, "id", None)
            if attr in SYNC_CONSTRUCTORS:
                self.result.sync_vars[name] = lineno

    # ---- Calls ------------------------------------------------------------

    def _is_thread_ctor(self, func: ast.expr) -> bool:
        if isinstance(func, ast.Name):
            return func.id in self._thread_names
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "Thread"
            and isinstance(func.value, ast.Name)
            and func.value.id in self._thread_modules
        )

    def _is_thread_call(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Call) and self._is_thread_ctor(node.func)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        self._record_call(node)

        # `threads.append(t)`: consume the handle before visiting children.
        append_arg = None
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "append"
            and isinstance(func.value, ast.Name)
            and len(node.args) == 1
        ):
            append_arg = node.args[0]
            if isinstance(append_arg, ast.Name) and self._lookup(append_arg.id, "handles"):
                self._consumed.add(id(append_arg))

        if self._is_thread_ctor(func):
            self._record_thread(node)
        self.generic_visit(node)

        if append_arg is not None:
            self._record_append(func.value.id, append_arg)
        if isinstance(func, ast.Attribute) and func.attr in ("start", "join"):
            self._record_start_or_join(node, func)

    def _record_call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        if name is None:
            return
        scope = self._scope
        site = CallSite(name, node.lineno)
        if scope.function:
            scope.function.calls.append(name)
            if scope.function.qualname == "main":
                self.result.main_calls.append(site)
        elif scope.kind == "module":
            self.result.module_calls.append(site)
        for loop in scope.open_loops:
            if name not in loop.info.function_calls:
                loop.info.function_calls.append(name)

    def _record_append(self, container: str, arg: ast.expr) -> None:
        ids: set[int] = set()
        if id(arg) in self._thread_by_call:
            ids = {self._thread_by_call[id(arg)]}
        elif isinstance(arg, ast.Name):
            ids = self._lookup(arg.id, "handles")
        if not ids:
            return
        self._scope.containers.setdefault(container, set()).update(ids)
        for index in ids:
            self.result.threads[index].container = container

    def _record_start_or_join(self, node: ast.Call, func: ast.Attribute) -> None:
        receiver = func.value
        if id(receiver) in self._thread_by_call:
            ids = {self._thread_by_call[id(receiver)]}
        elif isinstance(receiver, ast.Name):
            ids = self._lookup(receiver.id, "handles")
        else:
            return
        if not ids:
            return
        self.rewrite_plan[id(node)] = (func.attr, -1)
        for index in ids:
            thread = self.result.threads[index]
            if func.attr == "start":
                thread.start_lines.append(node.lineno)
            else:
                thread.join_lines.append(node.lineno)
                if node.args or node.keywords:
                    thread.timed_join_lines.append(node.lineno)

    def _record_thread(self, node: ast.Call) -> None:
        parts = parse_thread_call(node)
        scope = self._scope
        index = len(self.result.threads)

        args_node = parts.get("args")
        if isinstance(args_node, (ast.Tuple, ast.List)):
            args = [ast.unparse(e) for e in args_node.elts]
        else:
            args = [f"*{ast.unparse(args_node)}"] if args_node is not None else []
        kwargs_node = parts.get("kwargs")
        arg_names = sorted({
            n.id
            for root in (args_node, kwargs_node) if root is not None
            for n in ast.walk(root) if isinstance(n, ast.Name)
        })

        loops = scope.open_loops
        comp_vars = sorted(self._comp_vars)
        target = parts.get("target")
        thread = ThreadInfo(
            index=index,
            var_name=self._pending_var.get(id(node)),
            target=ast.unparse(target) if target is not None else None,
            target_qualname=None,
            args=args,
            kwargs=ast.unparse(kwargs_node) if kwargs_node is not None else None,
            arg_names=arg_names,
            lineno=node.lineno,
            end_lineno=node.end_lineno or node.lineno,
            parent_function=scope.function.qualname if scope.function else None,
            in_loop=bool(loops or comp_vars),
            loop_lineno=loops[-1].info.lineno if loops else (node.lineno if comp_vars else None),
            loop_type=loops[-1].info.loop_type if loops else ("comprehension" if comp_vars else None),
            iteration_vars=sorted({v for l in loops for v in l.info.loop_vars} | set(comp_vars)),
            daemon=ast.unparse(parts["daemon"]) if "daemon" in parts else None,
            name=ast.unparse(parts["name"]) if "name" in parts else None,
            has_star_args=bool(parts.get("star")),
        )
        self.result.threads.append(thread)
        self.rewrite_plan[id(node)] = ("create", index)
        self._thread_by_call[id(node)] = index
        self._thread_scopes[index] = scope
        for loop in loops:
            loop.info.creates_threads = True

    # ---- Post-processing --------------------------------------------------

    def _resolve_callee(self, scope: _Scope, name: str) -> str | None:
        if "." in name:
            base, _, attr = name.partition(".")
            owner = scope.function and scope.function.parent
            if base in ("self", "cls") and owner and "." not in attr:
                candidate = f"{owner}.{attr}"
                return candidate if candidate in self._scopes_by_qualname else None
            return None
        current: _Scope | None = scope
        while current is not None:
            if current.kind != "class" and name in current.defs:
                return current.defs[name]
            if current.kind == "function" and name in current.locals:
                return None  # Shadowed by a local variable.
            current = current.parent
        return None

    def _resolve_functions(self) -> None:
        functions = self.result.functions
        for info in functions:
            scope = self._scopes_by_qualname[info.qualname]
            resolved = (self._resolve_callee(scope, name) for name in info.calls)
            info.user_calls = sorted({q for q in resolved if q})

        main_scope = self._scopes_by_qualname.get("main")
        if main_scope:
            by_name = {f.qualname: f for f in functions}
            for site in self.result.main_calls:
                qualname = self._resolve_callee(main_scope, site.name)
                if qualname in by_name:
                    by_name[qualname].calls_from_main += 1

        recursive = _recursive_functions({f.qualname: f.user_calls for f in functions})
        for info in functions:
            info.is_recursive = info.qualname in recursive
            calls_others = any(c != info.qualname for c in info.user_calls)
            if info.is_recursive:
                info.classification = "recursive"
            elif info.is_nested_def or calls_others:
                info.classification = "nested"

    def _resolve_thread_targets(self) -> None:
        by_name = {f.qualname: f for f in self.result.functions}
        for thread in self.result.threads:
            if thread.target and thread.target.isidentifier():
                thread.target_qualname = self._resolve_callee(
                    self._thread_scopes[thread.index], thread.target
                )
                if thread.parent_function == "main" and thread.target_qualname in by_name:
                    by_name[thread.target_qualname].thread_starts_from_main += 1


def _recursive_functions(graph: dict[str, list[str]]) -> set[str]:
    """Iterative Tarjan: members of a call cycle, direct or mutual."""
    recursive = {name for name, callees in graph.items() if name in callees}
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    counter = 0
    for root in graph:
        if root in index:
            continue
        work = [(root, iter(graph[root]))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, callees = work[-1]
            for callee in callees:
                if callee not in graph:
                    continue
                if callee not in index:
                    index[callee] = low[callee] = counter
                    counter += 1
                    stack.append(callee)
                    on_stack.add(callee)
                    work.append((callee, iter(graph[callee])))
                    break
                if callee in on_stack:
                    low[node] = min(low[node], index[callee])
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == index[node]:
                    component = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.append(member)
                        if member == node:
                            break
                    if len(component) > 1:
                        recursive.update(component)
    return recursive
