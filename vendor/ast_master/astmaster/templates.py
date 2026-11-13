"""Reusable task templates.

A template is built once per target function. ``finalize()`` adds only the
binding statements for one set of runtime values and shares the function's AST,
so a loop of N iterations costs N small bindings rather than N deep copies.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import math
from dataclasses import dataclass, field

from .models import ScanResult
from .validation import TargetDeps

_SCALARS = (bool, int, str, bytes, type(None))


def ensure_literal(value: object, _depth: int = 0) -> None:
    """Accept only exact builtin data types: they round-trip through repr safely."""
    if _depth > 100:
        raise ValueError("runtime value is nested too deeply")
    kind = type(value)
    if kind in _SCALARS:
        return
    if kind in (float, complex):
        parts = (value.real, value.imag) if kind is complex else (value,)
        if all(math.isfinite(p) for p in parts):
            return
        raise ValueError(f"non-finite number can't be sent to a worker: {value!r}")
    if kind in (list, tuple, set):
        for item in value:
            ensure_literal(item, _depth + 1)
    elif kind is dict:
        for key, item in value.items():
            ensure_literal(key, _depth + 1)
            ensure_literal(item, _depth + 1)
    else:
        raise ValueError(f"value of type {kind.__name__} can't be sent to a worker")


def _literal_node(value: object) -> ast.expr:
    if type(value) in _SCALARS:
        return ast.Constant(value)
    return ast.parse(repr(value), mode="eval").body


def _signature(function: ast.FunctionDef) -> inspect.Signature:
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    first_default = len(positional) - len(args.defaults)
    empty = inspect.Parameter.empty
    params = []
    for position, arg in enumerate(positional):
        kind = (
            inspect.Parameter.POSITIONAL_ONLY if position < len(args.posonlyargs)
            else inspect.Parameter.POSITIONAL_OR_KEYWORD
        )
        default = None if position >= first_default else empty
        params.append(inspect.Parameter(arg.arg, kind, default=default))
    if args.vararg:
        params.append(inspect.Parameter(args.vararg.arg, inspect.Parameter.VAR_POSITIONAL))
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        params.append(inspect.Parameter(
            arg.arg, inspect.Parameter.KEYWORD_ONLY, default=None if default else empty
        ))
    if args.kwarg:
        params.append(inspect.Parameter(args.kwarg.arg, inspect.Parameter.VAR_KEYWORD))
    return inspect.Signature(params)


@dataclass(slots=True)
class TemplateSite:
    """Where in the client program this template gets used."""

    lineno: int
    parent_function: str | None
    in_loop: bool
    loop_lineno: int | None
    loop_type: str | None
    iteration_vars: list[str]


@dataclass(slots=True)
class FinalizedTask:
    template_id: str
    module: ast.Module
    args: tuple
    kwargs: dict
    source: str


@dataclass(slots=True)
class Template:
    template_id: str
    target: str
    body: ast.Module
    sites: list[TemplateSite] = field(default_factory=list)
    _signature: inspect.Signature = field(init=False, repr=False)
    _body_source: str = field(init=False, repr=False)
    _call: ast.stmt = field(init=False, repr=False)

    def __post_init__(self) -> None:
        function = next(n for n in reversed(self.body.body) if isinstance(n, ast.FunctionDef))
        self._signature = _signature(function)
        self._body_source = ast.unparse(self.body)
        self._call = ast.parse(f"__result__ = {self.target}(*__args__, **__kwargs__)").body[0]

    @property
    def source(self) -> str:
        return self._body_source

    @property
    def is_loop_template(self) -> bool:
        return any(site.in_loop for site in self.sites)

    def finalize(self, args=(), kwargs=None) -> FinalizedTask:
        """Bind runtime values. Raises TypeError or ValueError if they don't fit."""
        args = tuple(args)
        kwargs = dict(kwargs or {})
        self._signature.bind(*args, **kwargs)
        ensure_literal(args)
        ensure_literal(kwargs)
        binding = [
            ast.Assign([ast.Name("__args__", ast.Store())], _literal_node(args)),
            ast.Assign([ast.Name("__kwargs__", ast.Store())], _literal_node(kwargs)),
        ]
        for statement in binding:
            ast.fix_missing_locations(statement)
        source = "\n".join((self._body_source, *map(ast.unparse, binding), ast.unparse(self._call)))
        module = ast.Module(body=[*self.body.body, *binding, self._call], type_ignores=[])
        return FinalizedTask(self.template_id, module, args, kwargs, source)

    def to_dict(self) -> dict:
        """Serialize for storage or for sending to a worker."""
        return {
            "template_id": self.template_id,
            "target": self.target,
            "source": self._body_source,
            "sites": [
                {name: getattr(site, name) for name in TemplateSite.__slots__}
                for site in self.sites
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Template":
        return cls(
            template_id=data["template_id"],
            target=data["target"],
            body=ast.parse(data["source"]),
            sites=[TemplateSite(**site) for site in data["sites"]],
        )


def build_templates(
    scan: ScanResult, targets: dict[str, TargetDeps]
) -> tuple[list[Template], dict[int, str]]:
    """Build one template per target. Returns (templates, thread index -> id)."""
    templates: dict[str, Template] = {}
    thread_templates: dict[int, str] = {}
    for thread in scan.threads:
        target = thread.target_qualname
        if target not in templates:
            deps = targets[target]
            future = [
                n for n in deps.imports
                if isinstance(n, ast.ImportFrom) and n.module == "__future__"
            ]
            others = [n for n in deps.imports if n not in future]
            body = ast.Module(body=[*future, *others, *deps.constants, deps.function], type_ignores=[])
            for node in body.body:
                ast.fix_missing_locations(node)
            digest = hashlib.sha256(ast.unparse(body).encode("utf-8", "surrogatepass")).hexdigest()
            templates[target] = Template(digest[:16], target, body)
        template = templates[target]
        template.sites.append(TemplateSite(
            lineno=thread.lineno,
            parent_function=thread.parent_function,
            in_loop=thread.in_loop,
            loop_lineno=thread.loop_lineno,
            loop_type=thread.loop_type,
            iteration_vars=thread.iteration_vars,
        ))
        thread_templates[thread.index] = template.template_id
    return list(templates.values()), thread_templates
