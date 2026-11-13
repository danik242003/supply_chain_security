"""Plain metadata produced by the scanner.

These objects hold no AST nodes, so they are cheap to pickle across a process
pool and straightforward to persist in SQLite later.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"      # Blocks parallel execution.
    WARNING = "warning"  # Allowed, but behaviour may differ: alert the user.
    INFO = "info"


@dataclass(slots=True)
class Issue:
    severity: Severity
    code: str
    message: str
    lineno: int | None = None


@dataclass(slots=True)
class CallSite:
    name: str
    lineno: int


@dataclass(slots=True)
class FunctionInfo:
    name: str
    qualname: str
    lineno: int
    end_lineno: int
    parent: str | None = None          # Enclosing function or class qualname.
    is_async: bool = False
    is_method: bool = False
    is_generator: bool = False
    decorators: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)       # Every callee, as written.
    user_calls: list[str] = field(default_factory=list)  # Callees defined in this file.
    calls_from_main: int = 0
    thread_starts_from_main: int = 0   # Thread(target=this) created in main().
    is_nested_def: bool = False
    is_recursive: bool = False
    classification: str = "neither"    # "recursive", "nested" or "neither".


@dataclass(slots=True)
class LoopInfo:
    loop_type: str                     # "for", "async for" or "while".
    lineno: int
    end_lineno: int
    parent_function: str | None
    parent_loop_lineno: int | None
    depth: int
    is_nested: bool
    inner_loop_lines: list[int] = field(default_factory=list)
    function_calls: list[str] = field(default_factory=list)
    loop_vars: list[str] = field(default_factory=list)
    assigned_vars: list[str] = field(default_factory=list)
    read_vars: list[str] = field(default_factory=list)  # Reads of locals only.
    creates_threads: bool = False


@dataclass(slots=True)
class ThreadInfo:
    index: int
    var_name: str | None
    target: str | None                 # The target expression, as written.
    target_qualname: str | None        # Resolved function in this file, if any.
    args: list[str]
    kwargs: str | None
    arg_names: list[str]
    lineno: int
    end_lineno: int
    parent_function: str | None
    in_loop: bool = False
    loop_lineno: int | None = None
    loop_type: str | None = None
    iteration_vars: list[str] = field(default_factory=list)
    container: str | None = None       # e.g. the `threads` in threads.append(t).
    daemon: str | None = None
    name: str | None = None
    has_star_args: bool = False
    start_lines: list[int] = field(default_factory=list)
    join_lines: list[int] = field(default_factory=list)
    timed_join_lines: list[int] = field(default_factory=list)
    unsupported_uses: list[CallSite] = field(default_factory=list)
    escape_lines: list[int] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    filename: str
    functions: list[FunctionInfo] = field(default_factory=list)
    loops: list[LoopInfo] = field(default_factory=list)
    threads: list[ThreadInfo] = field(default_factory=list)
    main_calls: list[CallSite] = field(default_factory=list)
    module_calls: list[CallSite] = field(default_factory=list)
    duplicate_functions: list[str] = field(default_factory=list)
    thread_subclasses: list[CallSite] = field(default_factory=list)
    other_concurrency: list[CallSite] = field(default_factory=list)
    sync_vars: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        values = dict(data)
        values["functions"] = [FunctionInfo(**f) for f in data["functions"]]
        values["loops"] = [LoopInfo(**l) for l in data["loops"]]
        values["threads"] = [
            ThreadInfo(**{**t, "unsupported_uses": [CallSite(**u) for u in t["unsupported_uses"]]})
            for t in data["threads"]
        ]
        for name in ("main_calls", "module_calls", "thread_subclasses", "other_concurrency"):
            values[name] = [CallSite(**c) for c in data[name]]
        return cls(**values)


class DatabaseLocationError(RuntimeError):
    """The SQLite file can't be created or opened. The message says where and how to fix it."""
