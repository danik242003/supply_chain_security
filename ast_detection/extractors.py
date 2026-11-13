"""Built-in AST node visitors that turn Python source into numeric security features.

Every feature is a count or statistic computed purely from the syntax tree and
its literals; the code is never imported or executed. Call names are resolved
through the file's import aliases, so ``import base64 as b; b.b64decode(...)``
and ``from os import system; system(...)`` are recognised.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Call taxonomy
# --------------------------------------------------------------------------- #
EXEC_CALLS = frozenset({"exec", "eval", "compile", "builtins.exec", "builtins.eval", "builtins.compile"})
DYNAMIC_IMPORT_CALLS = frozenset({"__import__", "importlib.import_module", "importlib.__import__", "builtins.__import__"})
DECODE_CALLS = frozenset({
    "base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.a85decode", "base64.b85decode",
    "base64.urlsafe_b64decode", "base64.decodebytes", "codecs.decode", "binascii.unhexlify",
    "binascii.a2b_base64", "binascii.a2b_hex", "bytes.fromhex", "zlib.decompress", "bz2.decompress",
    "lzma.decompress", "gzip.decompress", "marshal.loads", "pickle.loads",
})
NETWORK_CALLS = frozenset({
    "urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve", "urllib.urlopen",
    "urllib2.urlopen", "requests.get", "requests.post", "requests.put", "requests.request",
    "http.client.HTTPConnection", "http.client.HTTPSConnection", "socket.socket", "socket.create_connection",
    "socket.gethostbyname", "socket.getaddrinfo", "ftplib.FTP", "smtplib.SMTP", "httpx.get", "httpx.post",
})
PROCESS_PREFIXES = ("subprocess.", "os.exec", "os.spawn", "pty.")
PROCESS_CALLS = frozenset({"os.system", "os.popen", "os.startfile", "commands.getoutput"})
FILE_WRITE_CALLS = frozenset({
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move", "shutil.rmtree", "os.chmod",
    "os.rename", "os.replace", "os.remove", "os.unlink", "os.makedirs",
})
FILE_WRITE_METHODS = frozenset({"write_text", "write_bytes"})
ENV_CALLS = frozenset({"os.getenv", "os.environ.get", "os.environ.copy", "os.environ.items"})
RECON_CALLS = frozenset({
    "platform.node", "platform.uname", "platform.system", "platform.platform", "socket.gethostname",
    "getpass.getuser", "os.getlogin", "os.getcwd", "os.uname", "uuid.getnode",
})
REFLECTION_CALLS = frozenset({"globals", "locals", "vars"})
THREAD_CALLS = frozenset({"threading.Thread", "multiprocessing.Process", "_thread.start_new_thread"})
INSTALL_COMMAND_BASES = ("install", "develop", "egg_info", "build_py", "sdist", "build_ext", "bdist_wheel")
SENSITIVE_PATH_MARKERS = (
    ".ssh", "id_rsa", ".aws", "credentials", "/etc/passwd", "/etc/shadow", ".bashrc", ".profile",
    ".zshrc", "site-packages", ".pth", "autostart", "crontab", ".git-credentials", ".npmrc", ".pypirc",
    "Login Data", "keychain", ".kube/config", ".docker/config.json",
)

_URL = re.compile(r"[a-z][a-z0-9+.-]*://", re.I)
_IP_URL = re.compile(r"[a-z]+://\d{1,3}(?:\.\d{1,3}){3}", re.I)
_ENCODED = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")
_HEX = re.compile(r"^(?:[0-9a-fA-F]{2}){20,}$")

#: Ordered list of per-file feature names emitted by :class:`SecurityFeatureExtractor`.
FILE_FEATURES: tuple[str, ...] = (
    "lines", "nodes", "max_depth", "functions", "classes", "imports",
    "exec_calls", "dynamic_imports", "decode_calls", "network_calls", "process_calls",
    "file_write_calls", "env_access", "recon_calls", "reflection_calls", "thread_starts",
    "chr_calls", "string_concat_ops", "string_reversals", "silent_excepts",
    "module_level_dangerous", "exec_of_decoded", "install_hook_classes", "cmdclass_keywords",
    "strings", "max_string_len", "max_string_entropy", "high_entropy_strings", "encoded_strings",
    "url_literals", "ip_url_literals", "sensitive_path_literals", "parse_error",
)


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _fold_str(node: ast.AST) -> str | None:
    """Statically fold string constants joined with ``+`` (e.g. ``"ex" + "ec"``)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold_str(node.left), _fold_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _dotted(node: ast.AST) -> str | None:
    """``a.b.c`` for Name/Attribute chains, else ``None``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


MAX_NODES_PER_FILE = 200
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class RiskyNode:
    """One AST node worth showing to an analyst (location + why it matters)."""

    path: str
    line: int
    col: int
    end_line: int
    end_col: int
    node: str                 # AST node type, e.g. "Call", "ClassDef", "Constant"
    name: str                 # resolved call / class / literal preview
    categories: list[str]
    severity: str             # low | medium | high | critical
    module_level: bool        # runs at import time

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable representation."""
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


@dataclass
class FileFeatures:
    """Feature counts and flagged nodes for one source file."""

    path: str
    values: dict[str, float] = field(default_factory=lambda: dict.fromkeys(FILE_FEATURES, 0.0))
    is_install: bool = False
    nodes: list[RiskyNode] = field(default_factory=list)


class SecurityFeatureExtractor(ast.NodeVisitor):
    """Single-pass visitor collecting security-relevant syntactic features.

    Args:
        path: Package-relative file path (``setup.py`` is treated as install-time code).
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.result = FileFeatures(path=path, is_install=path.rsplit("/", 1)[-1] == "setup.py")
        self._v = self.result.values
        self._aliases: dict[str, str] = {}
        self._func_depth = 0
        self._depth = 0

    # Public API ---------------------------------------------------------- #
    def extract(self, source: str | bytes) -> FileFeatures:
        """Parse ``source`` and return its features (``parse_error = 1`` if it cannot be parsed)."""
        text = source.decode("utf-8", "replace") if isinstance(source, bytes) else source
        self._v["lines"] = float(text.count("\n") + 1)
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            self._v["parse_error"] = 1.0
            return self.result
        self._collect_aliases(tree)
        self.visit(tree)
        return self.result

    # Helpers ------------------------------------------------------------- #
    def _collect_aliases(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self._aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    self._aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def _resolve(self, func: ast.expr) -> str | None:
        name = _dotted(func)
        if name is None:
            return self._resolve_dynamic_module(func)
        head, _, rest = name.partition(".")
        base = self._aliases.get(head, head)
        return f"{base}.{rest}" if rest else base

    def _resolve_dynamic_module(self, func: ast.expr) -> str | None:
        """``__import__("base64").b64decode`` / ``importlib.import_module("os").system`` -> ``base64.b64decode``."""
        attrs: list[str] = []
        node = func
        while isinstance(node, ast.Attribute):
            attrs.append(node.attr)
            node = node.value
        if not attrs or not isinstance(node, ast.Call) or not node.args:
            return None
        loader = _dotted(node.func)
        loader = self._aliases.get(loader, loader) if loader else None
        module = _fold_str(node.args[0])
        if loader in DYNAMIC_IMPORT_CALLS and module:
            return ".".join([module, *reversed(attrs)])
        return None

    def _bump(self, key: str, amount: float = 1.0) -> None:
        self._v[key] += amount

    def _flag(self, node: ast.AST, name: str, categories: list[str], severity: str) -> None:
        """Record a risky node; install-time (setup.py) and import-time code is escalated one level."""
        if len(self.result.nodes) >= MAX_NODES_PER_FILE:
            return
        module_level = self._func_depth == 0
        if (self.result.is_install or module_level) and severity in ("low", "medium") and any(
            c in ("exec", "process", "network", "dynamic_import") for c in categories
        ):
            severity = "high"
        self.result.nodes.append(RiskyNode(
            path=self.path, line=getattr(node, "lineno", 0), col=getattr(node, "col_offset", 0),
            end_line=getattr(node, "end_lineno", None) or getattr(node, "lineno", 0),
            end_col=getattr(node, "end_col_offset", None) or 0,
            node=type(node).__name__, name=name[:80], categories=categories, severity=severity,
            module_level=module_level,
        ))

    # Generic traversal ---------------------------------------------------- #
    def generic_visit(self, node: ast.AST) -> None:
        """Count nodes and track maximum tree depth for every node visited."""
        self._v["nodes"] += 1
        self._depth += 1
        self._v["max_depth"] = max(self._v["max_depth"], self._depth)
        super().generic_visit(node)
        self._depth -= 1

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        if not isinstance(node, ast.Lambda):
            self._bump("functions")
        self._func_depth += 1
        self.generic_visit(node)
        self._func_depth -= 1

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function
    visit_Lambda = _visit_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Count classes; flag setuptools command subclasses overriding ``run()`` (install hooks)."""
        self._bump("classes")
        bases = [(_dotted(b) or "").rsplit(".", 1)[-1] for b in node.bases]
        has_run = any(isinstance(n, ast.FunctionDef) and n.name == "run" for n in node.body)
        if has_run and any(b in INSTALL_COMMAND_BASES for b in bases):
            self._bump("install_hook_classes")
            self._flag(node, f"class {node.name}({', '.join(bases)})", ["install_hook"], "medium")
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Count ``import`` statements."""
        self._bump("imports", len(node.names))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Count ``from ... import`` statements."""
        self._bump("imports", len(node.names))
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Count silent exception handlers (``except: pass``), a common payload-hiding idiom."""
        for handler in node.handlers:
            if len(handler.body) == 1 and isinstance(handler.body[0], (ast.Pass, ast.Continue)):
                self._bump("silent_excepts")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Count and flag string-literal concatenation (``"ex" + "ec"``) used to hide names."""
        if isinstance(node.op, ast.Add) and all(
            isinstance(side, ast.Constant) and isinstance(side.value, str) for side in (node.left, node.right)
        ):
            self._bump("string_concat_ops")
            self._flag(node, repr(node.left.value + node.right.value)[:40], ["obfuscation"], "low")  # type: ignore[union-attr]
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Count and flag reversed string literals (``"..."[::-1]``)."""
        sl = node.slice
        if (
            isinstance(sl, ast.Slice) and isinstance(sl.step, ast.UnaryOp) and isinstance(sl.step.op, ast.USub)
            and isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes))
        ):
            self._bump("string_reversals")
            self._flag(node, "string[::-1]", ["obfuscation"], "medium")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Count ``os.environ`` access."""
        if self._resolve(node) == "os.environ":
            self._bump("env_access")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Profile string literals: length, entropy, encoded blobs, URLs, raw-IP URLs, sensitive paths."""
        value = node.value
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if isinstance(value, str):
            self._bump("strings")
            self._v["max_string_len"] = max(self._v["max_string_len"], float(len(value)))
            if len(value) >= 16:
                entropy = shannon_entropy(value)
                self._v["max_string_entropy"] = max(self._v["max_string_entropy"], entropy)
                if entropy > 4.5:
                    self._bump("high_entropy_strings")
            literal_flags: list[str] = []
            if _ENCODED.match(value) or _HEX.match(value):
                self._bump("encoded_strings")
                literal_flags.append("encoded_blob")
            if _URL.search(value):
                self._bump("url_literals")
            if _IP_URL.search(value):
                self._bump("ip_url_literals")
                literal_flags.append("raw_ip_url")
            if any(marker in value for marker in SENSITIVE_PATH_MARKERS):
                self._bump("sensitive_path_literals")
                literal_flags.append("sensitive_path")
            if literal_flags:
                preview = value if len(value) <= 40 else value[:37] + "..."
                self._flag(node, repr(preview), literal_flags, "medium")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Classify a call (exec, decode, network, process, file write, ...) and flag it with a severity."""
        name = self._resolve(node.func) or ""
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        # getattr(builtins, "ex" + "ec")(...) is an exec call in disguise.
        inner = node.func
        if (isinstance(inner, ast.Call) and self._resolve(inner.func) == "getattr" and len(inner.args) >= 2
                and _fold_str(inner.args[1]) in ("exec", "eval", "compile", "__import__")):
            folded = _fold_str(inner.args[1]) or ""
            name = "__import__" if folded == "__import__" else f"builtins.{folded}"
        dangerous = False
        cats: list[str] = []
        severity = "low"

        if name in EXEC_CALLS or name.endswith((".exec", ".eval")) and "builtins" in name:
            self._bump("exec_calls")
            dangerous = True
            cats.append("exec")
            severity = "medium"
            if node.args and self._contains_decode(node.args[0]):
                self._bump("exec_of_decoded")
                cats.append("exec_of_decoded")
                severity = "critical"
        if name == "getattr" and len(node.args) >= 2:
            target = _dotted(node.args[0]) or ""
            if not isinstance(node.args[1], ast.Constant) or "builtins" in target:
                self._bump("reflection_calls")
                dangerous = dangerous or "builtins" in target
                cats.append("reflection")
                if "builtins" in target:
                    severity = max(severity, "high", key=SEVERITY_RANK.__getitem__)
        if name in REFLECTION_CALLS:
            self._bump("reflection_calls")
            cats.append("reflection")
        if name in DYNAMIC_IMPORT_CALLS:
            self._bump("dynamic_imports")
            cats.append("dynamic_import")
        if name in DECODE_CALLS or method == "fromhex":
            self._bump("decode_calls")
            cats.append("decode")
        if name in NETWORK_CALLS:
            self._bump("network_calls")
            dangerous = True
            cats.append("network")
        if name in PROCESS_CALLS or name.startswith(PROCESS_PREFIXES):
            self._bump("process_calls")
            dangerous = True
            cats.append("process")
        if name in FILE_WRITE_CALLS or method in FILE_WRITE_METHODS or self._is_write_open(name, node):
            self._bump("file_write_calls")
            cats.append("file_write")
        if name in ENV_CALLS:
            self._bump("env_access")
            cats.append("env")
        if name in RECON_CALLS:
            self._bump("recon_calls")
            cats.append("recon")
        if name in THREAD_CALLS:
            self._bump("thread_starts")
            cats.append("thread")
        if name == "chr":
            self._bump("chr_calls")
        if name.rsplit(".", 1)[-1] == "setup" and any(k.arg == "cmdclass" for k in node.keywords):
            self._bump("cmdclass_keywords")
        if dangerous and self._func_depth == 0:
            self._bump("module_level_dangerous")
        if cats and cats != ["thread"] or (cats == ["thread"] and self._func_depth == 0):
            if any(c in ("network", "process") for c in cats) or (
                (self._func_depth == 0 or self.result.is_install)
                and any(c in ("file_write", "decode", "env") for c in cats)
            ):
                severity = max(severity, "medium", key=SEVERITY_RANK.__getitem__)
            self._flag(node, name or method or "<call>", cats, severity)
        self.generic_visit(node)

    def _contains_decode(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                name = self._resolve(sub.func) or ""
                method = sub.func.attr if isinstance(sub.func, ast.Attribute) else ""
                if name in DECODE_CALLS or method in ("fromhex", "decode") or name.endswith("decompress"):
                    return True
        return False

    @staticmethod
    def _is_write_open(name: str, node: ast.Call) -> bool:
        if name not in ("open", "io.open", "codecs.open"):
            return False
        mode: ast.expr | None = node.args[1] if len(node.args) > 1 else None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode = kw.value
        return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+")


def extract_file_features(path: str, source: str | bytes) -> FileFeatures:
    """Convenience wrapper: features for one file."""
    return SecurityFeatureExtractor(path).extract(source)


#: Counts summed across files; everything else (max_*) is maximised.
_MAX_FEATURES = frozenset({"max_depth", "max_string_len", "max_string_entropy"})

#: Calls that matter most when they run during installation.
_INSTALL_DANGER = ("exec_calls", "network_calls", "process_calls", "decode_calls", "env_access", "recon_calls")

#: Weights for the built-in heuristic static risk (used when astmaster is unavailable).
_HEURISTIC_WEIGHTS: dict[str, float] = {
    "exec_of_decoded": 2.0, "install_dangerous_calls": 0.6, "module_level_dangerous": 0.4,
    "exec_calls": 0.4, "ip_url_literals": 0.6, "sensitive_path_literals": 0.5, "encoded_strings": 0.3,
    "reflection_calls": 0.3, "install_hook_classes": 0.3, "string_concat_ops": 0.1, "chr_calls": 0.05,
}


def aggregate_package(files: list[FileFeatures]) -> dict[str, float]:
    """Combine per-file features into one package vector (``ast_*`` names).

    Adds package-level features: ``ast_n_files``, ``ast_install_dangerous_calls``
    (dangerous calls inside ``setup.py``) and ``ast_builtin_risk`` (a bounded
    heuristic score in [0, 1)).
    """
    agg = dict.fromkeys(FILE_FEATURES, 0.0)
    install_danger = 0.0
    for f in files:
        for key, value in f.values.items():
            agg[key] = max(agg[key], value) if key in _MAX_FEATURES else agg[key] + value
        if f.is_install:
            install_danger += sum(f.values[k] for k in _INSTALL_DANGER)
    agg["install_dangerous_calls"] = install_danger
    agg["n_files"] = float(len(files))
    raw = sum(w * min(agg.get(k, 0.0), 5.0) for k, w in _HEURISTIC_WEIGHTS.items())
    agg["builtin_risk"] = 1.0 - math.exp(-raw / 2.0)
    return {f"ast_{k}": float(v) for k, v in agg.items()}
