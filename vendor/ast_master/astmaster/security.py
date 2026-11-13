"""Static supply chain checks. Nothing here ever executes the scanned code.

The visitor records *signals* (facts about a file) and ``rate_file`` turns them
into *findings* (severities), based on when the code runs and on combinations of
capabilities. Keeping these apart means signals can be cached by content hash,
while a file's rating can still change with its context, such as a helper module
that setup.py imports.

Names are resolved after the whole file has been visited, so reordering code
can't dodge detection. A small evaluator folds pure expressions ("ex" + "ec",
base64, zlib...) without running anything, and decoded Python is scanned too.
"""

from __future__ import annotations

import ast
import base64
import binascii
import bz2
import codecs
import lzma
import math
import pickletools
import re
import struct
import unicodedata
import zlib
from collections import Counter
from dataclasses import asdict, dataclass, field

RULES_VERSION = 5
SEVERITIES = ("low", "medium", "high", "critical")
_MAX_DECODED = 2 * 1024 * 1024
_MAX_PAYLOAD_DEPTH = 3
_MAX_PER_RULE = 20


@dataclass(frozen=True, slots=True)
class Rule:
    caps: frozenset[str]
    message: str
    install: str
    imported: str
    runtime: str


def _rule(caps: str, message: str, install: str, imported: str | None = None, runtime: str | None = None) -> Rule:
    imported = imported or install
    return Rule(frozenset(caps.split()), message, install, imported, runtime or imported)


RULES: dict[str, Rule] = {
    # Dynamic code execution.
    "exec-decoded": _rule("exec obfuscation", "Executes code that was decoded or de-obfuscated at runtime", "critical"),
    "exec-network": _rule("exec network", "Executes code downloaded from the network", "critical"),
    "hidden-code": _rule("exec obfuscation", "Encoded payload contains code with dangerous capabilities", "critical"),
    "exec-dynamic": _rule("exec", "exec/eval/compile on a value that isn't constant", "high", "high", "low"),
    "exec-constant": _rule("", "exec/eval on a constant string", "low"),
    "exec-local-file": _rule("", "Executes a local .py file (often a version loader)", "low"),
    "exec-data-file": _rule("exec", "Executes the contents of a file that isn't Python source", "high", "high", "medium"),
    "deserialize-code": _rule("exec", "marshal.loads can load executable code objects", "high", "high", "medium"),
    "deserialize-pickle": _rule("exec", "Unpickles data, which can run code", "high", "medium", "low"),
    "dynamic-import": _rule("exec", "Imports a module whose name isn't constant", "high", "medium", "low"),
    "obfuscated-access": _rule("obfuscation", "Reaches a dangerous function through reflection or a built-up name", "high", "high", "medium"),
    "obfuscated-name": _rule("obfuscation", "Assembles the name of a dangerous function or module from pieces", "high"),
    "dynamic-reflection": _rule("obfuscation", "Looks up a function on a sensitive module by a computed name", "high", "high", "medium"),
    "code-object": _rule("exec", "Builds a function directly from a code object", "high", "high", "medium"),
    "hidden-sink": _rule("exec obfuscation", "Runs code or a command through a function reached by reflection", "critical"),
    # Commands.
    "shell-dangerous": _rule("shell", "Runs a command matching a known attack pattern", "critical", "critical", "high"),
    "shell-dynamic": _rule("shell", "Runs a command that isn't constant", "high", "high", "low"),
    "shell-static": _rule("shell", "Runs an external command", "high", "high", "low"),
    "shell-build-tool": _rule("", "Runs a common build tool", "low"),
    "script-dangerous": _rule("shell", "Script contains a known attack pattern", "high"),
    # Network and data access.
    "network-call": _rule("network", "Makes a network request", "high", "medium", "low"),
    "suspicious-host": _rule("network", "References a service often used for payloads or exfiltration", "high", "high", "medium"),
    "log-shipping": _rule("network", "Attaches a logging handler that sends records to a remote host", "high", "high", "medium"),
    "raw-ip-url": _rule("network", "URL points at a raw public IP address", "medium", "medium", "low"),
    "secret-path": _rule("secret", "References a credential file", "high", "medium", "low"),
    "secret-env": _rule("secret", "Reads a sensitive environment variable", "high", "medium", "low"),
    "secret-env-dump": _rule("secret", "Reads the whole environment", "low"),
    "recon": _rule("recon", "Collects host or user identity", "low"),
    # Hiding and persistence.
    "decoder": _rule("obfuscation", "Decodes or decompresses data", "low"),
    "opaque-string": _rule("obfuscation", "Long high-entropy string that couldn't be decoded", "low"),
    "import-hook": _rule("persist", "Adds an import hook, which can rewrite modules imported later", "high", "high", "medium"),
    "tls-disabled": _rule("", "Turns off TLS certificate checks for the whole process", "high"),
    "persistence": _rule("persist", "References a location used for persistence", "high", "medium", "low"),
    "self-delete": _rule("persist", "Deletes its own file", "high", "high", "medium"),
    "silent-sink": _rule("", "Dangerous call wrapped in an except that hides all failures", "medium", "medium", "low"),
    "native-code": _rule("", "Loads native code with ctypes", "medium", "low"),
    "whitespace-hidden": _rule("obfuscation", "Code pushed out of view by a long run of whitespace", "high"),
    "bidi-control": _rule("obfuscation", "Bidirectional control characters can make code display misleadingly", "high"),
    "mixed-script": _rule("obfuscation", "Identifier mixes alphabets (possible look-alike)", "medium"),
    # Packaging.
    "install-hook": _rule("", "setup.py overrides install commands", "low"),
    "dependency-link": _rule("", "setup.py uses dependency_links to fetch from a custom location", "high"),
    "known-malicious-dep": _rule("", "Depends on a package name known to have been malicious", "critical"),
    "typosquat-dep": _rule("", "Dependency name is one edit away from a popular package", "high"),
    "requirement-url": _rule("", "Requirement installs directly from a URL or VCS", "medium"),
    "extra-index": _rule("", "Adds a package index, which enables dependency confusion", "high"),
    "custom-backend": _rule("", "Build backend is loaded from this repository", "medium"),
    "pth-exec": _rule("exec", ".pth file runs code at every Python startup", "high"),
    "symlink-escape": _rule("", "Symlink points outside the repository", "high"),
    "opaque-binary": _rule("", "Compiled or packed file can't be audited from source", "medium"),
    # Coverage problems: not evidence of an attack, but not evidence of safety.
    "unparsed": _rule("", "Python file couldn't be parsed, so it wasn't analyzed", "medium"),
    "too-complex": _rule("", "File is nested too deeply to analyze", "medium"),
    "too-large": _rule("", "File is too large to analyze", "medium"),
    "unreadable": _rule("", "File couldn't be read", "medium"),
    "skipped-venv": _rule("", "Virtual environment was not scanned", "low"),
    # Combinations, produced by rate_file.
    "exfiltration": _rule("", "Reads secrets and also uses the network", "critical", "critical", "medium"),
    "credential-exfiltration": _rule("", "Reads credential files and uses the network in the same function", "critical", "critical", "high"),
    "env-exfiltration": _rule("", "Sends the whole environment over the network", "critical"),
    "recon-exfiltration": _rule("", "Collects host identity and also uses the network", "high"),
    # Medium alone, because that's also what an authenticated API client looks like.
    "function-exfiltration": _rule("", "One function reads a secret and uses the network", "medium"),
    "silent-exfiltration": _rule("", "One function reads a secret and uses the network, hiding any failure", "critical"),
    "obfuscated-sink": _rule("", "Combines decoding with command, network or code execution", "critical", "high", "low"),
    "download-execute": _rule("", "Combines network access with dynamic code execution", "critical", "high", "low"),
    # Phase 3.
    "cluster-attack-match": _rule("", "Structure closely resembles a known attack pattern", "high", "high", "medium"),
}

COVERAGE_RULES = frozenset({"unparsed", "too-complex", "too-large", "unreadable", "opaque-binary"})

_EXEC = {"exec", "eval", "compile", "runpy.run_path", "runpy.run_module"}
_SHELL = {
    "os.system", "os.popen", "pty.spawn", "commands.getoutput", "commands.getstatusoutput",
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec", "os.posix_spawn", "os.posix_spawnp",
}
_SHELL_PREFIX = re.compile(r"os\.(exec|spawn)[lv]p?e?$")
_NETWORK = {
    "socket.socket", "socket.create_connection", "socket.gethostbyname", "socket.getaddrinfo",
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib2.urlopen", "urllib.urlopen", "urllib.urlretrieve",
    "http.client.HTTPConnection", "http.client.HTTPSConnection", "httplib.HTTPConnection", "httplib.HTTPSConnection",
    "ftplib.FTP", "ftplib.FTP_TLS", "smtplib.SMTP", "smtplib.SMTP_SSL", "telnetlib.Telnet",
    "xmlrpc.client.ServerProxy", "paramiko.SSHClient", "aiohttp.ClientSession", "urllib3.PoolManager",
    "dns.resolver.resolve", "dns.resolver.query", "websocket.create_connection", "requests.Session", "httpx.Client",
    "httpx.AsyncClient",
}
_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
_RECON = {"socket.gethostname", "getpass.getuser", "os.getlogin", "platform.node", "uuid.getnode", "os.uname"}
_NATIVE = {"ctypes.CDLL", "ctypes.cdll.LoadLibrary", "ctypes.WinDLL", "ctypes.windll", "ctypes.LibraryLoader"}
_REMOVERS = {"os.remove", "os.unlink", "shutil.rmtree"}
_LOG_SENDERS = {
    "logging.handlers.HTTPHandler", "logging.handlers.SocketHandler", "logging.handlers.DatagramHandler",
    "logging.handlers.SMTPHandler",
}
_CODE_BUILDERS = {"types.FunctionType", "types.CodeType"}
_IMPORT_HOOKS = {f"sys.{hook}.{method}" for hook in ("meta_path", "path_hooks") for method in ("insert", "append", "extend")}
_TLS_SWITCH = "ssl._create_default_https_context"
# Looking up this machine's own name, which sends nothing chosen by the code.
_NAME_LOOKUPS = {"socket.gethostbyname", "socket.getaddrinfo"}
_OWN_NAME_CALLS = {"socket.gethostname", "platform.node"}
_OWN_NAMES = {"", "localhost", "127.0.0.1", "::1"}
# Their first argument is a search pattern: text the code looks for, not text it uses.
_PATTERN_CALLS = {f"re.{name}" for name in ("compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn", "split")}
_SENSITIVE_MODULES = {"builtins", "__builtins__", "__builtin__", "os", "subprocess", "socket"}
_SECRET_RULES = {"secret-env", "secret-path", "secret-env-dump"}
_PICKLE = {"pickle.loads", "cPickle.loads", "_pickle.loads", "dill.loads", "cloudpickle.loads"}
# These evaluate a string as Python, as get_type_hints does with string annotations.
_FORWARD_REFS = {"typing.ForwardRef", "typing_extensions.ForwardRef"}
_PICKLE_DANGER = re.compile(
    r"(?:os|posix|nt|subprocess|builtins|__builtin__|commands|pty|socket|runpy|importlib|urllib\S*|requests)(?:$|[ .])"
)
_BUILD_TOOLS = {
    "git", "make", "cmake", "ninja", "gcc", "g++", "cc", "c++", "clang", "clang++", "ld", "pkg-config",
    "python", "python3", "cython", "rustc", "cargo", "swig", "<python>", "xcrun", "sw_vers", "uname", "ldconfig",
    "nvcc", "gfortran", "ar", "sphinx-build",
}

_SENSITIVE_ENV = re.compile(
    r"TOKEN|SECRET|PASSW|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|^AWS_|^GCP_|^AZURE_|^GITHUB_|^GITLAB_|"
    r"^PYPI|^TWINE_|^NPM_|^SLACK_|^SSH_", re.I,
)
_CREDENTIAL_PATH = re.compile(
    r"\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.netrc|\.pypirc|\.npmrc|\.git-credentials|"
    r"\.docker[/\\]config\.json|\.kube[/\\]config|/etc/shadow|\.gnupg[/\\]|wallet\.dat|\.bash_history|"
    r"Login Data|Local State|/proc/(?:self|\d+)/environ"
)
_PERSISTENCE = re.compile(
    r"\.bashrc|\.bash_profile|\.zshrc|crontab|/etc/cron|LaunchAgents|LaunchDaemons|/etc/systemd/system|"
    r"\.config/autostart|CurrentVersion\\+Run|/etc/rc\.local|authorized_keys"
)
_BAD_HOST = re.compile(
    r"pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|ngrok(-free)?\.(io|app)|webhook\.site|requestbin|"
    r"requestcatcher\.com|discord(app)?\.com/api/webhooks|api\.telegram\.org|pipedream\.net|interact\.sh|"
    r"oastify\.com|burpcollaborator\.net", re.I,
)
_IP_URL = re.compile(r"\b(?:https?|ftp)://(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}")
_SHELL_ATTACK = re.compile(
    r"\b(?:curl|wget|fetch)\b[^|;&\n]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|"
    r"\b(?:curl|wget|fetch)\b[^|;&\n]{0,300}\|\s*python|"
    r"\bcurl\b[^|;&\n]{0,300}\s(?:-d|--data\S*|-T|--upload-file|-F|--form)\s|"
    r"/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^|;&\n]{0,100}\s-e\s|\bbash\s+-i\b|"
    r"base64\s+(?:-d|-D|--decode)[^|;\n]{0,200}\|\s*(?:ba)?sh|"
    r"powershell[^\n]{0,200}(?:-e(?:nc|ncodedcommand)?\s|iex\b|downloadstring)|"
    r"certutil[^\n]{0,100}-urlcache|mshta\s+http", re.I,
)
_ENCODED = re.compile(r"[A-Za-z0-9+/_\-=\s]{64,}")
# Words nobody needs to assemble from pieces. \b keeps "retrie" + "val" from reading as eval.
_DANGEROUS_WORD = re.compile(
    r"\b(?:exec|eval|__import__|__builtins__|builtins|system|popen|subprocess|socket|urlopen|environ|getenv|"
    r"marshal|pickle|base64|b64decode|urllib)\b|^os$"
)
_BIDI = re.compile(rb"\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]")
_LONG_GAP = re.compile(rb"[ \t]{40,}\S")
_DANGEROUS_CAPS = frozenset({"exec", "shell", "network", "secret", "persist"})

# Published examples, not a feed: connect a real advisory source (e.g. OSV) later.
KNOWN_MALICIOUS = frozenset({
    "acqusition", "apidev-coop", "bzip", "colourama", "crypt", "django-server", "jeilyfish", "pwd",
    "python3-dateutil", "setup-tools", "telnet", "urlib3",
})
POPULAR = frozenset({
    "requests", "urllib3", "numpy", "pandas", "scipy", "django", "flask", "boto3", "botocore", "setuptools",
    "wheel", "pip", "certifi", "idna", "charset-normalizer", "pyyaml", "cryptography", "pytest", "matplotlib",
    "pillow", "sqlalchemy", "jinja2", "click", "packaging", "six", "attrs", "rich", "tqdm", "aiohttp", "colorama",
    "python-dateutil", "beautifulsoup4", "lxml", "selenium", "tensorflow", "torch", "scikit-learn", "paramiko",
    "pydantic", "fastapi", "uvicorn", "httpx", "redis", "psycopg2", "pymongo", "jellyfish", "simplejson", "toml",
})


def normalize_dep(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _one_edit_apart(a: str, b: str) -> bool:
    """Levenshtein distance 1, or a single adjacent transposition."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


@dataclass(slots=True)
class Signal:
    rule: str
    line: int
    top: str | None = None       # Top-level function or class that contains it.
    module_level: bool = True    # Runs when the module is imported.
    detail: str = ""
    snippet: str = ""


@dataclass(slots=True)
class FileSignals:
    status: str = "ok"
    signals: list[Signal] = field(default_factory=list)
    local_imports: list[tuple[str, int]] = field(default_factory=list)
    exec_targets: list[str] = field(default_factory=list)
    thread_count: int = 0
    parallel_feasible: bool = False
    structure: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "FileSignals":
        values = dict(data)
        values["signals"] = [Signal(**s) for s in data["signals"]]
        values["local_imports"] = [tuple(i) for i in data["local_imports"]]
        return cls(**values)


@dataclass(slots=True)
class Finding:
    rule: str
    severity: str
    context: str                 # install, import, runtime or repository.
    path: str
    line: int
    message: str
    detail: str = ""
    snippet: str = ""


# ---- Bounded, side-effect-free decoding --------------------------------------


def _bounded(decompressor_output: bytes, unused_tail: bool) -> bytes | None:
    return None if unused_tail or len(decompressor_output) > _MAX_DECODED else decompressor_output


def _inflate(data: bytes, wbits: int = zlib.MAX_WBITS) -> bytes | None:
    engine = zlib.decompressobj(wbits)
    output = engine.decompress(data, _MAX_DECODED + 1)
    return _bounded(output, bool(engine.unconsumed_tail))


def _bunzip(data: bytes) -> bytes | None:
    engine = bz2.BZ2Decompressor()
    output = engine.decompress(data, _MAX_DECODED + 1)
    return _bounded(output, not engine.needs_input and not engine.eof)


def _unlzma(data: bytes) -> bytes | None:
    engine = lzma.LZMADecompressor()
    output = engine.decompress(data, _MAX_DECODED + 1)
    return _bounded(output, not engine.needs_input and not engine.eof)


def _as_bytes(value: str | bytes) -> bytes:
    return value.encode("utf-8", "surrogatepass") if isinstance(value, str) else value


_PURE_DECODERS = {
    "base64.b64decode": lambda v: base64.b64decode(_as_bytes(v)),
    "base64.standard_b64decode": lambda v: base64.standard_b64decode(_as_bytes(v)),
    "base64.urlsafe_b64decode": lambda v: base64.urlsafe_b64decode(_as_bytes(v)),
    "base64.b32decode": lambda v: base64.b32decode(_as_bytes(v)),
    "base64.b16decode": lambda v: base64.b16decode(_as_bytes(v), casefold=True),
    "base64.b85decode": lambda v: base64.b85decode(_as_bytes(v)),
    "base64.a85decode": lambda v: base64.a85decode(_as_bytes(v)),
    "binascii.unhexlify": lambda v: binascii.unhexlify(_as_bytes(v)),
    "binascii.a2b_hex": lambda v: binascii.a2b_hex(_as_bytes(v)),
    "binascii.a2b_base64": lambda v: binascii.a2b_base64(_as_bytes(v)),
    "bytes.fromhex": lambda v: bytes.fromhex(v) if isinstance(v, str) else None,
    "zlib.decompress": lambda v: _inflate(_as_bytes(v)),
    "gzip.decompress": lambda v: _inflate(_as_bytes(v), 31),
    "bz2.decompress": lambda v: _bunzip(_as_bytes(v)),
    "lzma.decompress": lambda v: _unlzma(_as_bytes(v)),
}
_OTHER_DECODERS = {"codecs.decode", "marshal.loads", "pickle.loads", "chr", "binascii.a2b_uu"}


def _codec(value: str | bytes, encoding: str) -> str | bytes | None:
    encoding = encoding.lower().replace("-", "_")
    if encoding in ("rot13", "rot_13"):
        return codecs.decode(value, "rot13") if isinstance(value, str) else None
    if encoding in ("hex", "hex_codec"):
        return binascii.unhexlify(_as_bytes(value))
    if encoding in ("base64", "base64_codec", "base_64"):
        return base64.b64decode(_as_bytes(value))
    if encoding in ("zlib", "zlib_codec", "zip"):
        return _inflate(_as_bytes(value))
    if encoding in ("bz2", "bz2_codec"):
        return _bunzip(_as_bytes(value))
    if isinstance(value, bytes):
        return value.decode(encoding, "replace")
    return None


def _entropy(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def _first_token(command: str) -> str:
    parts = command.strip().split()
    return parts[0].rsplit("/", 1)[-1].lower() if parts else ""


def _pickle_calls_danger(value: str | bytes | None) -> bool:
    """Read a pickle's opcodes without loading it, looking for the modules it would use."""
    if not isinstance(value, bytes):
        return False
    try:
        return any(isinstance(arg, str) and _PICKLE_DANGER.match(arg) for _, arg, _ in pickletools.genops(value))
    except (ValueError, EOFError, UnicodeDecodeError, KeyError, IndexError, struct.error):
        return False


def _alternatives(value: ast.expr) -> list[ast.expr]:
    """The expressions `a or b` and `a if c else b` can produce."""
    if isinstance(value, ast.BoolOp):
        return [option for inner in value.values for option in _alternatives(inner)]
    if isinstance(value, ast.IfExp):
        return [*_alternatives(value.body), *_alternatives(value.orelse)]
    return [value]


def _parameters(node: ast.AST) -> list[ast.arg]:
    arguments = node.args
    return [a for a in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs, arguments.vararg, arguments.kwarg) if a]


def _scope_key(scope: str | None) -> str | None:
    """Code under a __main__ guard still assigns module variables."""
    return None if scope == "<main-guard>" else scope


def _is_main_guard(test: ast.expr) -> bool:
    """`__name__ == "__main__"`, alone or as one required part of an `and`."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return any(_is_main_guard(value) for value in test.values)
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)):
        return False
    sides = (test.left, test.comparators[0])
    return (
        any(isinstance(side, ast.Name) and side.id == "__name__" for side in sides)
        and any(isinstance(side, ast.Constant) and side.value == "__main__" for side in sides)
    )


# ---- Visitor -----------------------------------------------------------------


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, source: bytes = b"", depth: int = 0) -> None:
        self._source = source
        self._lines: list[bytes] | None = None
        self._depth = depth
        self.result = FileSignals()
        self._ctx: tuple[str | None, bool, bool] = (None, False, False)  # scope, in function, __main__ guard.
        self._suppress_refs = False
        self._calls: list[tuple[ast.Call, tuple]] = []
        self._aliases: dict[str, list[ast.expr]] = {}
        self._imports: dict[str, str] = {}
        self._assigned: dict[str, list[ast.expr]] = {}
        self._scoped: dict[str | None, dict[str, list[ast.expr]]] = {}  # The same, per scope. None is the module.
        self._global_names: dict[str | None, set[str]] = {}
        self._functions: dict[str, ast.AST] = {}
        self._discarded: set[int] = set()  # Calls whose result nothing uses.
        self._returns: dict[str, list[ast.expr]] = {}
        self._strings: list[tuple[str, int, tuple, int]] = []
        self._subscripts: list[tuple[ast.Subscript, tuple]] = []
        self._attr_assigns: list[tuple[ast.Attribute, tuple]] = []
        self._built: list[tuple[ast.expr, tuple]] = []        # Expressions that may assemble a string.
        self._annotations: list[tuple[ast.expr, tuple]] = []  # Evaluated by get_type_hints.
        self._env_iters: list[tuple[ast.expr, tuple]] = []
        self._silent_tries: list[tuple[int, int, tuple]] = []
        self._docstrings: set[int] = set()
        self._defs: set[str] = set()
        self._refs: dict[str | None, set[str]] = {}
        self._const_memo: dict[int, object] = {}
        self._const_nodes = 0
        self._const_active: set[int] = set()
        self._resolve_calls = 0
        self._seen: Counter[tuple[str, int]] = Counter()
        self._rule_counts: Counter[str] = Counter()
        self._payloads_seen: set[bytes] = set()

    # ---- Running ----------------------------------------------------------

    def run(self, tree: ast.Module) -> FileSignals:
        self._tree = tree
        self._mark_docstring(tree)
        self.visit(tree)
        self._process_calls()
        self._process_strings()
        self._process_built_strings()
        self._process_tries()
        self._process_secret_flows()
        self._apply_reachability()
        return self.result

    def _emit(self, rule: str, line: int, ctx: tuple, detail: str = "") -> None:
        key = (rule, line)
        if self._seen[key] or self._rule_counts[rule] >= _MAX_PER_RULE:
            return
        self._seen[key] += 1
        self._rule_counts[rule] += 1
        top, in_function, guarded = ctx
        signal = Signal(rule, line, top, not in_function and not guarded, detail[:300], self._snippet(line))
        self.result.signals.append(signal)

    def _snippet(self, line: int) -> str:
        if not self._source:
            return ""
        if self._lines is None:
            self._lines = self._source.split(b"\n")
        if 0 < line <= len(self._lines):
            return self._lines[line - 1].decode("utf-8", "replace").strip()[:200]
        return ""

    def _apply_reachability(self) -> None:
        """A function called while a module imports is effectively import-time code."""
        reached: set[str] = set()
        pending = list(self._refs.get(None, ()))
        while pending:
            name = pending.pop()
            if name in self._defs and name not in reached:
                reached.add(name)
                pending.extend(self._refs.get(name, ()))
                # Using a class runs its constructor, not every method it has.
                pending += (f"{name}.__init__", f"{name}.__new__")
        for signal in self.result.signals:
            if signal.top in reached:
                signal.module_level = True

    # ---- Structure --------------------------------------------------------

    def _mark_docstring(self, node: ast.AST) -> None:
        body = getattr(node, "body", None)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            self._docstrings.add(id(body[0].value))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.partition(".")[0]
            self._imports[bound] = alias.name if alias.asname else bound
            self.result.local_imports.append((alias.name, 0))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name != "*":
                dotted = f"{module}.{alias.name}" if module else alias.name
                if not node.level:
                    self._imports[alias.asname or alias.name] = dotted
            self.result.local_imports.append((
                f"{module}.{alias.name}" if module and alias.name != "*" else module or alias.name, node.level,
            ))

    def _visit_scope(self, node: ast.AST, is_function: bool) -> None:
        self._mark_docstring(node)
        scope, in_function, guarded = self._ctx
        if scope is None:
            inner = node.name
        elif not in_function and "." not in scope and scope != "<main-guard>":
            inner = f"{scope}.{node.name}"  # A method keeps its own identity.
        else:
            inner = scope
        self._defs.add(inner)
        if is_function:
            self._functions.setdefault(inner, node)
            # A parameter is local, so a module variable of the same name says nothing about it.
            locals_ = self._scoped.setdefault(inner, {})
            for parameter in _parameters(node):
                locals_.setdefault(parameter.arg, [])
        outer = self._ctx
        for expr in getattr(node, "decorator_list", ()):
            self.visit(expr)
        if is_function:
            for default in (*node.args.defaults, *(d for d in node.args.kw_defaults if d)):
                self.visit(default)
            # These run when the function is defined, unless `from __future__ import annotations` is on.
            arguments = node.args
            every = (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs, arguments.vararg, arguments.kwarg)
            for annotation in (*(a.annotation for a in every if a), node.returns):
                if annotation is not None:
                    self._annotations.append((annotation, self._ctx))
                    self.visit(annotation)
        else:
            # Subclassing doesn't run the base class, so a base isn't a call.
            self._suppress_refs = True
            for expr in node.bases:
                self.visit(expr)
            self._suppress_refs = False
            for keyword in node.keywords:
                self.visit(keyword.value)
        self._ctx = (inner, in_function or is_function, guarded)
        for statement in node.body:
            self.visit(statement)
        self._ctx = outer

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scope(node, True)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scope(node, True)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scope(node, False)

    def visit_If(self, node: ast.If) -> None:
        if not _is_main_guard(node.test):
            self.generic_visit(node)
            return
        saved = self._ctx
        self._ctx = (saved[0] or "<main-guard>", saved[1], True)
        for statement in node.body:
            self.visit(statement)
        self._ctx = saved
        for statement in node.orelse:
            self.visit(statement)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and not self._suppress_refs:
            self._refs.setdefault(self._ctx[0], set()).add(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Link `self.run()`, `Task.run()` and `Task().run()` to the method.
        base = node.value
        if isinstance(base, ast.Call):
            base = base.func
        if isinstance(base, ast.Name) and not self._suppress_refs:
            scope = self._ctx[0]
            owner = scope.partition(".")[0] if base.id in ("self", "cls") and scope else base.id
            self._refs.setdefault(scope, set()).add(f"{owner}.{node.attr}")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._note_assignment(target.id, node.value)
                if target.id == "__annotations__" and isinstance(node.value, ast.Dict):
                    self._annotations.extend((value, self._ctx) for value in node.value.values)
            elif isinstance(target, ast.Attribute):
                self._attr_assigns.append((target, self._ctx))
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # Recorded so `x = ""; x += y` can't fold to its first value.
        if isinstance(node.target, ast.Name):
            self._note_assignment(node.target.id, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            self._note_assignment(node.target.id, node.value)
        self._annotations.append((node.annotation, self._ctx))
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._note_assignment(node.target.id, node.value)
        self.generic_visit(node)

    def _note_assignment(self, name: str, value: ast.expr) -> None:
        values = self._assigned.setdefault(name, [])
        if len(values) < 8:
            values.append(value)
        scope = _scope_key(self._ctx[0])
        if name in self._global_names.get(scope, ()):
            scope = None
        scoped = self._scoped.setdefault(scope, {}).setdefault(name, [])
        if len(scoped) < 8:
            scoped.append(value)

    def _values(self, name: str, scope: str | None) -> list[ast.expr]:
        """What `name` can hold when read in `scope`, following Python's own scoping."""
        scope = _scope_key(scope)
        if scope is not None and name in self._scoped.get(scope, ()) and name not in self._global_names.get(scope, ()):
            return self._scoped[scope][name]
        module = self._scoped.get(None, {})
        return module[name] if name in module else self._assigned.get(name, [])

    def visit_Global(self, node: ast.Global) -> None:
        self._global_names.setdefault(_scope_key(self._ctx[0]), set()).update(node.names)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name):
                self._note_assignment(item.optional_vars.id, item.context_expr)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None and self._ctx[0]:
            self._returns.setdefault(self._ctx[0], []).append(node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._env_iters.append((node.iter, self._ctx))
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        for handler in node.handlers:
            if all(isinstance(s, (ast.Pass, ast.Continue)) for s in handler.body):
                self._silent_tries.append((node.body[0].lineno, node.body[-1].end_lineno or node.lineno, self._ctx))
                break
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            self._discarded.add(id(node.value))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._calls.append((node, self._ctx))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            self._built.append((node, self._ctx))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self._subscripts.append((node, self._ctx))
        if isinstance(node.slice, ast.Slice):
            self._built.append((node, self._ctx))
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.Add):
            self._built.append((node, self._ctx))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, (str, bytes)) and len(node.value) >= 6 and id(node) not in self._docstrings:
            value = node.value
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            self._strings.append((value, node.lineno, self._ctx, id(node)))

    # ---- Name resolution --------------------------------------------------

    def _resolve(self, node: ast.expr, seen: frozenset[str] = frozenset()) -> tuple[str | None, bool]:
        """Return (canonical dotted name, reached through reflection)."""
        self._resolve_calls += 1
        if self._resolve_calls > 500000:  # A budget, so crafted code can't stall the scan.
            return None, False
        name, obfuscated = self._resolve_raw(node, seen)
        if name:
            for prefix in ("builtins.", "__builtin__.", "__builtins__."):
                if name.startswith(prefix):
                    name = name[len(prefix):]
                    break
        return name, obfuscated

    def _resolve_raw(self, node: ast.expr, seen: frozenset[str]) -> tuple[str | None, bool]:
        if isinstance(node, ast.Name):
            name = node.id
            if name in seen:
                return name, False
            if name in self._imports:
                return self._imports[name], False
            for assigned in self._assigned.get(name, ()):
                for value in _alternatives(assigned):
                    if isinstance(value, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
                        resolved, obfuscated = self._resolve(value, seen | {name})
                        if resolved and self._is_interesting(resolved):
                            return resolved, obfuscated
            return name, False
        if isinstance(node, ast.Attribute):
            base, obfuscated = self._resolve(node.value, seen)
            return (f"{base}.{node.attr}" if base else None), obfuscated
        if isinstance(node, ast.Call):
            getter = self._attrgetter_name(node.func, seen)
            if getter and node.args:
                base, _ = self._resolve(node.args[0], seen)
                return (f"{base}.{getter}" if base else None), True
            callee, obfuscated = self._resolve(node.func, seen)
            if callee == "sys.modules.get" and node.args:
                module = self._const(node.args[0])
                return (module, True) if isinstance(module, str) else (None, False)
            if callee and callee.endswith(".__getattribute__") and node.args:
                owner, values = callee[: -len(".__getattribute__")], node.args
                if owner == "object" and len(values) == 2:
                    owner = self._resolve(values[0], seen)[0]
                attr = self._const(values[-1])
                return (f"{owner}.{attr}", True) if owner and isinstance(attr, str) else (None, False)
            if callee in ("__import__", "importlib.import_module") and node.args:
                module = self._const(node.args[0])
                if isinstance(module, str):
                    root = module if callee != "__import__" else module.partition(".")[0]
                    return root, obfuscated or not isinstance(node.args[0], ast.Constant)
            if callee == "getattr" and len(node.args) >= 2:
                base, reflected = self._resolve(node.args[0], seen)
                attr = self._const(node.args[1])
                if base and isinstance(attr, str):
                    return f"{base}.{attr}", reflected or not isinstance(node.args[1], ast.Constant)
            return None, False
        if isinstance(node, ast.Subscript):
            base = node.value
            key = self._const(node.slice)
            if not isinstance(key, str):
                return None, False
            if isinstance(base, ast.Call) and isinstance(base.func, ast.Name) and base.func.id in ("globals", "locals"):
                return key, True
            if isinstance(base, ast.Call) and isinstance(base.func, ast.Name) and base.func.id == "vars" and base.args:
                inner, _ = self._resolve(base.args[0], seen)
                return (f"{inner}.{key}" if inner else None), True
            owner, _ = self._resolve(base, seen)
            if owner == "sys.modules":
                return key, True
            if owner == "__dict__":  # __builtins__.__dict__, after the builtins prefix is removed.
                return key, True
            if owner and owner.endswith(".__dict__"):
                return f"{owner[:-len('.__dict__')]}.{key}", True
            if owner in ("__builtins__", "builtins", "__builtin__"):
                return key, True
        return None, False

    def _attrgetter_name(self, func: ast.expr, seen: frozenset[str]) -> str | None:
        """The attribute in `operator.attrgetter("x")`, written inline or held in a variable."""
        if isinstance(func, ast.Name):
            values = self._assigned.get(func.id, ())
            func = values[0] if len(values) == 1 else func
        if isinstance(func, ast.Call) and func.args and self._resolve(func.func, seen)[0] == "operator.attrgetter":
            attr = self._const(func.args[0])
            return attr if isinstance(attr, str) else None
        return None

    @staticmethod
    def _is_interesting(name: str) -> bool:
        root = name.partition(".")[0]
        return name in _EXEC or name in _PURE_DECODERS or root in {
            "os", "subprocess", "socket", "urllib", "requests", "http", "pty", "ctypes", "marshal", "builtins",
            "__builtins__", "__builtin__", "importlib", "base64", "binascii", "zlib", "bz2", "lzma", "gzip",
            "codecs", "httpx", "ftplib", "smtplib", "telnetlib", "sys", "__import__", "getattr", "runpy", "open",
            "pickle", "cPickle", "_pickle", "dill", "cloudpickle", "typing", "typing_extensions", "types",
        }

    # ---- Constant folding (never runs user code) --------------------------

    def _const(self, node: ast.expr, seen: frozenset[str] = frozenset()) -> str | bytes | None:
        key = id(node)
        if key in self._const_memo:
            return self._const_memo[key]  # type: ignore[return-value]
        if key in self._const_active:  # `x = getattr(a, x)` would otherwise never end.
            return None
        self._const_nodes += 1
        self._const_active.add(key)
        try:
            value = self._const_uncached(node, seen) if self._const_nodes < 200000 else None
        finally:
            self._const_active.discard(key)
        if value is not None and len(value) > _MAX_DECODED:
            value = None
        if not seen:
            self._const_memo[key] = value
        return value

    def _const_uncached(self, node: ast.expr, seen: frozenset[str]) -> str | bytes | None:
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, (str, bytes)) else None
        if isinstance(node, ast.Name):
            values = self._assigned.get(node.id)
            if values and len(values) == 1 and node.id not in seen:
                return self._const(values[0], seen | {node.id})
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._const(node.left, seen)
            right = self._const(node.right, seen)
            if type(left) is type(right) and left is not None:
                return left + right
            return None
        if isinstance(node, ast.JoinedStr):
            parts = []
            for piece in node.values:
                value = self._const(piece.value if isinstance(piece, ast.FormattedValue) else piece, seen)
                if not isinstance(value, str):
                    return None
                parts.append(value)
            return "".join(parts)
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            base = self._const(node.value, seen)
            slice_ = node.slice
            if base is None or slice_.lower or slice_.upper:
                return None
            step = slice_.step
            if isinstance(step, ast.UnaryOp) and isinstance(step.op, ast.USub) and getattr(step.operand, "value", 0) == 1:
                return base[::-1]
            return None
        if isinstance(node, ast.Call):
            return self._const_call(node, seen)
        return None

    def _const_call(self, node: ast.Call, seen: frozenset[str]) -> str | bytes | None:
        func = node.func
        args = node.args
        try:
            if isinstance(func, ast.Attribute):
                method = func.attr
                if method == "join" and len(args) == 1:
                    separator = self._const(func.value, seen)
                    sequence = args[0]
                    if isinstance(sequence, ast.Name):
                        values = self._assigned.get(sequence.id, ())
                        sequence = values[0] if len(values) == 1 else sequence
                    if isinstance(separator, str):
                        characters = self._chr_sequence(sequence)
                        if characters is not None:
                            return separator.join(characters)
                    if separator is not None and isinstance(sequence, (ast.List, ast.Tuple)):
                        pieces = [self._const(e, seen) for e in sequence.elts]
                        if all(type(p) is type(separator) for p in pieces):
                            return separator.join(pieces)
                    if separator is None:
                        owner, _ = self._resolve(func.value)
                        if owner == "os.path" and all(isinstance(self._const(a, seen), str) for a in args):
                            return "/".join(self._const(a, seen) for a in args)
                    return None
                if method in ("decode", "encode") and func.value is not None:
                    base = self._const(func.value, seen)
                    if base is None:
                        return None
                    encoding = self._const(args[0], seen) if args else "utf-8"
                    if not isinstance(encoding, str):
                        return None
                    if method == "decode" and isinstance(base, bytes):
                        return _codec(base, encoding)
                    if method == "encode" and isinstance(base, str):
                        return base.encode(encoding, "replace") if encoding.lower() != "rot13" else None
                    return None
                if method in ("replace",) and len(args) == 2:
                    base, old, new = self._const(func.value, seen), self._const(args[0], seen), self._const(args[1], seen)
                    if type(base) is type(old) is type(new) and base is not None:
                        return base.replace(old, new)
                    return None
                if method == "strip" and not args:
                    base = self._const(func.value, seen)
                    return base.strip() if base is not None else None
            name, _ = self._resolve(func)
            if name in _PURE_DECODERS and args:
                value = self._const(args[0], seen)
                return _PURE_DECODERS[name](value) if value is not None else None
            if name in ("codecs.decode", "codecs.encode") and args:
                value = self._const(args[0], seen)
                encoding = self._const(args[1], seen) if len(args) > 1 else "utf-8"
                if value is not None and isinstance(encoding, str):
                    return _codec(value, encoding)
                return None
            if name == "chr" and len(args) == 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, int):
                return chr(args[0].value)
            if name in ("bytes", "bytearray") and len(args) == 1:
                if isinstance(args[0], (ast.List, ast.Tuple)):
                    return bytes(e.value for e in args[0].elts if isinstance(e, ast.Constant))
                return self._const(args[0], seen)
            if name == "str" and len(args) == 1:
                value = self._const(args[0], seen)
                return value if isinstance(value, str) else None
        except (ValueError, TypeError, OverflowError, OSError, EOFError, lzma.LZMAError, zlib.error, binascii.Error):
            return None
        return None

    def _chr_sequence(self, expr: ast.expr) -> list[str] | None:
        """The characters of `map(chr, numbers)` or `chr(n) for n in numbers`."""
        numbers = None
        if isinstance(expr, ast.Call) and len(expr.args) == 2 and self._resolve(expr.func)[0] == "map":
            if self._resolve(expr.args[0])[0] == "chr":
                numbers = expr.args[1]
        elif isinstance(expr, (ast.GeneratorExp, ast.ListComp)) and len(expr.generators) == 1:
            element, loop = expr.elt, expr.generators[0]
            if (
                isinstance(element, ast.Call) and self._resolve(element.func)[0] == "chr" and len(element.args) == 1
                and isinstance(element.args[0], ast.Name) and isinstance(loop.target, ast.Name)
                and element.args[0].id == loop.target.id and not loop.ifs
            ):
                numbers = loop.iter
        if isinstance(numbers, ast.Name):
            values = self._assigned.get(numbers.id, ())
            numbers = values[0] if len(values) == 1 else None
        if not isinstance(numbers, (ast.List, ast.Tuple)):
            return None
        codes = [e.value for e in numbers.elts if isinstance(e, ast.Constant) and isinstance(e.value, int)]
        if len(codes) != len(numbers.elts) or not all(0 <= code < 0x110000 for code in codes):
            return None
        return [chr(code) for code in codes]

    # ---- Taint: where a value passed to exec came from ---------------------

    def _origin(self, expr: ast.expr, scope: str | None, seen: set | None = None) -> set[str]:
        seen = set() if seen is None else seen
        labels: set[str] = set()
        for node in ast.walk(expr):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
                labels.add("decoded")  # Byte-wise XOR is how a payload hides from constant folding.
            elif isinstance(node, ast.Name) and (scope, node.id) not in seen:
                seen.add((scope, node.id))
                for value in self._values(node.id, scope):
                    labels |= self._origin(value, scope, seen)
            elif isinstance(node, ast.Call):
                name, _ = self._resolve(node.func)
                if name is None:
                    continue
                if name in _PURE_DECODERS or name in _OTHER_DECODERS:
                    labels.add("decoded")
                elif self._is_network(name):
                    labels.add("network")
                elif name in ("open", "io.open", "codecs.open") or name.endswith(".read_text"):
                    labels.add("file")
                elif name in self._returns and ("return", name) not in seen:
                    seen.add(("return", name))
                    for value in self._returns[name]:
                        labels |= self._origin(value, name, seen)
        return labels

    def _opened_path(self, expr: ast.expr, seen: set[str] | None = None) -> str | None:
        """Best-effort path of a file whose contents reach ``expr``."""
        seen = set() if seen is None else seen
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id not in seen:
                seen.add(node.id)
                for value in self._assigned.get(node.id, ()):
                    path = self._opened_path(value, seen)
                    if path:
                        return path
            elif isinstance(node, ast.Call):
                name, _ = self._resolve(node.func)
                if name in ("open", "io.open", "codecs.open") and node.args:
                    return self._path_hint(node.args[0])
        return None

    def _path_hint(self, expr: ast.expr, seen: frozenset[str] = frozenset()) -> str | None:
        value = self._const(expr)
        if isinstance(value, str):
            return value
        if isinstance(expr, ast.Call):
            name, _ = self._resolve(expr.func)
            if name in ("os.path.join", "pathlib.Path", "Path"):
                parts = [self._const(a) for a in expr.args]
                strings = [p for p in parts if isinstance(p, str)]
                return "/".join(strings) if strings else None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Div, ast.Add)):
            return self._path_hint(expr.right, seen)
        if isinstance(expr, ast.Name) and expr.id not in seen:
            for value in self._assigned.get(expr.id, ())[:1]:
                return self._path_hint(value, seen | {expr.id})
        return None

    # ---- Classifying calls ------------------------------------------------

    @staticmethod
    def _is_network(name: str) -> bool:
        if name in _NETWORK:
            return True
        root, _, attr = name.rpartition(".")
        return root in ("requests", "httpx") and attr in _HTTP_VERBS

    def _is_own_name_lookup(self, node: ast.Call, name: str) -> bool:
        """`gethostbyname(gethostname())` finds this machine's address. Reading the name is still `recon`."""
        if name not in _NAME_LOOKUPS or not node.args:
            return False
        host = node.args[0]
        if isinstance(host, ast.Call):
            return self._resolve(host.func)[0] in _OWN_NAME_CALLS
        return self._const(host) in _OWN_NAMES

    def _process_calls(self) -> None:
        for node, ctx in self._calls:
            name, obfuscated = self._resolve(node.func)
            if not name:
                self._check_env_dump(node, ctx)
                continue
            if obfuscated and (
                name in _EXEC or name in _SHELL or self._is_network(name) or _SHELL_PREFIX.match(name)
            ):
                self._emit("obfuscated-access", node.lineno, ctx, f"Resolves to {name}")
            if obfuscated and (name in _EXEC or name in _SHELL or _SHELL_PREFIX.match(name)):
                self._emit("hidden-sink", node.lineno, ctx, f"Resolves to {name}")
            if name in ("getattr", "setattr") and len(node.args) >= 2:
                self._check_attribute_call(node, name, ctx)
            elif name in _CODE_BUILDERS:
                self._emit("code-object", node.lineno, ctx, name)
            elif name in _LOG_SENDERS:
                self._emit("log-shipping", node.lineno, ctx, name)
            elif name in _IMPORT_HOOKS:
                self._emit("import-hook", node.lineno, ctx, name)
            if name in _EXEC:
                self._check_exec(node, name, ctx)
            elif name in _SHELL or _SHELL_PREFIX.match(name):
                self._check_shell(node, name, ctx)
            elif name in _PICKLE and node.args:
                self._check_pickle(node, name, ctx)
            elif name in _FORWARD_REFS and node.args:
                self._annotations.append((node.args[0], ctx))
            elif self._is_own_name_lookup(node, name):
                pass
            elif self._is_network(name):
                self._emit("network-call", node.lineno, ctx, name)
                if node.args:
                    url = self._const(node.args[0])
                    if isinstance(url, str):
                        self._check_string(url, node.lineno, ctx)
            elif name in _PURE_DECODERS or name in ("codecs.decode",):
                self._check_decoder(node, name, ctx)
            elif name == "marshal.loads":
                self._emit("deserialize-code", node.lineno, ctx, name)
            elif name in _RECON:
                self._emit("recon", node.lineno, ctx, name)
            elif name in _NATIVE:
                self._emit("native-code", node.lineno, ctx, name)
            elif name in ("__import__", "importlib.import_module") and node.args:
                self._check_import(node, ctx)
            elif name in _REMOVERS and node.args and self._refers_to_file(node.args[0]):
                self._emit("self-delete", node.lineno, ctx, name)
            elif name in ("os.getenv", "os.environ.get") and node.args:
                self._check_env_key(node.args[0], node.lineno, ctx)
            elif name in ("os.environ.copy", "os.environ.items", "os.environ.values", "os.environ.keys"):
                self._emit("secret-env-dump", node.lineno, ctx, name)
            elif name in ("setup", "setuptools.setup", "distutils.core.setup"):
                self._check_setup_call(node, ctx)
            self._check_env_dump(node, ctx)

        for target, ctx in self._attr_assigns:
            if self._resolve(target)[0] == _TLS_SWITCH:
                self._emit("tls-disabled", target.lineno, ctx)
        for node, ctx in self._subscripts:
            base, _ = self._resolve(node.value)
            if base == "os.environ":
                self._check_env_key(node.slice, node.lineno, ctx)
            elif self._const(node.slice) is None and not isinstance(node.slice, ast.Slice):
                self._check_namespace_lookup(node, base, ctx)
        for expr, ctx in self._env_iters:
            name, _ = self._resolve(expr) if isinstance(expr, (ast.Name, ast.Attribute)) else (None, False)
            if name == "os.environ":
                self._emit("secret-env-dump", expr.lineno, ctx, "Iterates os.environ")

    def _check_attribute_call(self, node: ast.Call, name: str, ctx: tuple) -> None:
        base = self._resolve(node.args[0])[0]
        attr = self._const(node.args[1])
        if name == "setattr":
            if isinstance(attr, str) and f"{base}.{attr}" == _TLS_SWITCH:
                self._emit("tls-disabled", node.lineno, ctx)
        elif attr is None and base in _SENSITIVE_MODULES:
            self._emit("dynamic-reflection", node.lineno, ctx, f"getattr on {base}")

    def _check_namespace_lookup(self, node: ast.Subscript, base: str | None, ctx: tuple) -> None:
        """`vars(os)[name]` and `os.__dict__[name]` with a name that can't be worked out."""
        owner = base[: -len(".__dict__")] if base and base.endswith(".__dict__") else None
        if isinstance(node.value, ast.Call) and self._resolve(node.value.func)[0] == "vars" and node.value.args:
            owner = self._resolve(node.value.args[0])[0]
        if owner in _SENSITIVE_MODULES:
            self._emit("dynamic-reflection", node.lineno, ctx, f"Namespace of {owner}")

    def _check_env_key(self, key_node: ast.expr, line: int, ctx: tuple) -> None:
        key = self._const(key_node)
        if isinstance(key, str):
            if _SENSITIVE_ENV.search(key):
                self._emit("secret-env", line, ctx, key)
        else:
            self._emit("secret-env-dump", line, ctx, "Variable environment key")

    def _check_env_dump(self, node: ast.Call, ctx: tuple) -> None:
        for arg in (*node.args, *(k.value for k in node.keywords)):
            if isinstance(arg, (ast.Name, ast.Attribute)) and self._resolve(arg)[0] == "os.environ":
                self._emit("secret-env-dump", node.lineno, ctx, "Passes the whole of os.environ")

    def _check_import(self, node: ast.Call, ctx: tuple) -> None:
        value = self._const(node.args[0])
        if isinstance(value, str):
            if not isinstance(node.args[0], ast.Constant):
                self._emit("obfuscated-access", node.lineno, ctx, f"Imports {value} via a built-up name")
            self.result.local_imports.append((value, 0))
        else:
            self._emit("dynamic-import", node.lineno, ctx, ast.unparse(node.args[0])[:120])

    def _refers_to_file(self, expr: ast.expr) -> bool:
        return any(isinstance(n, ast.Name) and n.id in ("__file__", "__path__") for n in ast.walk(expr))

    def _check_exec(self, node: ast.Call, name: str, ctx: tuple) -> None:
        if not node.args:
            return
        if name == "compile" and id(node) in self._discarded:
            return  # Compiling without keeping the result can't run anything.
        arg = node.args[0]
        constant = self._const(arg)
        origin = self._origin(arg, ctx[0])
        if "network" in origin:
            self._emit("exec-network", node.lineno, ctx, name)
        elif "decoded" in origin:
            self._emit("exec-decoded", node.lineno, ctx, name)
            if constant is not None:
                self._scan_payload(constant, node.lineno, ctx, encoded=True)
        elif constant is not None:
            self._emit("exec-constant", node.lineno, ctx, name)
            self._scan_payload(constant, node.lineno, ctx, encoded=False)
        elif "file" in origin:
            path = self._opened_path(arg)
            if path and path.endswith((".py", ".pyw")):
                self._emit("exec-local-file", node.lineno, ctx, path)
                self.result.exec_targets.append(path)
            elif path:
                self._emit("exec-data-file", node.lineno, ctx, path)
            else:
                self._emit("exec-dynamic", node.lineno, ctx, name)
        else:
            self._emit("exec-dynamic", node.lineno, ctx, name)

    def _check_pickle(self, node: ast.Call, name: str, ctx: tuple) -> None:
        """Unpickling is common, so what matters is a pickle in the source that would run a command."""
        arg = node.args[0]
        # pickle.loads(pickle.dumps(x)) is a round trip of a local object, wherever x came from.
        def round_trip(item: ast.AST) -> bool:
            return isinstance(item, ast.Call) and (self._resolve(item.func)[0] or "").endswith(".dumps")

        origin = self._origin(arg, ctx[0])
        if "network" in origin and not self._carries(arg, round_trip, ctx[0]):
            self._emit("exec-network", node.lineno, ctx, name)
        elif _pickle_calls_danger(self._const(arg)):
            self._emit("exec-decoded", node.lineno, ctx, f"{name}: the pickle in the source calls a dangerous module")
        else:
            self._emit("deserialize-pickle", node.lineno, ctx, name)

    def _command_text(self, arg: ast.expr) -> tuple[str, bool]:
        """Return the known text of a command, and whether all of it is known."""
        items = None
        if isinstance(arg, (ast.List, ast.Tuple)):
            items = arg.elts
        elif isinstance(arg, ast.Name):
            values = self._assigned.get(arg.id)
            if values and len(values) == 1 and isinstance(values[0], (ast.List, ast.Tuple)):
                items = values[0].elts
        if items is not None:
            parts, complete = [], True
            for position, element in enumerate(items):
                value = self._const(element)
                if isinstance(value, str):
                    parts.append(value)
                elif position == 0 and self._resolve(element)[0] == "sys.executable":
                    parts.append("<python>")
                else:
                    complete = False
            return " ".join(parts), complete
        value = self._const(arg)
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        return (value, True) if isinstance(value, str) else ("", False)

    def _check_shell(self, node: ast.Call, name: str, ctx: tuple) -> None:
        if not node.args:
            return
        arg = node.args[1] if name.startswith(("os.spawn", "os.posix_spawn")) and len(node.args) > 1 else node.args[0]
        text, complete = self._command_text(arg)
        origin = self._origin(arg, ctx[0])
        line = node.lineno
        if _SHELL_ATTACK.search(text[:8192]):
            self._emit("shell-dangerous", line, ctx, text[:200])
        elif "decoded" in origin or "network" in origin:
            self._emit("shell-dangerous", line, ctx, f"{name} runs a decoded or downloaded command")
        else:
            token = _first_token(text)
            if complete and re.search(r"\bpip3?\s+install\b", text):
                self._emit("shell-static", line, ctx, text[:200])
            elif token in _BUILD_TOOLS:
                self._emit("shell-build-tool", line, ctx, text[:200])
            elif complete and text:
                self._emit("shell-static", line, ctx, text[:200])
            else:
                self._emit("shell-dynamic", line, ctx, name)
        if text:
            self._check_string(text, line, ctx)
            match = re.search(r"(?:^|\s)(?:<python>|python[0-9.]*)\s+-c\s+(.+)$", text, re.S)
            if match:
                self._scan_payload(match.group(1), line, ctx, encoded=False)
            for inline in node.args[0].elts if isinstance(node.args[0], (ast.List, ast.Tuple)) else ():
                value = self._const(inline)
                if isinstance(value, str) and len(value) > 20 and "\n" in value:
                    self._scan_payload(value, line, ctx, encoded=False)

    def _check_decoder(self, node: ast.Call, name: str, ctx: tuple) -> None:
        self._emit("decoder", node.lineno, ctx, name)
        value = self._const(node)
        if value is not None:
            self._scan_payload(value, node.lineno, ctx, encoded=True)

    def _check_setup_call(self, node: ast.Call, ctx: tuple) -> None:
        for keyword in node.keywords:
            if keyword.arg == "cmdclass":
                self._emit("install-hook", node.lineno, ctx, ast.unparse(keyword.value)[:120])
            elif keyword.arg == "dependency_links":
                self._emit("dependency-link", node.lineno, ctx, ast.unparse(keyword.value)[:200])
            elif keyword.arg in ("install_requires", "setup_requires", "tests_require"):
                value = keyword.value
                if isinstance(value, ast.Name):
                    values = self._assigned.get(value.id, ())
                    value = values[0] if values else value
                if isinstance(value, (ast.List, ast.Tuple)):
                    for element in value.elts:
                        requirement = self._const(element)
                        if isinstance(requirement, str):
                            for signal in check_requirement(requirement, node.lineno):
                                self._emit(signal.rule, node.lineno, ctx, signal.detail)

    # ---- Strings and payloads ---------------------------------------------

    def _process_strings(self) -> None:
        patterns = self._pattern_constants()
        for value, line, ctx, node_id in self._strings:
            if node_id not in patterns:
                self._check_string(value, line, ctx)
            if len(value) >= 64 and _ENCODED.fullmatch(value):
                self._check_encoded(value, line, ctx)

    def _pattern_constants(self) -> set[int]:
        """Strings used only as search patterns. They name what code looks for, so tools that
        detect `pastebin.com` don't read as using it. A URL given to a network call is still
        checked where that call is handled, and encoded payloads are still decoded."""
        found: set[int] = set()
        for node, ctx in self._calls:
            if node.args and self._resolve(node.func)[0] in _PATTERN_CALLS:
                pattern = node.args[0]
                sources = self._values(pattern.id, ctx[0]) if isinstance(pattern, ast.Name) else [pattern]
                for source in sources:
                    found.update(id(n) for n in ast.walk(source) if isinstance(n, ast.Constant))
        return found

    def _string_pieces(self, expr: ast.expr, seen: set[str] | None = None) -> list[str]:
        seen = set() if seen is None else seen
        pieces: list[str] = []
        for node in ast.walk(expr):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                value = node.value
                pieces.append(value.decode("latin-1") if isinstance(value, bytes) else value)
            elif isinstance(node, ast.Name) and node.id not in seen:
                seen.add(node.id)
                for value in self._assigned.get(node.id, ()):
                    pieces += self._string_pieces(value, seen)
        return pieces

    def _process_built_strings(self) -> None:
        """Flag a dangerous word that exists only once the pieces are put together.

        Requiring the word to span pieces keeps ordinary code generation quiet: building
        text around a whole word, like "exec " + command, doesn't hide anything.
        """
        for expr, ctx in self._built:
            value = self._const(expr)
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            if not isinstance(value, str) or not value or len(value) > 8192:
                continue
            words = {match.group(0) for match in _DANGEROUS_WORD.finditer(value)}
            if not words:
                continue
            pieces = self._string_pieces(expr)
            hidden = sorted(w for w in words if not any(w in piece for piece in pieces))
            if hidden:
                self._emit("obfuscated-name", expr.lineno, ctx, f"Builds {hidden[0]!r} from pieces")
                self._scan_payload(value, expr.lineno, ctx, encoded=True)
        for expr, ctx in self._annotations:
            value = self._const(expr)
            if isinstance(value, str) and "(" in value:
                self._scan_payload(value, expr.lineno, ctx, encoded=True)

    def _check_string(self, value: str, line: int, ctx: tuple) -> None:
        if _CREDENTIAL_PATH.search(value):
            self._emit("secret-path", line, ctx, value[:120])
        if _PERSISTENCE.search(value):
            self._emit("persistence", line, ctx, value[:120])
        if "://" in value or "." in value:
            if _BAD_HOST.search(value):
                self._emit("suspicious-host", line, ctx, value[:120])
            match = _IP_URL.search(value)
            if match:
                first, second = int(match.group(1)), int(match.group(2))
                private = (
                    first in (0, 10, 127) or (first == 192 and second == 168)
                    or (first == 172 and 16 <= second <= 31) or (first == 169 and second == 254)
                )
                if not private:
                    self._emit("raw-ip-url", line, ctx, value[:120])

    def _check_encoded(self, value: str, line: int, ctx: tuple) -> None:
        compact = "".join(value.split())
        decoded = None
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(compact + "=" * (-len(compact) % 4))
                break
            except (binascii.Error, ValueError):
                continue
        before = len(self.result.signals)
        if decoded is not None:
            for candidate in (decoded, self._try(_inflate, decoded), self._try(_inflate, decoded, 31)):
                if candidate:
                    self._scan_payload(candidate, line, ctx, encoded=True)
        if len(self.result.signals) == before and len(compact) >= 200 and _entropy(compact) > 5.0:
            self._emit("opaque-string", line, ctx, f"{len(compact)} characters")

    @staticmethod
    def _try(function, *args) -> bytes | None:
        try:
            return function(*args)
        except (zlib.error, ValueError):
            return None

    def _scan_payload(self, payload: str | bytes, line: int, ctx: tuple, encoded: bool) -> None:
        """Scan code held in a string. Only code that was encoded counts as hidden.

        Readable code, such as a test passing a script to `python -c`, is rated by
        what it does, as if it had been written directly on this line.
        """
        data = _as_bytes(payload)
        if self._depth >= _MAX_PAYLOAD_DEPTH or len(data) < 6 or data in self._payloads_seen:
            return
        self._payloads_seen.add(data)
        text = data.decode("latin-1")
        if _SHELL_ATTACK.search(text[:8192]):
            self._emit("hidden-code" if encoded else "shell-dangerous", line, ctx, f"Text: {text[:160]}")
            return
        try:
            tree = ast.parse(data)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            self._check_string(text[:8192], line, ctx)
            return
        visitor = SecurityVisitor(b"", self._depth + 1)
        try:
            inner = visitor.run(tree).signals
        except RecursionError:
            self._emit("too-complex", line, ctx, "Code held in a string")
            return
        for signal in inner:
            if RULES[signal.rule].caps & _DANGEROUS_CAPS:
                if encoded:
                    self._emit("hidden-code", line, ctx, f"{signal.rule} in decoded code: {text[:160]}")
                    return
                self._emit(signal.rule, line, ctx, f"In code held in a string: {signal.detail}")

    def _carries(self, expr: ast.expr, wanted, scope: str | None, seen: set[str] | None = None) -> bool:
        """Does `expr`, or a variable it uses, contain a node that `wanted` accepts?"""
        seen = set() if seen is None else seen
        for node in ast.walk(expr):
            if wanted(node):
                return True
            if isinstance(node, ast.Name) and node.id not in seen:
                seen.add(node.id)
                if any(self._carries(value, wanted, scope, seen) for value in self._values(node.id, scope)):
                    return True
        return False

    def _process_secret_flows(self) -> None:
        """Follow a secret into a network call's arguments, including through helpers in this file.

        A secret passed to a helper that sends it is the same as doing both in one
        function, so it's rated the same: medium, since API clients do it too, unless a
        silent except is hiding failures.
        """
        signals = self.result.signals
        secret_tops = {s.top for s in signals if s.rule in _SECRET_RULES and s.top}
        network_tops = {s.top for s in signals if "network" in RULES[s.rule].caps and s.top}
        silent_tops = {s.top for s in signals if s.rule == "silent-sink"}

        def local(name: str, ctx: tuple) -> str:
            owner, _, attr = name.partition(".")
            return f"{ctx[0].partition('.')[0]}.{attr}" if owner in ("self", "cls") and ctx[0] and attr else name

        # os.environ.get("X") and os.environ["X"] read one value, not the whole environment.
        one_value = {
            id(node.value) for node in ast.walk(self._tree)
            if isinstance(node, ast.Subscript) or (isinstance(node, ast.Attribute) and node.attr in ("get", "pop", "setdefault"))
        }

        def is_environ(node: ast.AST) -> bool:
            return (
                isinstance(node, (ast.Name, ast.Attribute)) and id(node) not in one_value
                and self._resolve(node)[0] == "os.environ"
            )

        def sent(argument: ast.expr, call: ast.Call, target: str, direct: bool) -> bool:
            return direct or self._param_may_send(target, self._bound_parameter(target, call, argument))

        def is_secret_call(ctx: tuple):
            def check(node: ast.AST) -> bool:
                if not isinstance(node, ast.Call):
                    return False
                name = self._resolve(node.func)[0]
                return bool(name) and local(name, ctx) in secret_tops
            return check

        for node, ctx in self._calls:
            name = self._resolve(node.func)[0]
            if not name:
                continue
            target = local(name, ctx)
            direct = self._is_network(name)
            if not direct and target not in network_tops:
                continue
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            scope = ctx[0]
            if any(self._carries(a, is_environ, scope) and sent(a, node, target, direct) for a in arguments):
                self._emit("env-exfiltration", node.lineno, ctx, name)
            elif any(self._carries(a, is_secret_call(ctx), scope) and sent(a, node, target, direct) for a in arguments):
                hidden = ctx[0] in silent_tops or (not direct and target in silent_tops)
                self._emit("silent-exfiltration" if hidden else "function-exfiltration", node.lineno, ctx, f"Into {name}")

    def _bound_parameter(self, target: str, call: ast.Call, argument: ast.expr) -> str | None:
        """The helper's parameter that receives `argument`, or None if that can't be told."""
        function = self._functions.get(target)
        if function is None:
            return None
        arguments = function.args
        positional = [a.arg for a in (*arguments.posonlyargs, *arguments.args)]
        if isinstance(call.func, ast.Attribute) and positional[:1] in (["self"], ["cls"]):
            positional = positional[1:]
        if any(isinstance(a, ast.Starred) for a in call.args):
            return None
        for position, value in enumerate(call.args):
            if value is argument:
                return positional[position] if position < len(positional) else None
        names = {*positional, *(a.arg for a in arguments.kwonlyargs)}
        for keyword in call.keywords:
            if keyword.value is argument:
                return keyword.arg if keyword.arg in names else None
        return None

    def _param_may_send(self, target: str, parameter: str | None) -> bool:
        """False only when a helper provably does nothing with a value but run a process with it.

        A helper that uses the network for something else isn't sending this value. Anything
        less certain counts as sending: another call, or storing it somewhere for later.
        """
        function = self._functions.get(target)
        if function is None or parameter is None:
            return True

        def holds(expr: ast.expr, seen: set[str] | None = None) -> bool:
            """Does `expr` hold the value? A started process doesn't hold what it was started with."""
            seen = set() if seen is None else seen
            for node in ast.walk(expr):
                if not isinstance(node, ast.Name):
                    continue
                if node.id == parameter:
                    return True
                if node.id not in seen:
                    seen.add(node.id)
                    for value in self._values(node.id, target):
                        started = isinstance(value, ast.Call) and self._resolve(value.func)[0] in _SHELL
                        if not started and holds(value, seen):
                            return True
            return False

        for node in ast.walk(function):
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(not isinstance(t, ast.Name) for t in targets) and holds(node.value):
                    return True
        for call, ctx in self._calls:
            if ctx[0] != target:
                continue
            name = self._resolve(call.func)[0]
            if name in _SHELL:
                continue
            # `env=` given to an imported function is how a process launcher takes its environment.
            spawner = bool(name) and not (
                self._is_network(name) or name in self._functions or name.startswith(("self.", "cls."))
            )
            for keyword in call.keywords:
                if holds(keyword.value) and not (spawner and keyword.arg == "env"):
                    return True
            if any(holds(value) for value in call.args):
                return True
        return False

    def _process_tries(self) -> None:
        if not self._silent_tries:
            return
        sinks = [s.line for s in self.result.signals if RULES[s.rule].caps & {"exec", "shell", "network"}]
        for start, end, ctx in self._silent_tries:
            if any(start <= line <= end for line in sinks):
                self._emit("silent-sink", start, ctx)


# ---- Whole-file checks ---------------------------------------------------------


def _mixed_script(name: str) -> bool:
    scripts = set()
    for char in name:
        if char.isalpha():
            scripts.add(unicodedata.name(char, "?").split(" ")[0])
    return "LATIN" in scripts and len(scripts) > 1


def _layout_signals(tree: ast.Module, data: bytes) -> list[Signal]:
    found: list[Signal] = []
    if not data.isascii():
        for match in _BIDI.finditer(data):
            line = data.count(b"\n", 0, match.start()) + 1
            found.append(Signal("bidi-control", line, detail="Trojan Source style characters"))
            break
        names = {
            n.id: n.lineno for n in ast.walk(tree) if isinstance(n, ast.Name) and not n.id.isascii()
        }
        for name, line in names.items():
            if _mixed_script(name):
                found.append(Signal("mixed-script", line, detail=name))
                break
    if _LONG_GAP.search(data):
        lines = data.split(b"\n")
        for node in ast.walk(tree):
            if isinstance(node, ast.stmt) and node.col_offset >= 40 and node.lineno <= len(lines):
                before = lines[node.lineno - 1][:node.col_offset]
                stripped = before.rstrip().removesuffix(b";").rstrip()
                gap = len(before) - len(stripped)
                if gap >= 40 and (stripped or node.col_offset >= 120):
                    found.append(Signal(
                        "whitespace-hidden", node.lineno, detail=f"{gap} spaces before this code",
                        snippet=lines[node.lineno - 1].strip().decode("utf-8", "replace")[:200],
                    ))
                    break
    return found


def scan_python_tree(tree: ast.Module, data: bytes) -> FileSignals:
    """Run all checks on an AST that has already been parsed."""
    from .scanner import AstScanner

    visitor = SecurityVisitor(data)
    result = visitor.run(tree)
    result.signals.extend(_layout_signals(tree, data))
    structure = AstScanner().scan(tree)
    result.thread_count = len(structure.threads)
    result.structure = {
        "functions": len(structure.functions),
        "nested_functions": sum(f.is_nested_def for f in structure.functions),
        "recursive_functions": sum(f.is_recursive for f in structure.functions),
        "loops": len(structure.loops),
        "max_loop_depth": max((l.depth for l in structure.loops), default=0),
        "threads": len(structure.threads),
        "module_calls": len(structure.module_calls),
    }
    return result


def scan_python(data: bytes) -> FileSignals:
    """Parse and scan Python source. Parsing problems are reported as signals."""
    try:
        return scan_python_tree(ast.parse(data), data)
    except (SyntaxError, ValueError) as error:
        line = getattr(error, "lineno", None) or 1
        result = FileSignals(status="unparsed")
        result.signals.append(Signal("unparsed", line, detail=str(error)[:200]))
        # Python 2 or broken code can still hide an attack, so check the raw text.
        text = data[:1024 * 1024].decode("latin-1")
        if _SHELL_ATTACK.search(text):
            result.signals.append(Signal("script-dangerous", 1, detail="Raw text of the unparsable file"))
        return result
    except (RecursionError, MemoryError):
        result = FileSignals(status="too-complex")
        result.signals.append(Signal("too-complex", 1))
        return result


def check_requirement(text: str, line: int) -> list[Signal]:
    """Check one requirement string, such as a line of requirements.txt."""
    text = text.split(" #", 1)[0].strip()
    if not text or text.startswith("#"):
        return []
    lowered = text.lower()
    if lowered.startswith(("--extra-index-url", "--index-url", "-i ", "--trusted-host", "--find-links", "-f ")):
        return [Signal("extra-index", line, detail=text[:200], snippet=text[:200])]
    if text.startswith(("-r ", "-c ", "--", "-e .")):
        return []
    if "://" in text or lowered.startswith(("git+", "hg+", "svn+", "bzr+", "-e ")):
        return [Signal("requirement-url", line, detail=text[:200], snippet=text[:200])]
    match = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", text)
    if not match:
        return []
    raw = match.group(0)
    name = normalize_dep(raw)
    if name in KNOWN_MALICIOUS or raw == "jeIlyfish":
        return [Signal("known-malicious-dep", line, detail=raw, snippet=text[:200])]
    if name not in POPULAR and len(name) >= 5:
        for popular in POPULAR:
            if _one_edit_apart(name, popular):
                return [Signal("typosquat-dep", line, detail=f"{raw} resembles {popular}", snippet=text[:200])]
    return []


def scan_requirements(data: bytes) -> FileSignals:
    result = FileSignals()
    for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        result.signals.extend(check_requirement(line, number))
    return result


def scan_pth(data: bytes) -> FileSignals:
    """Lines of a .pth file starting with `import` run at every interpreter start."""
    result = FileSignals()
    for number, raw in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if raw.startswith(("import ", "import\t")):
            result.signals.append(Signal("pth-exec", number, detail=raw[:200], snippet=raw[:200]))
            inner = scan_python(raw.encode("utf-8"))
            for signal in inner.signals:
                signal.line = number
                signal.snippet = raw[:200]
                result.signals.append(signal)
    return result


def scan_pyproject(data: bytes) -> FileSignals:
    import tomllib

    result = FileSignals()
    try:
        config = tomllib.loads(data.decode("utf-8", "replace"))
    except tomllib.TOMLDecodeError as error:
        result.status = "unparsed"
        result.signals.append(Signal("unparsed", 1, detail=str(error)[:200]))
        return result
    build = config.get("build-system", {})
    if isinstance(build, dict) and build.get("backend-path"):
        result.signals.append(Signal("custom-backend", 1, detail=str(build.get("build-backend"))[:200]))
    declared: list[object] = []
    if isinstance(build, dict):
        declared += build.get("requires", []) or []
    project = config.get("project", {})
    if isinstance(project, dict):
        declared += project.get("dependencies", []) or []
    for requirement in declared:
        if isinstance(requirement, str):
            result.signals.extend(check_requirement(requirement, 1))
    return result


def scan_setup_cfg(data: bytes) -> FileSignals:
    result = FileSignals()
    active = False
    for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        stripped = line.strip()
        if re.match(r"(install_requires|setup_requires)\s*=", stripped):
            active = True
            stripped = stripped.partition("=")[2].strip()
        elif active and (not line[:1].isspace() or not stripped):
            active = False
        if active and stripped:
            result.signals.extend(check_requirement(stripped, number))
    return result


def scan_script(data: bytes) -> FileSignals:
    result = FileSignals()
    text = data[:4 * 1024 * 1024].decode("latin-1")
    match = _SHELL_ATTACK.search(text)
    if match:
        line = text.count("\n", 0, match.start()) + 1
        result.signals.append(Signal("script-dangerous", line, detail=match.group(0)[:200], snippet=match.group(0)[:200]))
    return result


# ---- Rating ----------------------------------------------------------------------


def file_kind(path: str) -> str:
    """install: runs during pip install. test: not imported by users of a package."""
    name = path.rsplit("/", 1)[-1].lower()
    if name == "setup.py" or name.endswith(".pth"):
        return "install"
    parts = path.lower().split("/")[:-1]
    if any(p in ("test", "tests", "testing") for p in parts) or name.startswith("test_") or name.endswith("_test.py"):
        return "test"
    return "module"


def _context(signal: Signal, kind: str, install_reached: bool) -> str:
    if kind == "install":
        return "install"
    if not signal.module_level:
        return "runtime"
    if install_reached:
        return "install"
    return "runtime" if kind == "test" else "import"


def _severity(rule: Rule, context: str) -> str:
    return {"install": rule.install, "import": rule.imported, "runtime": rule.runtime}[context]


def rate_file(path: str, signals: FileSignals, install_reached: bool = False) -> list[Finding]:
    kind = file_kind(path)
    findings: list[Finding] = []
    by_context: dict[str, list[Signal]] = {"install": [], "import": [], "runtime": []}

    def add(rule_name: str, context: str, line: int, detail: str = "", snippet: str = "") -> None:
        rule = RULES[rule_name]
        findings.append(Finding(rule_name, _severity(rule, context), context, path, line, rule.message, detail, snippet))

    for signal in signals.signals:
        context = _context(signal, kind, install_reached)
        by_context[context].append(signal)
        add(signal.rule, context, signal.line, signal.detail, signal.snippet)

    def has(group: list[Signal], cap: str) -> list[Signal]:
        return [s for s in group if cap in RULES[s.rule].caps]

    for context in ("install", "import"):
        _rate_combinations(by_context[context], context, has, add)

    scopes: dict[str | None, list[Signal]] = {}
    for signal in by_context["runtime"]:
        scopes.setdefault(signal.top, []).append(signal)
    for top, group in scopes.items():
        if top is None:
            continue
        network = has(group, "network")
        if not network:
            continue
        sink = network[0]
        credential = [s for s in group if s.rule == "secret-path"]
        named_secret = [s for s in group if s.rule in ("secret-env", "secret-env-dump")]
        if credential:
            add("credential-exfiltration", "runtime", sink.line, f"{top}: credential reference on line {credential[0].line}", sink.snippet)
        elif any(s.rule == "secret-env-dump" for s in group):
            add("exfiltration", "runtime", sink.line, f"{top}: reads the environment", sink.snippet)
        if credential or named_secret:
            source = (credential or named_secret)[0]
            silent = any(s.rule == "silent-sink" for s in group)
            add("silent-exfiltration" if silent else "function-exfiltration", "runtime", sink.line,
                f"{top}: secret on line {source.line}", sink.snippet)
    return findings


def _rate_combinations(group: list[Signal], context: str, has, add) -> None:
    network = has(group, "network")
    if not group:
        return
    if network:
        sink = network[0]
        secrets = has(group, "secret")
        if secrets:
            add("exfiltration", context, sink.line, f"Secret source on line {secrets[0].line}", sink.snippet)
        recon = has(group, "recon")
        if recon:
            add("recon-exfiltration", context, sink.line, f"{recon[0].detail} on line {recon[0].line}", sink.snippet)
        if any(s.rule == "exec-dynamic" for s in group):
            add("download-execute", context, sink.line, "", sink.snippet)
    if has(group, "obfuscation"):
        sinks = [s for s in group if RULES[s.rule].caps & {"shell", "network", "exec"} and "obfuscation" not in RULES[s.rule].caps]
        if sinks:
            add("obfuscated-sink", context, sinks[0].line, sinks[0].rule, sinks[0].snippet)


# Each verdict owns a band, so a score can never contradict the verdict beside it.
_RISK_BANDS = {"SAFE": (0, 29), "SUSPICIOUS": (30, 69), "MALICIOUS": (70, 100)}
_RISK_POINTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
_RISK_HALF_POINTS = 50

# Findings about code hidden in, or run from, data. Anything else stays only in `findings`.
PAYLOAD_KINDS = {
    "hidden-code": "encoded-code",
    "exec-decoded": "decoded-exec",
    "hidden-sink": "decoded-exec",
    "exec-network": "remote-exec",
    "exec-dynamic": "dynamic-exec",
    "exec-constant": "dynamic-exec",
    "exec-data-file": "dynamic-exec",
    "code-object": "dynamic-exec",
    "pth-exec": "dynamic-exec",
    "deserialize-code": "deserialization",
    "deserialize-pickle": "deserialization",
    "decoder": "decoder",
    "opaque-string": "opaque-string",
}
_PAYLOAD_ENCODINGS = (
    ("base64", ("b64decode", "base64", "b32decode", "b85decode", "a85decode")),
    ("hex", ("unhexlify", "fromhex")),
    ("rot13", ("rot13", "rot_13")),
    ("zlib", ("zlib", "decompress", "gzip", "bz2", "lzma")),
    ("marshal", ("marshal",)),
    ("pickle", ("pickle",)),
)
_MAX_PAYLOAD_PREVIEW = 500


def risk_score(findings: list[Finding]) -> int:
    """Rank results from 0 to 100 for triage. A heuristic, not a probability of compromise."""
    low, high = _RISK_BANDS[verdict_for(findings)]
    points = sum(_RISK_POINTS[f.severity] for f in findings)
    # Flattens instead of capping, so large repositories don't all reach the top of a band.
    return low + math.ceil((high - low) * (1 - 0.5 ** (points / _RISK_HALF_POINTS)))


def payload_fields(finding: Finding) -> tuple[str, str | None, str] | None:
    """(kind, encoding, preview) for a payload finding, otherwise None.

    The encoding is read from the text around the finding, so it's a best guess and is
    None when that text doesn't name one.
    """
    kind = PAYLOAD_KINDS.get(finding.rule)
    if kind is None:
        return None
    text = f"{finding.snippet} {finding.detail}"
    lowered = text.lower()
    encoding = next((name for name, words in _PAYLOAD_ENCODINGS if any(w in lowered for w in words)), None)
    return kind, encoding, text.strip()[:_MAX_PAYLOAD_PREVIEW]


def verdict_for(findings: list[Finding]) -> str:
    """Medium findings are notes. Absence of findings isn't proof of safety, as the report says."""
    severities = {f.severity for f in findings}
    if "critical" in severities:
        return "MALICIOUS"
    if "high" in severities or any(f.rule in COVERAGE_RULES for f in findings):
        return "SUSPICIOUS"
    return "SAFE"
