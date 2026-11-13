"""Phase 1: a fast text filter that decides which files deserve an AST.

Skipping a file means trusting this filter, so it follows one rule: a word is here
if code needs that word to reach a dangerous capability. tests/test_phases.py
checks on real code that it never drops a file the full AST scan would flag.

For speed it splits a file into a *set* of words once, then does set lookups, which
gives word boundaries for free. Slower regexes only run if a word makes them relevant.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Always analyzed, because they run automatically.
ENTRY_POINTS = frozenset({"setup.py", "__init__.py", "__main__.py", "conftest.py"})

_WORDS = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")

# Dangerous wherever they appear: reaching these needs no import.
_ALWAYS = frozenset({
    b"ForwardRef", b"HTTPHandler", b"SocketHandler", b"DatagramHandler", b"SMTPHandler", b"meta_path", b"path_hooks",
    b"_create_default_https_context", b"exec", b"eval", b"execfile", b"__import__", b"__builtins__", b"__builtin__",
    b"globals", b"__subclasses__", b"__bases__", b"__mro__", b"__globals__", b"__code__", b"__getattribute__",
    b"FunctionType", b"CodeType", b"popen", b"Popen", b"execl", b"execle", b"execlp", b"execlpe", b"execv",
    b"execve", b"execvp", b"execvpe", b"spawnl", b"spawnle", b"spawnlp", b"spawnlpe", b"spawnv", b"spawnve",
    b"spawnvp", b"spawnvpe", b"posix_spawn", b"posix_spawnp", b"environ", b"getenv", b"gethostname", b"getlogin",
    b"getnode", b"fromhex", b"unhexlify", b"rot13", b"unlink", b"rmtree", b"authorized_keys", b"crontab",
    b"LaunchAgents", b"LaunchDaemons", b"id_rsa", b"id_ed25519", b"pastebin", b"hastebin", b"ngrok", b"requestbin",
    b"requestcatcher", b"pipedream", b"oastify", b"burpcollaborator",
})
# Common English or names, so they count only on an import line.
_MODULES = frozenset({
    b"importlib", b"runpy", b"builtins", b"marshal", b"pickle", b"cPickle", b"shelve", b"dill", b"ctypes", b"cffi",
    b"subprocess", b"pty", b"commands", b"socket", b"urllib", b"urllib2", b"urllib3", b"requests", b"httpx",
    b"aiohttp", b"http", b"httplib", b"ftplib", b"smtplib", b"telnetlib", b"paramiko", b"xmlrpc", b"websocket",
    b"pycurl", b"webbrowser", b"dns", b"getpass", b"base64", b"binascii", b"zlib", b"gzip", b"bz2", b"lzma",
    b"codecs", b"atexit", b"platform", b"uuid", b"asyncio",
})
# word -> a pattern that must also match, because the word alone is common.
_GATED = {
    word: re.compile(pattern) for word, pattern in {
        b"system": rb"\.system\b",
        b"compile": rb"(?<![.\w])compile\b",
        b"chr": rb"\bchr\s*\(",
        b"bytes": rb"\bbytes\s*\(\s*\[",
        b"modules": rb"\bsys\s*\.\s*modules\b",
        b"remove": rb"\.remove\s*\(\s*__file__",
        b"ssh": rb"\.ssh\b", b"aws": rb"\.aws\b", b"netrc": rb"\.netrc\b", b"pypirc": rb"\.pypirc\b",
        b"npmrc": rb"\.npmrc\b", b"credentials": rb"\.git-credentials\b", b"docker": rb"\.docker\b",
        b"kube": rb"\.kube\b", b"gnupg": rb"\.gnupg\b", b"bashrc": rb"\.bashrc\b", b"bash_profile": rb"\.bash_profile\b",
        b"bash_history": rb"\.bash_history\b", b"zshrc": rb"\.zshrc\b", b"etc": rb"/etc/(?:shadow|passwd|cron|systemd|rc\.local)",
        b"autostart": rb"\.config/autostart", b"CurrentVersion": rb"CurrentVersion", b"Login": rb"Login Data",
        b"Local": rb"Local State", b"wallet": rb"wallet\.dat", b"paste": rb"paste\.ee", b"transfer": rb"transfer\.sh",
        b"webhook": rb"webhook\.site", b"webhooks": rb"api/webhooks", b"telegram": rb"api\.telegram",
        b"interact": rb"interact\.sh", b"curl": rb"\bcurl\b[^\n]*\|", b"wget": rb"\bwget\b[^\n]*\|",
    }.items()
}
# A backslash can continue an import onto the next line.
_IMPORT_LINE = re.compile(rb"\b(?:import|from)\b(?:[^\n\\]|\\[\s\S])*")
_FROM_OS = re.compile(rb"\bfrom\s+(?:os|sys)\b")
_RISKY_HANDLE = re.compile(rb"\bimport\s+(?:[\w.]+\s*,\s*)*(?:os|sys)\b")
_REFLECTION = frozenset({b"getattr", b"vars", b"__dict__", b"locals", b"attrgetter"})
# A string assembled from pieces, which is how a name dodges every word list above.
_BUILT_STRING = re.compile(rb"""['"]\s*\+\s*['"]|\[\s*:\s*:\s*-\s*1\s*\]|\bjoin\s*\(\s*[\[(]\s*b?['"]""")
_IP_URL = re.compile(rb"://\d")
_HEX_ESCAPES = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){8}")
_LONG_ENCODED = re.compile(rb"[A-Za-z0-9+/_\-=]{64}")
_LONG_GAP = re.compile(rb"[ \t]{40}\S")
# Python honours these, so a file can spell every keyword in another encoding.
_ENCODING_COOKIE = re.compile(rb"\A(?:[^\n]*\n)?[ \t\f]*#[^\n]*coding[:=][ \t]*([-\w.]+)")
_PLAIN_ENCODINGS = frozenset({"utf-8", "utf8", "ascii", "us-ascii", "latin-1", "latin1", "iso-8859-1"})
_BIDI = re.compile(rb"\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]")
_IMPORTS = re.compile(rb"^[ \t]*(?:from[ \t]+(\.*[\w.]*)[ \t]+import\b[ \t]*\(?([^\n#]*)|import[ \t]+([^\n#]+))", re.M)
_MAX_REASONS = 6


@dataclass(slots=True)
class FilterResult:
    flagged: bool
    reasons: list[str] = field(default_factory=list)


def _reasons(data: bytes) -> list[str]:
    words = set(_WORDS.findall(data))
    reasons = sorted(w.decode("latin-1") for w in words & _ALWAYS)
    if b"import" in words or b"from" in words:
        imported: set[bytes] = set()
        for line in _IMPORT_LINE.findall(data):
            imported.update(_WORDS.findall(line))
        reasons += sorted(w.decode("latin-1") for w in imported & _MODULES)
        if _FROM_OS.search(data):
            reasons.append("from os/sys")
    for word in words & _GATED.keys():
        if _GATED[word].search(data):
            reasons.append(word.decode("latin-1"))
    if words & _REFLECTION and _RISKY_HANDLE.search(data):
        reasons.append("reflection")
    if _BUILT_STRING.search(data):
        reasons.append("built-up string")
    if _IP_URL.search(data):
        reasons.append("IP address URL")
    if _HEX_ESCAPES.search(data):
        reasons.append("hex escapes")
    if _LONG_ENCODED.search(data):
        reasons.append("long encoded string")
    if _LONG_GAP.search(data):
        reasons.append("long whitespace gap")
    return reasons


def scan_text(data: bytes, name: str = "") -> FilterResult:
    """Decide from raw bytes alone. Never parses or runs anything."""
    if name.rsplit("/", 1)[-1].lower() in ENTRY_POINTS:
        return FilterResult(True, ["entry point"])
    reasons = _reasons(data)
    if b"\0" in data:
        reasons.append("NUL byte")
    cookie = _ENCODING_COOKIE.match(data)
    if cookie and cookie.group(1).decode("latin-1").lower().replace("_", "-") not in _PLAIN_ENCODINGS:
        reasons.append(f"encoding {cookie.group(1).decode('latin-1')}")
    if not data.isascii():
        # Python normalizes identifiers, so a fullwidth "exec" really is exec.
        if _BIDI.search(data):
            reasons.append("bidi control characters")
        text = data.decode("utf-8", "replace")
        normalized = unicodedata.normalize("NFKC", text).encode("utf-8", "replace")
        if normalized != text.encode("utf-8", "replace"):
            reasons += [r for r in _reasons(normalized) if r not in reasons]
        if _mixed_script_words(text):
            reasons.append("mixed-script identifier")
    return FilterResult(bool(reasons), reasons[:_MAX_REASONS])


def _mixed_script_words(text: str) -> bool:
    for word in re.findall(r"[^\W\d]+", text):
        if not word.isascii() and any(c.isascii() for c in word):
            return True
    return False


def fast_imports(data: bytes) -> list[tuple[str, int]]:
    """Imports found without parsing, so filtered files still link setup.py to what it reaches."""
    found: list[tuple[str, int]] = []
    for match in _IMPORTS.finditer(data):
        if match.group(3) is not None:
            for part in match.group(3).split(b","):
                words = part.split()
                if words:
                    found.append((words[0].decode("latin-1"), 0))
            continue
        module = match.group(1).decode("latin-1")
        level = len(module) - len(module.lstrip("."))
        base = module.lstrip(".")
        found.append((base, level))
        for part in (match.group(2) or b"").replace(b")", b"").split(b","):
            words = part.split()
            if words and words[0] != b"*":
                name = words[0].decode("latin-1")
                found.append((f"{base}.{name}" if base else name, level))
    return found
