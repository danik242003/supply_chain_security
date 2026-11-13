"""HTTP client for the AST detection service (standard library only).

The AI engine never imports the AST code: it talks to the service over HTTP
(``AST_SERVICE_URL``; ``http://ast_detection:8000`` inside Docker Compose) and
verifies every response before its features are used:

* schema version is supported,
* the SHA-256 ``feature_digest`` matches the received features (transport integrity),
* the service reports the package it was asked about.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

from ai_engine.config import AST_SERVICE_URL, SUPPORTED_AST_SCHEMA


class ASTServiceError(RuntimeError):
    """Service unreachable, returned an error, or produced an unverifiable response."""


def feature_digest(features: Mapping[str, float]) -> str:
    """Recompute the service's digest (must stay byte-identical to the server side)."""
    payload = json.dumps({k: round(float(v), 6) for k, v in sorted(features.items())}, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ASTServiceClient:
    """Client for ``/health``, ``/analyze`` and ``/analyze/batch``.

    Args:
        base_url: Service URL; defaults to ``$AST_SERVICE_URL``.
        timeout: Per-request timeout in seconds.
    """

    def __init__(self, base_url: str | None = None, timeout: float = 120.0) -> None:
        self.base_url = (base_url or AST_SERVICE_URL).rstrip("/")
        self.timeout = timeout

    def _request(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base_url + path, data=data, method="POST" if data else "GET",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (internal URL)
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise ASTServiceError(f"{path} -> HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise ASTServiceError(f"AST service unreachable at {self.base_url}: {exc}") from exc

    def health(self) -> dict[str, Any]:
        """Service status, backend description and feature names."""
        return self._request("/health")

    def wait_until_ready(self, timeout: float = 60.0, interval: float = 1.0) -> dict[str, Any]:
        """Poll ``/health`` until the service answers or ``timeout`` elapses."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.health()
            except ASTServiceError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval)

    def analyze(self, name: str, files: Mapping[str, str]) -> dict[str, Any]:
        """Analyse one package and return the verified result."""
        return self.verify(self._request("/analyze", {"name": name, "files": dict(files)}), expected_name=name)

    def analyze_batch(self, packages: Sequence[Mapping[str, Any]], chunk_size: int = 100) -> list[dict[str, Any]]:
        """Analyse many ``{"name", "files"}`` packages, preserving order."""
        results: list[dict[str, Any]] = []
        for start in range(0, len(packages), chunk_size):
            chunk = [{"name": p["name"], "files": dict(p["files"]),
                      **({"request_id": p["request_id"]} if p.get("request_id") else {})}
                     for p in packages[start:start + chunk_size]]
            response = self._request("/analyze/batch", {"packages": chunk})["results"]
            if len(response) != len(chunk):
                raise ASTServiceError("batch response length mismatch")
            results.extend(self.verify(r, expected_name=p["name"]) for r, p in zip(response, chunk))
        return results

    @staticmethod
    def verify(result: dict[str, Any], expected_name: str | None = None) -> dict[str, Any]:
        """Validate schema, package identity and feature digest of one result."""
        if result.get("schema_version") != SUPPORTED_AST_SCHEMA:
            raise ASTServiceError(f"unsupported AST schema {result.get('schema_version')}")
        if expected_name is not None and result.get("package") != expected_name:
            raise ASTServiceError(f"response for {result.get('package')!r}, expected {expected_name!r}")
        features = result.get("features")
        if not isinstance(features, dict) or not features:
            raise ASTServiceError("response carries no features")
        if feature_digest(features) != result.get("feature_digest"):
            raise ASTServiceError("feature digest mismatch: AST features corrupted in transit")
        return result
