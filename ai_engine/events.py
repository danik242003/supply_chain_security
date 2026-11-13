"""Fire-and-forget telemetry events pushed to the admin dashboard (standard library only).

Deliberately a copy of ``ast_detection.events``: the two services share no code.

Events are queued and POSTed in batches by a daemon thread, so analysis latency is
never affected. When ``EVENT_SINK_URL`` is unset, or the dashboard is down, events
are dropped (and counted): telemetry must never break detection.

Event envelope::

    {"id", "ts", "source", "type", "request_id", "package", "data": {...}}
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

TOKEN_HEADER = "X-SCS-Token"


class EventEmitter:
    """Asynchronous batch emitter.

    Args:
        source: Name of the emitting service (``ast_detection``, ``ai_engine``, ...).
        url: Ingest endpoint; defaults to ``$EVENT_SINK_URL`` (disabled if empty).
        token: Shared secret sent as ``X-SCS-Token``; defaults to ``$SCS_EVENT_TOKEN``.
    """

    def __init__(self, source: str, url: str | None = None, token: str | None = None, max_queue: int = 2000) -> None:
        self.source = source
        self.url = url if url is not None else os.environ.get("EVENT_SINK_URL", "")
        self.token = token if token is not None else os.environ.get("SCS_EVENT_TOKEN", "")
        self.dropped = 0
        self.sent = 0
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max_queue)
        self._idle = threading.Event()
        self._idle.set()
        if self.url:
            threading.Thread(target=self._worker, name=f"{source}-events", daemon=True).start()

    @property
    def enabled(self) -> bool:
        """Whether a sink is configured."""
        return bool(self.url)

    def emit(self, event_type: str, *, request_id: str | None = None, package: str | None = None,
             **data: Any) -> dict[str, Any]:
        """Queue an event (non-blocking). Returns the event envelope."""
        event = {
            "id": uuid.uuid4().hex,
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": self.source,
            "type": event_type,
            "request_id": request_id,
            "package": package,
            "data": data,
        }
        if self.url:
            try:
                self._idle.clear()
                self._queue.put_nowait(event)
            except queue.Full:
                self.dropped += 1
        return event

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until the queue is drained (used before short-lived processes exit)."""
        if not self.url:
            return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.empty() and self._idle.wait(0.05):
                return True
            time.sleep(0.02)
        return False

    def _worker(self) -> None:
        while True:
            batch = [self._queue.get()]
            while len(batch) < 50:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            self._post(batch)
            if self._queue.empty():
                self._idle.set()

    def _post(self, batch: list[dict[str, Any]]) -> None:
        body = json.dumps({"events": batch}, default=str).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", TOKEN_HEADER: self.token})
        try:
            with urllib.request.urlopen(req, timeout=3):  # noqa: S310 (internal URL)
                self.sent += len(batch)
        except Exception as exc:  # telemetry is best-effort
            self.dropped += len(batch)
            logger.debug("event delivery failed (%s); dropped %d", exc, len(batch))
