"""Runs finalized templates on this machine, standing in for cluster workers.

Each task is a separate process, so it has its own memory like a remote node
does. THIS IS NOT A SANDBOX: tasks run arbitrary code with this user's rights.
"""

from __future__ import annotations

import ast
import json
import os
import secrets
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .db import AnalysisRepository, TaskRepository

_RUNNER = str(Path(__file__).with_name("worker_runner.py"))


class UnknownTemplate(KeyError):
    pass


class LocalExecutor:
    def __init__(
        self,
        analyses: AnalysisRepository,
        tasks: TaskRepository,
        max_workers: int | None = None,
        task_timeout: float = 300.0,
    ) -> None:
        self._analyses = analyses
        self._tasks = tasks
        self._timeout = task_timeout
        self._pool = ThreadPoolExecutor(max_workers or os.cpu_count() or 1, thread_name_prefix="task")
        # Only for waking long-polling clients. The database holds the actual state.
        self._waiters: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def submit(self, template_id: str, args_repr: str, kwargs_repr: str) -> str:
        """Raises UnknownTemplate, TypeError or ValueError if the request is bad."""
        template = self._analyses.get_template(template_id)
        if template is None:
            raise UnknownTemplate(template_id)
        try:
            args = ast.literal_eval(args_repr)
            kwargs = ast.literal_eval(kwargs_repr)
        except (SyntaxError, MemoryError, RecursionError) as error:
            raise ValueError(f"arguments aren't literal data: {error}") from error
        if type(args) is not tuple or type(kwargs) is not dict:
            raise ValueError("args must be a tuple and kwargs a dict")
        task = template.finalize(args, kwargs)

        task_id = secrets.token_urlsafe(12)
        self._tasks.create(task_id, template_id, args_repr, kwargs_repr)
        with self._lock:
            self._waiters[task_id] = threading.Event()
        self._pool.submit(self._run, task_id, task.source)
        return task_id

    def _run(self, task_id: str, source: str) -> None:
        self._tasks.mark_running(task_id)
        try:
            process = subprocess.run(
                [sys.executable, "-I", _RUNNER],
                input=source.encode("utf-8", "surrogatepass"),
                capture_output=True,
                timeout=self._timeout,
            )
            if process.returncode != 0:
                stderr = process.stderr.decode("utf-8", "replace")[-2000:]
                raise RuntimeError(f"worker exited with status {process.returncode}: {stderr}")
            reply = json.loads(process.stdout)
            reply["stderr"] = process.stderr.decode("utf-8", "replace")
            self._tasks.finish(task_id, "done", reply)
        except subprocess.TimeoutExpired:
            self._tasks.finish(task_id, "failed", {"error": f"timed out after {self._timeout:g}s"})
        except (OSError, RuntimeError, ValueError) as error:
            self._tasks.finish(task_id, "failed", {"error": str(error)})
        finally:
            with self._lock:
                waiter = self._waiters.pop(task_id, None)
            if waiter:
                waiter.set()

    def status(self, task_id: str, wait: float = 0.0) -> dict | None:
        if wait > 0:
            with self._lock:
                waiter = self._waiters.get(task_id)
            if waiter:
                waiter.wait(wait)
        return self._tasks.get(task_id)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
