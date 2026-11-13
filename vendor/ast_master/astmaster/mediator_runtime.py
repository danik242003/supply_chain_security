"""Client-side Mediator. Its AST is embedded into every transformed program.

This file must stay standalone: standard library only, with all imports local,
so it can't collide with names in the user's program.
"""


def _astmaster_merge(live, before, after):
    """Apply what a worker changed (before -> after) to the client's live object."""
    if type(live) is not type(after) or type(before) is not type(after):
        return
    if isinstance(live, dict):
        for key in before:
            if key not in after:
                live.pop(key, None)
        for key, value in after.items():
            if key not in before:
                live[key] = value
            elif before[key] != value:
                if isinstance(value, (dict, list, set)) and key in live:
                    _astmaster_merge(live[key], before[key], value)
                else:
                    live[key] = value
    elif isinstance(live, list):
        for index, value in enumerate(after[:len(before)]):
            if before[index] != value and index < len(live):
                if isinstance(value, (dict, list, set)):
                    _astmaster_merge(live[index], before[index], value)
                else:
                    live[index] = value
        if len(after) > len(before):
            live.extend(after[len(before):])
        elif len(after) < len(before):
            del live[len(after):]
    elif isinstance(live, set):
        live.difference_update(before - after)
        live.update(after - before)


class _AstMasterError(RuntimeError):
    pass


class _AstMasterTask:
    """Stands in for a Thread, including any use the rewrite didn't reach."""

    def __init__(self, template_id, args, kwargs, name, daemon):
        self.template_id = template_id
        self.args = tuple(args)
        self.kwargs = dict(kwargs or {})
        self.name = name or "remote-task"
        self.daemon = bool(daemon)
        self.result = None
        self.exception = None
        self.task_id = None
        self.finished = False
        self.sent_args = None
        self.sent_kwargs = None

    def start(self):
        __mediator__.submit(self)

    def join(self, timeout=None):
        __mediator__.wait(self, timeout)

    def is_alive(self):
        return self.task_id is not None and not __mediator__.poll(self)


class _AstMasterMediator:
    def __init__(self):
        self._registered = False
        self._outstanding = []

    def create_task(self, template_id, args=(), kwargs=None, name=None, daemon=None):
        return _AstMasterTask(template_id, args, kwargs, name, daemon)

    def submit(self, task):
        """Send the task and return immediately, as Thread.start() does."""
        import ast
        import atexit

        if task.task_id is not None:
            raise RuntimeError("threads can only be started once")
        args_repr = repr(task.args)
        kwargs_repr = repr(task.kwargs)
        try:
            task.sent_args = ast.literal_eval(args_repr)
            task.sent_kwargs = ast.literal_eval(kwargs_repr)
        except (ValueError, SyntaxError) as error:
            raise _AstMasterError(
                f"arguments of {task.name} can't be sent to a worker: only plain "
                f"data (numbers, strings, lists, dicts...) is supported: {args_repr[:200]}"
            ) from error
        reply = self._request("POST", "/api/tasks", {
            "template_id": task.template_id,
            "args_repr": args_repr,
            "kwargs_repr": kwargs_repr,
        })
        task.task_id = reply["task_id"]
        self._outstanding.append(task)
        if not self._registered:
            self._registered = True
            atexit.register(self._drain)

    def wait(self, task, timeout=None):
        """Pause until the server responds, apply the result, then resume."""
        import time

        if task.task_id is None:
            raise RuntimeError("cannot join thread before it is started")
        deadline = None if timeout is None else time.monotonic() + timeout
        while not task.finished:
            remaining = 25.0 if deadline is None else max(0.0, min(25.0, deadline - time.monotonic()))
            self._check(task, remaining)
            if deadline is not None and time.monotonic() >= deadline:
                return

    def poll(self, task):
        if not task.finished:
            self._check(task, 0)
        return task.finished

    def _check(self, task, wait_seconds):
        reply = self._request("GET", f"/api/tasks/{task.task_id}?wait={wait_seconds:.3f}")
        if reply["status"] == "done":
            self._apply(task, reply)
        elif reply["status"] == "failed":
            task.finished = True
            self._forget(task)
            raise _AstMasterError(f"{task.name} failed on the server: {reply.get('error')}")

    def _apply(self, task, reply):
        import ast
        import sys

        task.finished = True
        self._forget(task)
        if reply.get("stdout"):
            sys.stdout.write(reply["stdout"])
        if reply.get("stderr"):
            sys.stderr.write(reply["stderr"])
        if reply.get("writeback_error"):
            raise _AstMasterError(f"{task.name}: {reply['writeback_error']}")
        task.result = ast.literal_eval(reply["result_repr"])
        after_args = ast.literal_eval(reply["args_repr"])
        after_kwargs = ast.literal_eval(reply["kwargs_repr"])
        for live, before, after in zip(task.args, task.sent_args, after_args):
            _astmaster_merge(live, before, after)
        for key, live in task.kwargs.items():
            _astmaster_merge(live, task.sent_kwargs[key], after_kwargs[key])
        if reply.get("exception"):
            # A failing thread prints its traceback and join() still returns.
            task.exception = reply["exception"]
            sys.stderr.write(f"Exception in remote thread {task.name}:\n{task.exception}")

    def _forget(self, task):
        if task in self._outstanding:
            self._outstanding.remove(task)

    def _drain(self):
        # Python waits for non-daemon threads at exit, so do the same here.
        for task in list(self._outstanding):
            if not task.daemon:
                self.wait(task)

    def _request(self, method, path, payload=None):
        import json
        import os
        import urllib.error
        import urllib.request

        base = os.environ.get("AST_MASTER_URL", "http://127.0.0.1:8000").rstrip("/")
        headers = {"X-Mediator-Token": os.environ.get("AST_MASTER_TOKEN", "")}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:500]
            raise _AstMasterError(f"master rejected {method} {path}: {error.code} {detail}") from error
        except OSError as error:
            raise _AstMasterError(f"can't reach the master at {base}: {error}") from error


__mediator__ = _AstMasterMediator()
