"""Runs one finalized template in a child process. Standard library only.

Reads source on stdin and writes one JSON result to the original stdout. User
code's own output is captured, and anything written directly to file descriptor
1 goes to stderr, so it can't corrupt the result.
"""

import ast
import contextlib
import io
import json
import os
import sys
import traceback


def literal_repr(value):
    text = repr(value)
    ast.literal_eval(text)
    return text


def main():
    source = sys.stdin.buffer.read().decode("utf-8", "surrogatepass")
    result_fd = os.dup(1)
    os.dup2(2, 1)
    captured = io.StringIO()
    namespace = {"__name__": "__astmaster_worker__"}
    exception = None
    try:
        with contextlib.redirect_stdout(captured):
            exec(compile(source, "<template>", "exec"), namespace)
    except SystemExit:
        pass  # In a thread, SystemExit ends only that thread, silently.
    except BaseException:
        exception = traceback.format_exc()

    # A thread's return value is optional, so a non-literal one is just dropped.
    try:
        result_repr = literal_repr(namespace.get("__result__"))
    except (ValueError, SyntaxError, RecursionError, MemoryError):
        result_repr = "None"
    payload = {"stdout": captured.getvalue(), "exception": exception, "result_repr": result_repr}
    try:
        payload["args_repr"] = literal_repr(namespace.get("__args__", ()))
        payload["kwargs_repr"] = literal_repr(namespace.get("__kwargs__", {}))
    except (ValueError, SyntaxError, RecursionError, MemoryError):
        payload["writeback_error"] = "the target left non-data objects in its arguments, so they can't be returned"
    with os.fdopen(result_fd, "w", encoding="ascii") as out:
        json.dump(payload, out)


if __name__ == "__main__":
    main()
