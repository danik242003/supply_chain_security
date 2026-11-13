"""tinyjson: small helpers for JSON documents."""

import json
import os

__version__ = "2.4.1"


def load(path):
    """Load a JSON document from disk."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def dump(obj, path, indent=2):
    """Write ``obj`` as JSON, creating parent directories."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=indent)


def flatten(doc, prefix=""):
    """Flatten nested dicts into dotted keys."""
    out = {}
    for key, value in doc.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            out.update(flatten(value, name))
        else:
            out[name] = value
    return out
