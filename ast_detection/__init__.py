"""AST detection service: static analysis of package source into security feature vectors.

Never executes analysed code. Wraps the local AST Master analyzer (``astmaster``)
when it is available and always runs the built-in extractor in
:mod:`ast_detection.extractors`.
"""

__version__ = "1.0.0"
FEATURE_SCHEMA_VERSION = 1
