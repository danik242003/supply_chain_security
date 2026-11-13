"""AST Master: static analysis and thread-to-cluster transformation for Python."""

from .pipeline import AnalysisResult, analyze_source

__all__ = ["AnalysisResult", "analyze_source"]
