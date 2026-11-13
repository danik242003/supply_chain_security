"""Source -> scan -> validate -> templates + transformed AST."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .mediator import transform
from .models import Issue, ScanResult, Severity
from .scanner import AstScanner
from .security import Finding, rate_file, scan_python_tree
from .templates import Template, build_templates
from .validation import validate


@dataclass(slots=True)
class AnalysisResult:
    filename: str
    scan: ScanResult
    issues: list[Issue] = field(default_factory=list)
    templates: list[Template] = field(default_factory=list)
    transformed_ast: ast.Module | None = None
    security_findings: list[Finding] = field(default_factory=list)

    @property
    def feasible(self) -> bool:
        """An empty template list means the file isn't suitable for parallel execution."""
        return bool(self.templates)

    @property
    def transformed_source(self) -> str | None:
        return ast.unparse(self.transformed_ast) if self.transformed_ast else None


def parse_and_scan(source: str | bytes, filename: str) -> tuple[ast.Module, AstScanner]:
    tree = ast.parse(source, filename)
    scanner = AstScanner(filename)
    scanner.scan(tree)
    return tree, scanner


def _security_issues(findings: list[Finding]) -> list[Issue]:
    levels = {"critical": Severity.ERROR, "high": Severity.WARNING, "medium": Severity.WARNING}
    return [
        Issue(levels[f.severity], f"security:{f.rule}", f"[{f.severity}, {f.context}] {f.message}. {f.detail}".strip(), f.line)
        for f in findings if f.severity in levels
    ]


def analyze_source(source: str | bytes, filename: str = "<input>", security: bool = True) -> AnalysisResult:
    """Analyze source without ever executing it. Pass bytes to honour encoding cookies.

    A critical security finding blocks templates, so the Master can't ship that
    code to the cluster.
    """
    empty = ScanResult(filename=filename)
    try:
        tree, scanner = parse_and_scan(source, filename)
        report = validate(tree, scanner.result, source)
    except SyntaxError as error:
        issue = Issue(Severity.ERROR, "syntax-error", f"Can't parse file: {error.msg}", error.lineno)
        return AnalysisResult(filename, empty, [issue])
    except ValueError as error:  # e.g. NUL bytes in the source.
        return AnalysisResult(filename, empty, [Issue(Severity.ERROR, "invalid-source", str(error))])
    except (RecursionError, MemoryError):
        issue = Issue(Severity.ERROR, "too-complex", "Code is nested too deeply to analyse.")
        return AnalysisResult(filename, empty, [issue])

    result = AnalysisResult(filename, scanner.result, report.issues)
    if security:
        raw = source.encode("utf-8", "surrogatepass") if isinstance(source, str) else source
        try:
            result.security_findings = rate_file(filename, scan_python_tree(tree, raw))
        except (RecursionError, MemoryError):
            result.issues.append(Issue(Severity.ERROR, "too-complex", "Code is nested too deeply to check for security."))
        result.issues.extend(_security_issues(result.security_findings))
    if any(i.severity is Severity.ERROR for i in result.issues) or not scanner.result.threads:
        return result
    result.templates, thread_templates = build_templates(scanner.result, report.targets)
    result.transformed_ast = transform(tree, scanner.rewrite_plan, thread_templates)
    return result
