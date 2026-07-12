"""Complexity sub-agent: cyclomatic complexity, nesting depth, function length."""
from __future__ import annotations

from ..parsing import Finding, ParsedFile

AGENT = "complexity"

BRANCH_NODES = {
    "if_statement", "elif_clause", "for_statement", "while_statement",
    "except_clause", "with_statement", "boolean_operator",
    "conditional_expression", "case_clause",
}
BLOCK_NODES = {"if_statement", "for_statement", "while_statement", "try_statement", "with_statement"}

MAX_COMPLEXITY = 10
MAX_NESTING = 4
MAX_LENGTH = 80


def _cyclomatic(pf: ParsedFile, fn) -> int:
    return 1 + sum(1 for n in pf.walk(fn) if n.type in BRANCH_NODES)


def _max_nesting(node, depth: int = 0) -> int:
    best = depth
    for child in node.children:
        d = depth + (1 if child.type in BLOCK_NODES else 0)
        best = max(best, _max_nesting(child, d))
    return best


def analyze(pf: ParsedFile) -> list[Finding]:
    findings: list[Finding] = []
    for fn in pf.functions():
        name = pf.function_name(fn)

        cc = _cyclomatic(pf, fn)
        if cc > MAX_COMPLEXITY:
            findings.append(Finding.from_node(
                pf, fn, rule="CPX001", severity="medium", agent=AGENT,
                message=f"`{name}` has cyclomatic complexity {cc} (max {MAX_COMPLEXITY}) — split it up.",
                complexity=cc,
            ))

        nesting = _max_nesting(fn)
        if nesting > MAX_NESTING:
            findings.append(Finding.from_node(
                pf, fn, rule="CPX002", severity="low", agent=AGENT,
                message=f"`{name}` nests {nesting} levels deep (max {MAX_NESTING}) — use early returns.",
                nesting=nesting,
            ))

        length = fn.end_point[0] - fn.start_point[0] + 1
        if length > MAX_LENGTH:
            findings.append(Finding.from_node(
                pf, fn, rule="CPX003", severity="low", agent=AGENT,
                message=f"`{name}` is {length} lines long (max {MAX_LENGTH}).",
                length=length,
            ))
    return findings
