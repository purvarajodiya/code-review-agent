"""API-contract sub-agent: diffs public signatures between old and new file versions."""
from __future__ import annotations

from ..parsing import Finding, ParsedFile

AGENT = "api_contract"


def _public_signatures(pf: ParsedFile) -> dict[str, list[str]]:
    sigs = {}
    for fn in pf.functions():
        name = pf.function_name(fn)
        if not name.startswith("_"):
            sigs[name] = pf.function_params(fn)
    return sigs


def _fn_node(pf: ParsedFile, name: str):
    for fn in pf.functions():
        if pf.function_name(fn) == name:
            return fn
    return pf.root


def analyze(old: ParsedFile | None, new: ParsedFile) -> list[Finding]:
    if old is None:
        return []
    findings: list[Finding] = []
    old_sigs, new_sigs = _public_signatures(old), _public_signatures(new)

    for name in old_sigs:
        if name not in new_sigs:
            findings.append(Finding.from_node(
                new, new.root, rule="API001", severity="high", agent=AGENT,
                message=f"Public function `{name}` was removed — breaking change for callers.",
                removed=name,
            ))
            continue

        old_p, new_p = old_sigs[name], new_sigs[name]
        node = _fn_node(new, name)
        removed = [p for p in old_p if p not in new_p]
        added_required = [
            p for p in new_p
            if p not in old_p and not p.startswith("*")
        ]
        if removed:
            findings.append(Finding.from_node(
                new, node, rule="API002", severity="high", agent=AGENT,
                message=f"`{name}` dropped parameter(s) {removed} — existing call sites will break.",
            ))
        elif old_p and new_p[: len(old_p)] != old_p:
            findings.append(Finding.from_node(
                new, node, rule="API003", severity="medium", agent=AGENT,
                message=f"`{name}` reordered parameters {old_p} -> {new_p} — positional callers will break silently.",
            ))
        if added_required:
            # Heuristic: flag only if the new params lack defaults in source
            src = new.text(node)
            for p in added_required:
                if f"{p}=" not in src.split(")")[0]:
                    findings.append(Finding.from_node(
                        new, node, rule="API004", severity="medium", agent=AGENT,
                        message=f"`{name}` added required parameter `{p}` without a default.",
                    ))
    return findings
