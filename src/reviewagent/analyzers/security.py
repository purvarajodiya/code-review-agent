"""Security sub-agent: detects dangerous patterns via typed AST inspection."""
from __future__ import annotations

import re

from ..parsing import Finding, ParsedFile

AGENT = "security"

SECRET_NAME = re.compile(r"(password|passwd|secret|api_?key|token|private_key)", re.I)
SECRET_PLACEHOLDER = re.compile(r"^\s*(\"\"|''|\"?<[^>]*>\"?|None|os\.environ)", re.I)


def _call_name(pf: ParsedFile, call_node) -> str:
    fn = call_node.child_by_field_name("function")
    return pf.text(fn) if fn else ""


def analyze(pf: ParsedFile) -> list[Finding]:
    findings: list[Finding] = []
    for node in pf.walk():
        if node.type == "call":
            name = _call_name(pf, node)

            if name in ("eval", "exec"):
                findings.append(Finding.from_node(
                    pf, node, rule="SEC001", severity="high", agent=AGENT,
                    message=f"Use of `{name}()` allows arbitrary code execution.",
                ))

            elif name.startswith("subprocess.") or name in ("Popen", "call", "run", "check_output"):
                args = node.child_by_field_name("arguments")
                if args and "shell=True" in pf.text(args).replace(" ", "").replace("shell =", "shell="):
                    findings.append(Finding.from_node(
                        pf, node, rule="SEC002", severity="high", agent=AGENT,
                        message="subprocess with shell=True enables shell injection.",
                    ))

            elif name == "pickle.loads" or name == "pickle.load":
                findings.append(Finding.from_node(
                    pf, node, rule="SEC003", severity="medium", agent=AGENT,
                    message="Deserializing with pickle on untrusted data allows code execution.",
                ))

            elif name == "yaml.load":
                args_text = pf.text(node.child_by_field_name("arguments") or node)
                if "SafeLoader" not in args_text and "safe" not in args_text:
                    findings.append(Finding.from_node(
                        pf, node, rule="SEC004", severity="medium", agent=AGENT,
                        message="yaml.load without SafeLoader can execute arbitrary Python.",
                    ))

            elif name.endswith(".execute") or name == "execute":
                args = node.child_by_field_name("arguments")
                if args and args.named_children:
                    first = args.named_children[0]
                    if first.type in ("binary_operator", "string") and (
                        first.type == "binary_operator"
                        or any(c.type == "interpolation" for c in pf.walk(first))
                        or "%" in pf.text(first) and ".format" in pf.text(node)
                    ):
                        if first.type == "binary_operator" or any(
                            c.type == "interpolation" for c in pf.walk(first)
                        ):
                            findings.append(Finding.from_node(
                                pf, first, rule="SEC005", severity="high", agent=AGENT,
                                message="SQL built via string concatenation/f-string — use parameterized queries.",
                            ))

        elif node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None and right.type == "string":
                if SECRET_NAME.search(pf.text(left)):
                    value = pf.text(right)
                    if len(value.strip("\"'")) >= 6 and not SECRET_PLACEHOLDER.match(value):
                        findings.append(Finding.from_node(
                            pf, node, rule="SEC006", severity="high", agent=AGENT,
                            message="Hardcoded credential in source — move to environment/secret manager.",
                        ))
    return findings
