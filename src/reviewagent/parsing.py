"""Tree-sitter based AST parsing for Python source files."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

PY_LANGUAGE = Language(tspython.language())


def get_parser() -> Parser:
    try:
        return Parser(PY_LANGUAGE)
    except TypeError:  # older tree-sitter API
        p = Parser()
        p.set_language(PY_LANGUAGE)
        return p


@dataclass
class ParsedFile:
    path: str
    source: bytes
    root: Node

    @classmethod
    def from_source(cls, path: str, source: str | bytes) -> "ParsedFile":
        raw = source.encode() if isinstance(source, str) else source
        tree = get_parser().parse(raw)
        return cls(path=path, source=raw, root=tree.root_node)

    def text(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode(errors="replace")

    def walk(self, node: Optional[Node] = None) -> Iterator[Node]:
        """Depth-first traversal of every node in the tree."""
        stack = [node or self.root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(reversed(n.children))

    def functions(self) -> Iterator[Node]:
        for n in self.walk():
            if n.type == "function_definition":
                yield n

    def function_name(self, fn: Node) -> str:
        name = fn.child_by_field_name("name")
        return self.text(name) if name else "<anonymous>"

    def function_params(self, fn: Node) -> list[str]:
        params = fn.child_by_field_name("parameters")
        out: list[str] = []
        if params:
            for child in params.named_children:
                if child.type in ("identifier",):
                    out.append(self.text(child))
                elif child.type in (
                    "typed_parameter",
                    "default_parameter",
                    "typed_default_parameter",
                ):
                    ident = next(
                        (c for c in child.children if c.type == "identifier"), None
                    )
                    if ident is not None:
                        out.append(self.text(ident))
                elif child.type in ("list_splat_pattern", "dictionary_splat_pattern"):
                    out.append(self.text(child))
        return out


@dataclass
class Finding:
    """A single issue located at a concrete AST node."""

    rule: str
    severity: str  # "high" | "medium" | "low"
    message: str
    file: str
    line: int  # 1-indexed
    end_line: int
    start_byte: int
    end_byte: int
    snippet: str
    agent: str
    verified: bool = False
    meta: dict = field(default_factory=dict)

    @classmethod
    def from_node(
        cls, pf: ParsedFile, node: Node, *, rule: str, severity: str, message: str, agent: str, **meta
    ) -> "Finding":
        return cls(
            rule=rule,
            severity=severity,
            message=message,
            file=pf.path,
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            snippet=pf.text(node)[:200],
            agent=agent,
            meta=meta,
        )
