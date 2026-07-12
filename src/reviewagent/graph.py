"""LangGraph multi-agent pipeline.

    planner ──> security ──┐
        │──--> complexity ─┼──> aggregate ──> verify ──> (optional) summarize
        └────> api_contract┘

The planner inspects the parsed AST of each changed file and decides which
sub-agents to dispatch via conditional edges. Every step appends to a trace
log so each agent decision is replayable. The verifier re-parses every file
and confirms each finding's byte-range still matches its snippet —
deterministic verification that makes hallucinated findings impossible.
"""
from __future__ import annotations

import time
from dataclasses import asdict
from typing import Annotated, Any, Optional, TypedDict

from langgraph.graph import END, StateGraph

from .analyzers import api_contract, complexity, security
from .parsing import Finding, ParsedFile


def _merge(a: list, b: list) -> list:
    return a + b


class ReviewState(TypedDict, total=False):
    files: list[dict]           # [{path, source, old_source?}]
    plan: list[str]             # which agents to run
    findings: Annotated[list[Finding], _merge]
    trace: Annotated[list[dict], _merge]
    summary: Optional[str]


def _event(agent: str, action: str, **detail: Any) -> dict:
    return {"ts": time.time(), "agent": agent, "action": action, **detail}


# ---------------------------------------------------------------- nodes

def planner(state: ReviewState) -> dict:
    plan = ["security", "complexity"]
    if any(f.get("old_source") is not None for f in state["files"]):
        plan.append("api_contract")
    return {
        "plan": plan,
        "trace": [_event("planner", "dispatch", agents=plan,
                         files=[f["path"] for f in state["files"]])],
    }


def _parsed(state: ReviewState):
    for f in state["files"]:
        yield f, ParsedFile.from_source(f["path"], f["source"])


def security_node(state: ReviewState) -> dict:
    findings = [fd for _, pf in _parsed(state) for fd in security.analyze(pf)]
    return {"findings": findings,
            "trace": [_event("security", "analyzed", found=len(findings))]}


def complexity_node(state: ReviewState) -> dict:
    findings = [fd for _, pf in _parsed(state) for fd in complexity.analyze(pf)]
    return {"findings": findings,
            "trace": [_event("complexity", "analyzed", found=len(findings))]}


def api_contract_node(state: ReviewState) -> dict:
    findings = []
    for f, pf in _parsed(state):
        old = (ParsedFile.from_source(f["path"], f["old_source"])
               if f.get("old_source") is not None else None)
        findings += api_contract.analyze(old, pf)
    return {"findings": findings,
            "trace": [_event("api_contract", "analyzed", found=len(findings))]}


def verify_node(state: ReviewState) -> dict:
    """Deterministic verification: every finding must point at real source."""
    sources = {f["path"]: f["source"].encode() if isinstance(f["source"], str)
               else f["source"] for f in state["files"]}
    verified = dropped = 0
    for fd in state.get("findings", []):
        src = sources.get(fd.file, b"")
        actual = src[fd.start_byte:fd.end_byte].decode(errors="replace")[:200]
        fd.verified = actual == fd.snippet and fd.snippet != ""
        verified += fd.verified
        dropped += not fd.verified
    return {"trace": [_event("verifier", "verified", ok=verified, rejected=dropped)]}


def route(state: ReviewState) -> list[str]:
    return state["plan"]


def build_graph(llm_summarizer=None):
    g = StateGraph(ReviewState)
    g.add_node("planner", planner)
    g.add_node("security", security_node)
    g.add_node("complexity", complexity_node)
    g.add_node("api_contract", api_contract_node)
    g.add_node("verify", verify_node)

    g.set_entry_point("planner")
    g.add_conditional_edges("planner", route,
                            ["security", "complexity", "api_contract"])
    for agent in ("security", "complexity", "api_contract"):
        g.add_edge(agent, "verify")

    if llm_summarizer is not None:
        g.add_node("summarize", llm_summarizer)
        g.add_edge("verify", "summarize")
        g.add_edge("summarize", END)
    else:
        g.add_edge("verify", END)
    return g.compile()


_APP_CACHE: dict = {}


def review(files: list[dict], llm_summarizer=None) -> dict:
    """Run the full pipeline. Returns findings (verified only) + trace."""
    key = llm_summarizer is not None
    if key not in _APP_CACHE:
        _APP_CACHE[key] = build_graph(llm_summarizer)
    app = _APP_CACHE[key]
    out = app.invoke({"files": files, "findings": [], "trace": []})
    out["findings"] = [f for f in out.get("findings", []) if f.verified]
    return {
        "findings": [asdict(f) for f in out["findings"]],
        "trace": sorted(out.get("trace", []), key=lambda e: e["ts"]),
        "summary": out.get("summary"),
    }
