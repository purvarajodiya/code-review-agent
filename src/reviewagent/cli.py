"""CLI: `python -m reviewagent <new.py> [--old <old.py>] [--json] [--llm]`"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .graph import review

SEV_ICON = {"high": "[HIGH]", "medium": "[MED] ", "low": "[LOW] "}


def claude_summarizer(state):
    """Optional LLM node: summarizes verified findings for the PR comment.

    Only runs when ANTHROPIC_API_KEY is set. The LLM never *creates*
    findings — it only narrates the deterministic, verified ones.
    """
    import anthropic  # lazy import

    findings = [f for f in state.get("findings", []) if f.verified]
    if not findings:
        return {"summary": "No verified issues found."}
    client = anthropic.Anthropic()
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content":
                   "Write a 3-sentence PR review summary of these verified "
                   "static-analysis findings:\n" +
                   "\n".join(f"- {f.file}:{f.line} {f.rule} {f.message}" for f in findings)}],
    )
    return {"summary": msg.content[0].text}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="reviewagent")
    ap.add_argument("target", help="Python file or directory to review")
    ap.add_argument("--old", help="Previous version of the file (enables API-contract checks)")
    ap.add_argument("--json", action="store_true", help="Machine-readable output")
    ap.add_argument("--llm", action="store_true", help="Add Claude-written summary (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--trace", action="store_true", help="Print per-step agent trace")
    args = ap.parse_args(argv)

    target = Path(args.target)
    paths = sorted(target.rglob("*.py")) if target.is_dir() else [target]
    files = [{"path": str(p), "source": p.read_text()} for p in paths]
    if args.old:
        files[0]["old_source"] = Path(args.old).read_text()

    summarizer = claude_summarizer if (args.llm and os.environ.get("ANTHROPIC_API_KEY")) else None
    result = review(files, llm_summarizer=summarizer)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        for f in result["findings"]:
            print(f"{SEV_ICON[f['severity']]} {f['file']}:{f['line']}  {f['rule']}  {f['message']}")
        print(f"\n{len(result['findings'])} verified finding(s).")
        if result.get("summary"):
            print("\n--- Claude summary ---\n" + result["summary"])
        if args.trace:
            print("\n--- agent trace ---")
            for e in result["trace"]:
                extra = {k: v for k, v in e.items() if k not in ("ts", "agent", "action")}
                print(f"{e['agent']:>12} | {e['action']:<9} | {extra}")

    return 1 if any(f["severity"] == "high" for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
