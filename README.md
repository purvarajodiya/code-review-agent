# Autonomous Code Review Agent

Multi-agent AST analysis pipeline. A **LangGraph planner** parses changed Python files with **tree-sitter**, dispatches specialist sub-agents (security, complexity, API-contract) via conditional edges, then runs every finding through a **deterministic verifier** — a finding is only reported if its byte-range still matches real source code, which makes hallucinated findings structurally impossible.

```
             ┌─> security ────┐
 planner ────┼─> complexity ──┼─> verify ─> (optional) Claude summary
   (AST)     └─> api_contract ┘   (byte-range proof)
```

## Why not just prompt an LLM with the diff?

Prompt-only review hallucinates line numbers and issues. Here the **findings are produced by typed AST analyzers** (tree-sitter nodes in, `Finding` dataclasses out); the LLM is only allowed to *narrate* verified findings, never create them. Every agent step is appended to a trace log, so each decision is replayable (`--trace`).

## Live demo & web API

```bash
pip install ".[web]"
uvicorn app.main:app --reload      # then open http://localhost:8000
```

Paste Python into the editor, press "Review code", and click any finding to jump to its anchored line. The API is one endpoint: `POST /api/review` with `{"code": "...", "old_code": "..."}`. Ships with a Dockerfile (`docker build -t reviewagent . && docker run -p 7860:7860 reviewagent`) — deploys as-is to Hugging Face Spaces or Render. Requests are size-capped (100KB) and rate-limited (30/min per client); code is analyzed in memory and never stored.

## Quickstart

```bash
pip install .
reviewagent examples/vulnerable.py --trace          # single file
reviewagent new.py --old old.py                     # + API-contract diff checks
reviewagent src/ --json                             # whole directory, CI mode
ANTHROPIC_API_KEY=... reviewagent src/ --llm        # + Claude-written PR summary
pytest tests/ -q                                    # 19 tests
```

Exit code is non-zero when a high-severity finding is verified, so the GitHub Actions workflow (`.github/workflows/review.yml`) fails the check and posts findings as a PR comment.

## What it catches

| Agent | Rules |
|---|---|
| security | `eval`/`exec`, `subprocess shell=True`, pickle deserialization, unsafe `yaml.load`, SQL built by f-string/concat, hardcoded credentials |
| complexity | cyclomatic complexity > 10, nesting > 4, functions > 80 lines |
| api_contract | removed public functions, dropped params, reordered params, new required params (old vs. new file versions) |

## Benchmark (reproducible)

`benchmark/run_benchmark.py` seeds known defects into synthetic PRs and scores the pipeline against a naive keyword-grep baseline on the same corpus:

```bash
python benchmark/run_benchmark.py --n 5000 --seed 42
```

Latest run (5,000 simulated PRs, seed 42): **agent precision 1.00 / F1 1.00** vs **keyword baseline precision 0.63 / F1 0.77**. The gap comes from false positives the baseline can't avoid without an AST (e.g. `yaml.load(..., SafeLoader)`, parameterized SQL, variables that merely *mention* "token"). Numbers are deterministic given the seed — run it yourself.

> Honest caveat: the corpus is synthetic and rule-aligned, so treat this as a demonstration of the verification methodology, not a claim about arbitrary real-world code.

## Layout

```
src/reviewagent/
  parsing.py            tree-sitter wrapper, Finding dataclass
  graph.py              LangGraph state graph, planner, verifier, tracing
  analyzers/            security.py · complexity.py · api_contract.py
  cli.py                CLI + optional Claude summarizer node
tests/                  19 unit + end-to-end tests
benchmark/              seeded-defect harness (precision/recall/F1)
.github/workflows/      PR review + test CI
```
