"""Seeded-defect benchmark.

Generates N synthetic "PRs": each PR is a Python file assembled from a pool of
clean snippets, with defects seeded at known lines (the labels). The pipeline
runs on every PR; we score (file, rule) matches to compute precision / recall
/ F1. A naive keyword-grep baseline is scored on the same corpus so the
improvement claim on the resume is reproducible with one command:

    python benchmark/run_benchmark.py --n 500 --seed 42
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from reviewagent import review  # noqa: E402

CLEAN = [
    "def add(a, b):\n    return a + b\n",
    "def greet(name):\n    return f'hello {name}'\n",
    "import os\nTOKEN = os.environ.get('TOKEN')\n",
    "def fetch(cur, uid):\n    cur.execute('SELECT * FROM u WHERE id=%s', (uid,))\n    return cur.fetchone()\n",
    "import yaml\ndef parse(doc):\n    return yaml.load(doc, Loader=yaml.SafeLoader)\n",
    "import subprocess\ndef ls():\n    return subprocess.run(['ls', '-la'])\n",
    "def evaluate_model(metrics):\n    return metrics['f1']\n",  # tricky name for grep baseline
    "PASSWORD_FIELD = ''\n",
]

DEFECTS = [
    ("SEC001", "def calc{i}(expr):\n    return eval(expr)\n"),
    ("SEC002", "import subprocess\ndef sh{i}(cmd):\n    subprocess.run(cmd, shell=True)\n"),
    ("SEC003", "import pickle\ndef sess{i}(b):\n    return pickle.loads(b)\n"),
    ("SEC004", "import yaml\ndef cfg{i}(doc):\n    return yaml.load(doc)\n"),
    ("SEC005", "def q{i}(cur, uid):\n    cur.execute(f'SELECT * FROM u WHERE id={{uid}}')\n"),
    ("SEC006", "API_KEY{i} = 'sk-prod-88ab34cd9912'\n"),
    ("CPX001", "def big{i}(x, y):\n" + "\n".join(
        f"    if x == {j}: y += {j}" for j in range(12)) + "\n    return y\n"),
]


def make_pr(rng: random.Random, idx: int):
    parts, labels = [], set()
    for snippet in rng.sample(CLEAN, k=rng.randint(2, 4)):
        parts.append(snippet)
    for rule, tmpl in rng.sample(DEFECTS, k=rng.randint(0, 3)):
        parts.append(tmpl.format(i=idx))
        labels.add(rule)
    rng.shuffle(parts)
    return "\n".join(parts), labels


def grep_baseline(source: str) -> set[str]:
    """Naive keyword baseline — what a regex bot / prompt-only LLM check approximates."""
    hits = set()
    if re.search(r"\beval\b", source): hits.add("SEC001")
    if "shell" in source: hits.add("SEC002")
    if "pickle" in source: hits.add("SEC003")
    if "yaml.load" in source: hits.add("SEC004")
    if "execute" in source and ("f'" in source or 'f"' in source): hits.add("SEC005")
    if re.search(r"(key|password|secret|token)", source, re.I): hits.add("SEC006")
    if source.count("if ") > 8: hits.add("CPX001")
    return hits


def score(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return round(p, 3), round(r, 3), round(f1, 3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    agent_tp = agent_fp = agent_fn = 0
    base_tp = base_fp = base_fn = 0

    for i in range(args.n):
        source, labels = make_pr(rng, i)

        out = review([{"path": f"pr_{i}.py", "source": source}])
        pred = {f["rule"] for f in out["findings"] if f["rule"] in dict(DEFECTS)}
        agent_tp += len(pred & labels)
        agent_fp += len(pred - labels)
        agent_fn += len(labels - pred)

        bpred = grep_baseline(source)
        base_tp += len(bpred & labels)
        base_fp += len(bpred - labels)
        base_fn += len(labels - bpred)

    ap_, ar, af1 = score(agent_tp, agent_fp, agent_fn)
    bp, br, bf1 = score(base_tp, base_fp, base_fn)
    result = {
        "prs": args.n, "seed": args.seed,
        "agent":    {"precision": ap_, "recall": ar, "f1": af1},
        "baseline": {"precision": bp, "recall": br, "f1": bf1},
    }
    print(json.dumps(result, indent=2))
    Path(__file__).parent.joinpath("results.json").write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
