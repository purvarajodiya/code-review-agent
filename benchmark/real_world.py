"""Scan real open-source repositories with the review agent.

Clones repos (shallow), runs the multi-agent pipeline over every Python file,
and produces an aggregated report: findings per rule, per repo, with concrete
file:line examples. This complements the seeded benchmark with real-world data.

    python benchmark/real_world.py https://github.com/pallets/flask
    python benchmark/real_world.py --skip-tests <repo_url> [<repo_url> ...]

Notes:
- Findings are *flags for human review*, not confirmed vulnerabilities. Many
  hits in mature projects are intentional (test fixtures, CLI tools that
  legitimately shell out). Triage before citing anything publicly.
- Test files often intentionally contain "bad" patterns; findings are tagged
  with in_tests so you can separate them (--skip-tests excludes them).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from reviewagent import review  # noqa: E402

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "build", "dist",
             "__pycache__", ".tox", "site-packages", "vendor", "vendored"}
MAX_FILE_BYTES = 200_000
CHUNK = 25


def collect_py_files(root: Path, skip_tests: bool) -> list[Path]:
    out = []
    for p in root.rglob("*.py"):
        parts = set(p.parts)
        if parts & SKIP_DIRS:
            continue
        if skip_tests and any("test" in part.lower() for part in p.relative_to(root).parts):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(p)
    return sorted(out)


def scan_repo(url: str, skip_tests: bool) -> dict:
    name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    with tempfile.TemporaryDirectory() as td:
        print(f"\n=== {name} ===\ncloning {url} ...", flush=True)
        subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, td],
                       check=True)
        root = Path(td)
        paths = collect_py_files(root, skip_tests)
        print(f"scanning {len(paths)} Python files ...", flush=True)

        findings = []
        for i in range(0, len(paths), CHUNK):
            batch = []
            for p in paths[i:i + CHUNK]:
                try:
                    batch.append({"path": str(p.relative_to(root)),
                                  "source": p.read_text(encoding="utf-8")})
                except (UnicodeDecodeError, OSError):
                    continue
            if batch:
                findings += review(batch)["findings"]

        for f in findings:
            f["repo"] = name
            f["in_tests"] = "test" in f["file"].lower()
        return {"repo": name, "url": url, "files_scanned": len(paths),
                "findings": findings}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repos", nargs="*", default=[
        "https://github.com/pallets/flask",
        "https://github.com/psf/requests",
    ], help="Git URLs to scan (default: flask, requests)")
    ap.add_argument("--skip-tests", action="store_true",
                    help="Exclude test files (they often contain intentional bad patterns)")
    args = ap.parse_args()

    reports = [scan_repo(url, args.skip_tests) for url in (args.repos or [])]

    print("\n" + "=" * 60)
    for rep in reports:
        by_rule = Counter(f["rule"] for f in rep["findings"])
        non_test = [f for f in rep["findings"] if not f["in_tests"]]
        print(f"\n{rep['repo']}: {rep['files_scanned']} files, "
              f"{len(rep['findings'])} findings ({len(non_test)} outside tests)")
        for rule, n in by_rule.most_common():
            print(f"  {rule}: {n}")
        for f in [x for x in non_test if x['severity'] == 'high'][:5]:
            print(f"    e.g. [{f['severity'].upper()}] {f['file']}:{f['line']} — {f['message']}")

    out_path = Path(__file__).parent / "real_world_results.json"
    out_path.write_text(json.dumps(reports, indent=2, default=str))
    print(f"\nFull report -> {out_path}")


if __name__ == "__main__":
    main()
