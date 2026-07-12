import json
from pathlib import Path

import pytest

from reviewagent import review
from reviewagent.analyzers import api_contract, complexity, security
from reviewagent.parsing import ParsedFile


def pf(src, path="t.py"):
    return ParsedFile.from_source(path, src)


# ---------------- security agent ----------------

def rules(findings):
    return {f.rule for f in findings}

def test_detects_eval():
    assert "SEC001" in rules(security.analyze(pf("x = eval(user_input)")))

def test_detects_shell_true():
    assert "SEC002" in rules(security.analyze(pf(
        "import subprocess\nsubprocess.run(cmd, shell=True)")))

def test_detects_pickle():
    assert "SEC003" in rules(security.analyze(pf("import pickle\npickle.loads(b)")))

def test_detects_unsafe_yaml():
    assert "SEC004" in rules(security.analyze(pf("import yaml\nyaml.load(doc)")))

def test_safe_yaml_ok():
    assert "SEC004" not in rules(security.analyze(pf(
        "import yaml\nyaml.load(doc, Loader=yaml.SafeLoader)")))

def test_detects_sql_fstring():
    assert "SEC005" in rules(security.analyze(pf(
        'cur.execute(f"SELECT * FROM t WHERE id={i}")')))

def test_parameterized_sql_ok():
    assert "SEC005" not in rules(security.analyze(pf(
        'cur.execute("SELECT * FROM t WHERE id=%s", (i,))')))

def test_detects_hardcoded_secret():
    assert "SEC006" in rules(security.analyze(pf('API_KEY = "sk-live-abc123xy"')))

def test_env_secret_ok():
    assert "SEC006" not in rules(security.analyze(pf(
        'import os\nAPI_KEY = os.environ["API_KEY"]')))


# ---------------- complexity agent ----------------

def test_flags_high_complexity():
    branches = "\n".join(f"    if x == {i}: y += {i}" for i in range(12))
    src = f"def f(x, y):\n{branches}\n    return y"
    assert "CPX001" in rules(complexity.analyze(pf(src)))

def test_simple_function_ok():
    assert complexity.analyze(pf("def f(x):\n    return x + 1")) == []


# ---------------- api-contract agent ----------------

def test_removed_public_function():
    old, new = pf("def create(a): pass"), pf("def _create(a): pass")
    assert "API001" in rules(api_contract.analyze(old, new))

def test_dropped_parameter():
    old, new = pf("def send(to, cc): pass"), pf("def send(to): pass")
    assert "API002" in rules(api_contract.analyze(old, new))

def test_reordered_parameters():
    old, new = pf("def send(to, cc): pass"), pf("def send(cc, to): pass")
    assert "API003" in rules(api_contract.analyze(old, new))

def test_unchanged_signature_ok():
    old, new = pf("def send(to, cc): pass"), pf("def send(to, cc):\n    return 1")
    assert api_contract.analyze(old, new) == []


# ---------------- full graph ----------------

def test_graph_end_to_end():
    src = Path(__file__).parent.parent / "examples" / "vulnerable.py"
    out = review([{"path": str(src), "source": src.read_text()}])
    assert all(f["verified"] for f in out["findings"])
    assert {"SEC001", "SEC002", "SEC003", "SEC005", "SEC006", "CPX001"} <= {
        f["rule"] for f in out["findings"]}
    agents = {e["agent"] for e in out["trace"]}
    assert {"planner", "security", "complexity", "verifier"} <= agents

def test_planner_skips_api_agent_without_old_source():
    out = review([{"path": "a.py", "source": "def f(): pass"}])
    dispatched = next(e for e in out["trace"] if e["agent"] == "planner")["agents"]
    assert "api_contract" not in dispatched

def test_verifier_rejects_tampered_finding():
    """A finding whose byte-range doesn't match real source must be dropped."""
    from reviewagent.graph import verify_node
    from reviewagent.parsing import Finding
    fake = Finding(rule="SEC001", severity="high", message="x", file="a.py",
                   line=1, end_line=1, start_byte=0, end_byte=4,
                   snippet="NOT_IN_SOURCE", agent="security")
    state = {"files": [{"path": "a.py", "source": "pass"}], "findings": [fake]}
    verify_node(state)
    assert fake.verified is False

def test_findings_are_json_serializable():
    out = review([{"path": "a.py", "source": "x = eval(y)"}])
    json.dumps(out, default=str)
