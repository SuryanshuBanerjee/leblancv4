"""Fast offline tests (no model calls, no scanners, no sandbox). Run: python -m pytest tests -q"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEBLANC_DB", os.path.join(tempfile.mkdtemp(), "test.db"))

from leblanc import enrich, judge, report, stats  # noqa: E402
from leblanc.config import STUDY  # noqa: E402
from leblanc.dataset import load_tasks  # noqa: E402


def test_extract_classes():
    assert judge.extract("```python\nx = 1\n```", "stop") == ("ok", "x = 1")
    assert judge.extract("text only", "stop")[0] == "no_code"
    assert judge.extract("```python\ndef f(:\n```", "stop")[0] == "syntax_error"
    assert judge.extract("```python\ndef f(", "length")[0] == "truncated"
    assert judge.extract("```py\nprint(1)\n```\n```python\nx=2\n```")[1] == "print(1)"


def test_scaffolding_strip_keeps_line_numbers():
    code = "from flask import Flask\napp = Flask(__name__)\n\ndef f():\n    return 1\n\nif __name__ == '__main__':\n    app.run(debug=True)\n"
    stripped, lines = judge.strip_scaffolding(code)
    assert lines == {7, 8}
    assert len(stripped.splitlines()) == len(code.splitlines())
    assert "app.run" not in stripped and "def f" in stripped


def test_bare_app_run_is_scaffolding_but_other_run_is_not():
    code = "import threading\nfrom flask import Flask\nweb = Flask(__name__)\nt = threading.Thread()\nt.run()\nweb.run(host='0.0.0.0')\n"
    assert judge.scaffolding_lines(code) == {6}


def test_dedupe_cross_tool():
    fs = judge.dedupe([{"tool": "bandit", "rule": "B104", "cwes": ["CWE-605"], "severity": "MEDIUM", "line": 9},
                       {"tool": "semgrep", "rule": "avoid_app_run_with_bad_host", "cwes": ["CWE-668"], "severity": "WARNING", "line": 9},
                       {"tool": "bandit", "rule": "B608", "cwes": ["CWE-89"], "severity": "MEDIUM", "line": 4}])
    assert len(fs) == 2


def test_verdicts_ignore_scaffolding():
    fs = [{"tool": "bandit", "rule": "B201", "cwes": ["CWE-94"], "severity": "HIGH", "line": 8, "on_scaffolding": 1}]
    v = judge.verdicts(fs, "CWE-89")
    assert v["vuln_raw"] == 1 and v["vuln_task"] == 0


def test_target_set_related():
    assert "CWE-78" in judge.target_set("CWE-77")
    assert judge.target_set("CWE-89") == {"CWE-89"}


def test_arms_and_caps():
    t = load_tasks()[0]
    p, extra = enrich.build_prompt("plain", t)
    assert extra == "" and p == t["prompt"]
    p, extra = enrich.build_prompt("generic", t)
    assert extra == STUDY["generic_line"] and p.endswith(extra)
    p, extra = enrich.build_prompt("targeted", t)
    assert t["cwe"] in extra
    for task in load_tasks():
        assert enrich.analyze(task["prompt"])["tokens"] <= STUDY["warning_max_tokens"]
    assert enrich.analyze("print hello world")["warnings"] == []


def test_stats_known_values():
    assert abs(stats.binom_two_sided(0, 10) - 2 / 1024) < 1e-12
    assert stats.binom_two_sided(5, 10) == 1.0
    adj = stats.bh([0.01, 0.04, 0.03, None])
    assert adj[3] is None and abs(adj[0] - 0.03) < 1e-12 and abs(adj[1] - 0.04) < 1e-12
    k, po, n = stats.cohen_kappa(["tp", "fp", "tp", "tp"], ["tp", "fp", "fp", "tp"])
    assert n == 4 and abs(po - 0.75) < 1e-12 and abs(k - 0.5) < 1e-12
    lo, hi = stats.wilson(5, 10)
    assert 0.23 < lo < 0.24 and 0.76 < hi < 0.77


def test_paired_bootstrap_deterministic():
    pairs = {f"T{i}": [(1, 0), (1, 1), (0, 0)] for i in range(20)}
    a, b = stats.paired(pairs), stats.paired(pairs)
    assert a == b and abs(a["effect"] + 1 / 3) < 1e-12 and a["b_only"] == 0 and a["a_only"] == 20


def test_verdict_bands():
    base = {"n": 100, "lo": -0.20, "hi": -0.08, "effect": -0.14}
    assert report.verdict(base, 0.001, baseline=0.40) == "yes"
    assert report.verdict(dict(base, effect=-0.01, lo=-0.03, hi=0.02), 0.9, baseline=0.40) == "no"
    assert report.verdict(dict(base, effect=-0.14), 0.001, baseline=0.05) == "ceiling"
    assert report.verdict(dict(base, n=5), 0.001, baseline=0.4) == "insufficient"
    assert report.verdict(dict(base, effect=-0.08, lo=-0.2, hi=0.04), 0.2, baseline=0.4) == "unclear"


def test_outcome_rules():
    c = {"task_id": "T01", "extract": "no_code", "code": None, "judge_status": "na", "test_status": "na", "vuln_task": None,
         "fp_result": None, "sp_result": None, "fpl_result": None, "spl_result": None}
    assert report.outcome(c, "vuln_task") is None       # security excludes no-code outputs
    assert report.outcome(c, "fp_pass") == 0            # function counts them as failures
    c2 = {"task_id": "T01", "extract": "ok", "code": "x", "judge_status": "done", "test_status": "done", "vuln_task": 0,
          "fp_result": "pass", "sp_result": "harness_error", "fpl_result": "pass", "spl_result": "harness_error"}
    assert report.outcome(c2, "secure_pass") is None and report.outcome(c2, "fp_pass") == 1
    assert report.outcome(c2, "secure_pass_strict") is None and report.outcome(c2, "fp_pass_strict") == 1
    c3 = dict(c2, fpl_result="pass", spl_result="fail", fp_result="fail", sp_result="fail")
    assert report.outcome(c3, "fp_pass") == 1 and report.outcome(c3, "fp_pass_strict") == 0
    invalid = next(t["id"] for t in load_tasks() if not t["sp_valid"])
    assert report.outcome(dict(c3, task_id=invalid), "sp_fail") is None          # lenient security only on valid tasks
    assert report.outcome(dict(c3, task_id=invalid), "sp_fail_strict") == 1


def test_plan_idempotent_and_ordered():
    from leblanc import runner, store
    n1 = runner.plan(reps=2, task_limit=2)
    runner.plan(reps=2, task_limit=2)
    assert store.q1("SELECT COUNT(*) n FROM cells")["n"] == n1 == 2 * 2 * 3 * 5
    first_rep2 = store.q1("SELECT MIN(ord) o FROM cells WHERE rep=2")["o"]
    last_rep1 = store.q1("SELECT MAX(ord) o FROM cells WHERE rep=1")["o"]
    assert last_rep1 < first_rep2
    assert store.q1("SELECT COUNT(*) n FROM cells WHERE kind!='gen' AND base_cell NOT LIKE '%.plain'")["n"] == 0
