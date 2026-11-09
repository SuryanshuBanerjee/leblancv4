"""Offline checks. No model calls, no cost. `python -m leblanc selfcheck` exits non-zero on any failure."""
import hashlib
import json
import os
import tempfile

from . import enrich, judge, sandbox
from .config import DATA_DIR, MODELS, PRICES, STUDY, get_key, model_ids


def run(verbose=True, out=print):
    results = []

    def check(name, fn):
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        results.append(ok)
        out(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))

    def c_config():
        miss = [m for m in model_ids() if m not in PRICES["usd_per_million_tokens"]]
        return (not miss and len(model_ids()) >= 1 and STUDY["reps"] >= 1,
                f"{len(model_ids())} models, prices {'complete' if not miss else 'missing for ' + ', '.join(miss)}")

    def c_key():
        return bool(get_key(MODELS["key_env"])), f"{MODELS['key_env']} {'present' if get_key(MODELS['key_env']) else 'missing'}"

    def c_tasks():
        p = os.path.join(DATA_DIR, "tasks.json")
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        want = open(os.path.join(DATA_DIR, "tasks.sha256")).read().split()[0]
        n = len(json.load(open(p, encoding="utf-8")))
        return h == want and n == 56, f"{n} tasks, sha256 {'matches' if h == want else 'DIFFERS from'} data/tasks.sha256"

    def c_kb():
        from .dataset import load_tasks
        tasks = load_tasks()
        missing = sorted({t["cwe"] for t in tasks if not enrich.warning_line(t["cwe"])})
        longest = max(enrich.est_tokens(enrich.warning_line(t["cwe"])) for t in tasks if enrich.warning_line(t["cwe"]))
        return not missing and longest <= 40, f"every task CWE has a warning; longest targeted line about {longest} tokens"

    def c_cap():
        from .dataset import load_tasks
        held = json.load(open(os.path.join(DATA_DIR, "heldout.json"), encoding="utf-8"))
        worst = max(enrich.analyze(p)["tokens"] for p in [t["prompt"] for t in load_tasks()] + [h["prompt"] for h in held])
        return worst <= STUDY["warning_max_tokens"], f"Engine A output at most {worst} tokens (cap {STUDY['warning_max_tokens']})"

    def c_extract():
        cases = [("```python\nx = 1\n```", "stop", "ok"), ("no code here", "stop", "no_code"),
                 ("```python\ndef f(:\n```", "stop", "syntax_error"), ("```python\ndef f(", "length", "truncated")]
        bad = [c for c in cases if judge.extract(c[0], c[1])[0] != c[2]]
        return not bad, "extraction outcome classes" + (f" wrong for {bad}" if bad else "")

    def c_strip():
        code = "from flask import Flask\napp = Flask(__name__)\ndef f():\n    return 1\nif __name__ == '__main__':\n    app.run(debug=True)\n"
        return judge.scaffolding_lines(code) == {5, 6}, "scaffolding lines detected"

    def c_judge():
        ok, info = judge.selfcheck()
        return ok, f"Bandit and Semgrep both detect a known injection and pass clean code ({info['bad_tools']})"

    def c_dedupe():
        fs = judge.dedupe([{"tool": "bandit", "rule": "B201", "cwes": ["CWE-94"], "severity": "HIGH", "line": 3},
                           {"tool": "semgrep", "rule": "debug-enabled", "cwes": ["CWE-489"], "severity": "WARNING", "line": 3}])
        return len(fs) == 1 and fs[0]["tool"] == "bandit+semgrep", "cross-tool duplicates merge"

    def c_sandbox():
        ok, res = sandbox.selfcheck()
        return ok, "jail: no network, no Windows drives, no secrets, hangs killed" if ok else json.dumps(res)[:300]

    def c_refs():
        from .dataset import load_tasks
        tasks = load_tasks()
        jobs = []
        for t in tasks:
            jobs += [{"id": t["id"] + "|fp", "code": t["secure_reference"], "test": t["test_fp"], "entry": t["entry_point"]},
                     {"id": t["id"] + "|sp", "code": t["secure_reference"], "test": t["test_sp"], "entry": t["entry_point"]},
                     {"id": t["id"] + "|isp", "code": t["insecure_reference"], "test": t["test_sp"], "entry": t["entry_point"]}]
        res = sandbox.run_jobs(jobs)
        bad = [t["id"] for t in tasks if res[t["id"] + "|fp"]["raw_status"] != "pass" or res[t["id"] + "|sp"]["raw_status"] != "pass"]
        undetected = [t["id"] for t in tasks if res[t["id"] + "|isp"]["raw_status"] == "pass"]
        return not bad and not undetected, (f"all {len(tasks)} secure references pass both tests; all {len(tasks)} insecure references fail the security test"
                                            if not bad and not undetected else f"reference failures {bad}, undetected {undetected}")

    def c_nomock():
        from .dataset import load_tasks
        bad = [t["id"] for t in load_tasks() if any("__globals__" in t[f] for f in ("test_fp", "test_sp", "test_full"))]
        return not bad, "no study task's tests inject mocks into the solution" if not bad else f"coupled: {bad}"

    def c_lenient():
        from .dataset import load_tasks
        tasks = load_tasks()
        miss = [t["id"] for t in tasks if "test_fp_lenient" not in t]
        jobs = []
        for t in tasks:
            if "test_fp_lenient" in t:
                jobs += [{"id": t["id"] + "|fp", "code": t["secure_reference"], "test": t["test_fp_lenient"], "entry": t["entry_point"]},
                         {"id": t["id"] + "|sp", "code": t["secure_reference"], "test": t["test_sp_lenient"], "entry": t["entry_point"]},
                         {"id": t["id"] + "|isp", "code": t["insecure_reference"], "test": t["test_sp_lenient"], "entry": t["entry_point"]}]
        res = sandbox.run_jobs(jobs)
        bad = [t["id"] for t in tasks if t["id"] + "|fp" in res and (res[t["id"] + "|fp"]["raw_status"] != "pass" or res[t["id"] + "|sp"]["raw_status"] != "pass")]
        wrong = [t["id"] for t in tasks if t["id"] + "|isp" in res and (res[t["id"] + "|isp"]["raw_status"] != "pass") != bool(t.get("sp_valid"))]
        n_valid = sum(bool(t.get("sp_valid")) for t in tasks)
        return not miss and not bad and not wrong, (f"lenient tests: all secure references pass; {n_valid} tasks where the lenient security test catches the insecure reference"
                                                   if not (miss or bad or wrong) else f"missing {miss}, failing {bad}, sp_valid mismatch {wrong}")

    def c_db():
        from . import store
        with tempfile.TemporaryDirectory() as d:
            con = store.connect(os.path.join(d, "t.db"))
            con.executescript(store.SCHEMA)
            n = len(con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall())
            con.close()
        return n >= 9, f"schema creates {n} tables on an empty database"

    def c_stats():
        from . import stats
        p = stats.binom_two_sided(0, 10)
        q = stats.bh([0.01, 0.04, 0.03])
        k = stats.cohen_kappa([1, 0, 1, 0], [1, 0, 1, 0])[0]
        return abs(p - 0.001953125) < 1e-9 and abs(q[0] - 0.03) < 1e-9 and k == 1.0, "McNemar, BH and kappa on known values"

    for name, fn in [("configuration", c_config), ("API key", c_key), ("task list frozen", c_tasks),
                     ("knowledge base", c_kb), ("Engine A token cap", c_cap), ("code extraction", c_extract),
                     ("scaffolding detection", c_strip), ("finding de-duplication", c_dedupe), ("statistics", c_stats),
                     ("database schema", c_db), ("static analysers", c_judge), ("sandbox isolation", c_sandbox),
                     ("dataset references in sandbox", c_refs), ("no mock-injecting tests", c_nomock), ("lenient tests", c_lenient)]:
        check(name, fn)
    ok = all(results)
    out(f"\n{sum(results)} of {len(results)} checks passed." + ("" if ok else " Fix the failures before running."))
    return ok
