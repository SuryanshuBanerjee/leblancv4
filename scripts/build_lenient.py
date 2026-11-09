"""Build lenient versions of each study task's tests and validate them in the sandbox.

Lenient = calls to the tests' `assert_raises`-style helpers accept any exception (leblanc/sandbox.py:lenient_test).
A lenient security test is used only if it still fails the task's insecure reference (`sp_valid`).
Writes data/tasks_lenient.json. Deterministic; uses only the dataset's reference solutions, never model output.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leblanc import sandbox  # noqa: E402
from leblanc.config import DATA_DIR  # noqa: E402


def main():
    tasks = json.load(open(os.path.join(DATA_DIR, "tasks.json"), encoding="utf-8"))
    out, jobs = {}, []
    for t in tasks:
        fp, a = sandbox.lenient_test(t["test_fp"])
        sp, b = sandbox.lenient_test(t["test_sp"])
        out[t["id"]] = {"test_fp_lenient": fp, "test_sp_lenient": sp, "rewrites": a + b}
        jobs += [{"id": t["id"] + "|fp", "code": t["secure_reference"], "test": fp, "entry": t["entry_point"]},
                 {"id": t["id"] + "|sp", "code": t["secure_reference"], "test": sp, "entry": t["entry_point"]},
                 {"id": t["id"] + "|isp", "code": t["insecure_reference"], "test": sp, "entry": t["entry_point"]}]
    res = sandbox.run_jobs(jobs)
    for t in tasks:
        o = out[t["id"]]
        o["secure_ref_passes"] = res[t["id"] + "|fp"]["raw_status"] == "pass" and res[t["id"] + "|sp"]["raw_status"] == "pass"
        o["sp_valid"] = o["secure_ref_passes"] and res[t["id"] + "|isp"]["raw_status"] != "pass"
    with open(os.path.join(DATA_DIR, "tasks_lenient.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print("tasks", len(out), "| secure refs pass lenient:", sum(o["secure_ref_passes"] for o in out.values()),
          "| lenient security test valid:", sum(o["sp_valid"] for o in out.values()))
    print("not valid:", [k for k, o in out.items() if not o["sp_valid"]])


if __name__ == "__main__":
    main()
