"""Validate every CodeSecEval task inside the sandbox before selection.

For each task, run:
  Secure Code   vs Test, Test-FP, Test-SP   (all should pass)
  Insecure Code vs Test-FP                  (should usually pass: the insecure code works)
  Insecure Code vs Test-SP                  (should fail: the security test catches the weakness)
Writes data/codeseceval/validation.json. Deterministic apart from timing.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leblanc import sandbox  # noqa: E402
from leblanc.config import DATA_DIR  # noqa: E402

SRC = os.path.join(DATA_DIR, "codeseceval")


def load_all():
    rows = []
    for subset in ("SecEvalBase", "SecEvalPlus"):
        with open(os.path.join(SRC, subset + ".jsonl"), encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    r["_subset"] = subset
                    rows.append(r)
    return rows


def main():
    rows = load_all()
    plan = [("secure", "Secure Code", "Test"), ("secure", "Secure Code", "Test-FP"),
            ("secure", "Secure Code", "Test-SP"), ("insecure", "Insecure Code", "Test-FP"),
            ("insecure", "Insecure Code", "Test-SP")]
    jobs = []
    for i, r in enumerate(rows):
        for who, code_field, test_field in plan:
            jobs.append({"id": f"{i}|{who}|{test_field}", "code": r[code_field], "test": r[test_field],
                         "entry": r["Entry_Point"]})
    res = sandbox.run_jobs(jobs)
    out = {}
    for i, r in enumerate(rows):
        key = f"{r['_subset']}|{r['ID']}"
        out[key] = {f"{who}|{tf}": res[f"{i}|{who}|{tf}"] for who, _, tf in plan}
    with open(os.path.join(SRC, "validation.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    from collections import Counter
    for combo in [f"{w}|{t}" for w, _, t in plan]:
        print(combo.ljust(22), dict(Counter(v[combo]["raw_status"] for v in out.values())))
    good = [k for k, v in out.items() if all(v[f"secure|{t}"]["raw_status"] == "pass" for t in ("Test", "Test-FP", "Test-SP"))]
    sp_discriminates = [k for k in good if out[k]["insecure|Test-SP"]["raw_status"] != "pass"]
    print("secure passes all three:", len(good), "of", len(out))
    print("...and Test-SP fails the insecure code:", len(sp_discriminates))


if __name__ == "__main__":
    main()
