"""Select the study's 60 tasks from CodeSecEval by a fixed, seeded rule (docs/PROPOSAL.md section 4.1).

Eligibility: the task's Secure Code passes Test, Test-FP and Test-SP in our sandbox; Test-SP fails the task's
Insecure Code (the security test actually detects the weakness); and no test injects mock objects into the
solution's globals (such tests accept only code that uses the reference implementation's exact objects).
SecEvalPlus: `plus_per_cwe` tasks from each of its CWE types, drawn with the study seed.
SecEvalBase: `base_tasks` distinct CWE types drawn with the study seed (all of them if fewer), one task each.
Writes data/tasks.json and data/exclusions.json. Re-running reproduces the same files byte-for-byte.
"""
import json
import os
import random
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leblanc.config import DATA_DIR, STUDY  # noqa: E402

SRC = os.path.join(DATA_DIR, "codeseceval")


def norm_cwe(task_id):
    return "CWE-%d" % int(re.match(r"CWE-(\d+)", task_id).group(1))


def main():
    val = json.load(open(os.path.join(SRC, "validation.json"), encoding="utf-8"))
    rows = {}
    for subset in ("SecEvalBase", "SecEvalPlus"):
        for line in open(os.path.join(SRC, subset + ".jsonl"), encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                rows[f"{subset}|{r['ID']}"] = dict(r, _subset=subset)

    exclusions, eligible = [], []
    for key, r in sorted(rows.items()):
        v = val[key]
        bad = [f"{f}={v[f]['raw_status']}" for f in ("secure|Test", "secure|Test-FP", "secure|Test-SP")
               if v[f]["raw_status"] != "pass"]
        if bad:
            exclusions.append({"key": key, "reason": "reference solution fails its own tests in our sandbox: "
                               + ", ".join(bad) + " (" + v[bad[0].split("=")[0]]["detail"][:120] + ")"})
        elif v["insecure|Test-SP"]["raw_status"] == "pass":
            exclusions.append({"key": key, "reason": "Test-SP does not detect the task's own insecure code"})
        elif any("__globals__" in r[f] for f in ("Test", "Test-FP", "Test-SP")):
            exclusions.append({"key": key, "reason": "tests inject mock objects into the solution's globals, so they "
                               "only accept code that uses the same objects as the reference implementation"})
        else:
            eligible.append(key)

    rng = random.Random(STUDY["seed"])
    sel = STUDY["selection"]
    chosen = []

    plus = sorted(k for k in eligible if k.startswith("SecEvalPlus|"))
    by_cwe = {}
    for k in plus:
        by_cwe.setdefault(norm_cwe(rows[k]["ID"]), []).append(k)
    for cwe in sorted(by_cwe, key=lambda c: int(c.split("-")[1])):
        chosen += sorted(rng.sample(by_cwe[cwe], min(sel["plus_per_cwe"], len(by_cwe[cwe]))))

    base = sorted(k for k in eligible if k.startswith("SecEvalBase|"))
    by_cwe = {}
    for k in base:
        by_cwe.setdefault(norm_cwe(rows[k]["ID"]), []).append(k)
    cwes = sorted(by_cwe, key=lambda c: int(c.split("-")[1]))
    for cwe in sorted(rng.sample(cwes, min(sel["base_tasks"], len(cwes))), key=lambda c: int(c.split("-")[1])):
        chosen.append(rng.choice(sorted(by_cwe[cwe])))

    tasks = []
    for n, key in enumerate(chosen, 1):
        r = rows[key]
        tasks.append({
            "id": "T%02d" % n,
            "source": "CodeSecEval/" + r["_subset"],
            "source_id": r["ID"],
            "cwe": norm_cwe(r["ID"]),
            "entry_point": r["Entry_Point"],
            "prompt": r["Problem"],
            "test_fp": r["Test-FP"],
            "test_sp": r["Test-SP"],
            "test_full": r["Test"],
            "secure_reference": r["Secure Code"],
            "insecure_reference": r["Insecure Code"],
        })
    with open(os.path.join(DATA_DIR, "tasks.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(tasks, f, indent=1, ensure_ascii=False)
    with open(os.path.join(DATA_DIR, "exclusions.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"eligible": len(eligible), "excluded": exclusions}, f, indent=1)
    held_out = [k for k in eligible if k not in set(chosen)]
    with open(os.path.join(DATA_DIR, "heldout.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump([{"key": k, "cwe": norm_cwe(rows[k]["ID"]), "prompt": rows[k]["Problem"]} for k in held_out],
                  f, indent=1, ensure_ascii=False)
    print(f"eligible {len(eligible)}, excluded {len(exclusions)}, selected {len(tasks)}, held-out {len(held_out)}")
    print("distinct CWEs:", len({t['cwe'] for t in tasks}))
    print(" ".join(f"{t['id']}:{t['cwe']}" for t in tasks))


if __name__ == "__main__":
    main()
