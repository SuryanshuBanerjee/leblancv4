"""Results: every number on the Results page and in the export is computed here from the database.

Outcome definitions (docs/PROPOSAL.md section 4.6):
  vuln_task  static: any Bandit/Semgrep finding outside scaffolding           (lower is better)
  sp_fail    dynamic: the task's security test (Test-SP) does not pass         (lower is better)
  fp_pass    functional: the task's functional test (Test-FP) passes          (higher is better)
  secure_pass  fp_pass and Test-SP passes                                       (higher is better)
Security metrics exclude cells without extractable code; functional metrics count them as failures.
Test outcomes `harness_error` and `needs_config` are excluded from test metrics and reported.
"""
import csv
import json
import os
import random
import time
from collections import Counter, defaultdict

from . import enrich, judge, stats, store
from .config import DATA_DIR, MODELS, RUN_DIR, STUDY, model_ids, model_label, study_hash
from .dataset import task_map

D = STUDY["decision"]
EXCLUDED_TEST = ("harness_error", "needs_config")
SECURITY_METRICS = ("vuln_task", "sp_fail")
METRIC_LABEL = {"vuln_task": "static: scanner finding", "sp_fail": "dynamic: security test fails",
                "fp_pass": "works: functional test passes", "secure_pass": "secure and works",
                "vuln_target": "static: finding on the task's own CWE", "static_clean": "static: no finding",
                "fp_pass_strict": "works (published test, strict)", "sp_fail_strict": "security test fails (published, strict)",
                "secure_pass_strict": "secure and works (published, strict)"}


# ------------------------------------------------------------------ cell outcomes
def outcome(c, metric):
    has_code = c["extract"] == "ok" and c["code"] is not None
    if metric in ("vuln_task", "vuln_target", "vuln_bandit", "vuln_semgrep", "static_clean"):
        if not has_code or c["judge_status"] != "done" or c[metric if metric != "static_clean" else "vuln_task"] is None:
            return None
        v = c["vuln_task"] if metric == "static_clean" else c[metric]
        return 1 - v if metric == "static_clean" else v
    if metric in ("fp_pass", "sp_fail", "secure_pass", "fp_pass_strict", "sp_fail_strict", "secure_pass_strict"):
        strict = metric.endswith("_strict")
        base = metric.replace("_strict", "")
        # lenient security metrics exist only where the lenient security test still catches the insecure reference
        if not strict and base in ("sp_fail", "secure_pass") and not _sp_valid(c["task_id"]):
            return None
        if not has_code:
            return None if base == "sp_fail" else 0
        if c["test_status"] != "done":
            return None
        fp, sp = (c["fp_result"], c["sp_result"]) if strict else (c.get("fpl_result"), c.get("spl_result"))
        if fp is None and sp is None:
            return None
        if base == "fp_pass":
            return None if fp in EXCLUDED_TEST else int(fp == "pass")
        if base == "sp_fail":
            return None if sp in EXCLUDED_TEST else int(sp != "pass")
        if fp in EXCLUDED_TEST or sp in EXCLUDED_TEST:
            return None
        return int(fp == "pass" and sp == "pass")
    raise ValueError(metric)


def _sp_valid(task_id):
    t = task_map().get(task_id)
    return bool(t and t.get("sp_valid"))


def tokens(c):
    return (c["tokens_in"] or 0) + (c["tokens_out"] or 0)


def load_cells():
    return store.q("SELECT * FROM cells WHERE status='done'")


def _index(cells):
    gen = {(c["task_id"], c["model"], c["arm"], c["rep"]): c for c in cells if c["kind"] == "gen"}
    rep = {(c["task_id"], c["model"], c["kind"], c["rep"]): c for c in cells if c["kind"] != "gen"}
    return gen, rep


def _pct(x, digits=1):
    return "-" if x is None else f"{100 * x:.{digits}f}%"


def _pp(x):
    return "-" if x is None else f"{100 * x:+.1f} pp"


def _ci(lo, hi, pp=False):
    if lo is None:
        return "-"
    return f"[{100 * lo:+.1f}, {100 * hi:+.1f}]" if pp else f"[{100 * lo:.1f}, {100 * hi:.1f}]"


def _p(p):
    return "-" if p is None else ("<0.001" if p < 0.001 else f"{p:.3f}")


def verdict(res, q, baseline=None, security=True):
    """Pre-registered bands (PROPOSAL section 3). Effect direction: a decrease is the hypothesised effect."""
    if res["n"] < D["min_pairs"]:
        return "insufficient"
    if security and baseline is not None and baseline < D["ceiling_rate"]:
        return "ceiling"
    eff = 100 * res["effect"]
    if -eff >= D["practical_pp"] and q is not None and q < D["alpha"]:
        return "yes"
    if abs(eff) < D["no_effect_pp"] or (res["lo"] <= 0 <= res["hi"] and
                                        max(abs(res["lo"]), abs(res["hi"])) * 100 < D["practical_pp"]):
        return "no"
    return "unclear"


# ------------------------------------------------------------------ RQ helpers
def _rate(cells, metric):
    groups = defaultdict(list)
    for c in cells:
        v = outcome(c, metric)
        if v is not None:
            groups[c["task_id"]].append(v)
    return stats.cluster_rate(groups, D["bootstrap_resamples"])


def _pairs(a_cells, b_cells, metric):
    """a_cells/b_cells: {(task, rep): cell}. Returns {task: [(a, b)]} where both outcomes exist."""
    out = defaultdict(list)
    for key, a in a_cells.items():
        b = b_cells.get(key)
        if b is None:
            continue
        va, vb = outcome(a, metric), outcome(b, metric)
        if va is not None and vb is not None:
            out[key[0]].append((va, vb))
    return out


def _by_task_rep(gen, model, arm):
    return {(t, r): c for (t, m, a, r), c in gen.items() if m == model and a == arm}


# ------------------------------------------------------------------ the five RQs
def rq1(cells, gen):
    rows, ceil = [], {}
    for m in model_ids():
        plain = [c for (t, mm, a, r), c in gen.items() if mm == m and a == "plain"]
        r = {k: _rate(plain, k) for k in ("vuln_task", "vuln_target", "sp_fail", "fp_pass", "secure_pass")}
        ceil[m] = {k: (r[k]["rate"] is not None and r[k]["rate"] < D["ceiling_rate"]) for k in SECURITY_METRICS}
        rows.append([model_label(m), r["vuln_task"]["n"],
                     f"{_pct(r['vuln_task']['rate'])} {_ci(r['vuln_task']['lo'], r['vuln_task']['hi'])}",
                     f"{_pct(r['vuln_target']['rate'])}",
                     f"{_pct(r['sp_fail']['rate'])} {_ci(r['sp_fail']['lo'], r['sp_fail']['hi'])}",
                     f"{_pct(r['fp_pass']['rate'])} {_ci(r['fp_pass']['lo'], r['fp_pass']['hi'])}",
                     f"{_pct(r['secure_pass']['rate'])} {_ci(r['secure_pass']['lo'], r['secure_pass']['hi'])}",
                     ", ".join(k for k, v in ceil[m].items() if v) or "no"])
    # weaknesses that still get through, by CWE (plain arm, all models)
    tasks = task_map()
    by_cwe = defaultdict(lambda: [0, 0, 0, 0])
    for (t, m, a, r), c in gen.items():
        if a != "plain":
            continue
        cwe = tasks[t]["cwe"]
        v1, v2 = outcome(c, "sp_fail"), outcome(c, "vuln_task")
        if v1 is not None:
            by_cwe[cwe][0] += v1
            by_cwe[cwe][1] += 1
        if v2 is not None:
            by_cwe[cwe][2] += v2
            by_cwe[cwe][3] += 1
    cwe_rows = sorted(([cwe, f"{v[0]}/{v[1]}", _pct(v[0] / v[1]) if v[1] else "-", f"{v[2]}/{v[3]}",
                        _pct(v[2] / v[3]) if v[3] else "-"] for cwe, v in by_cwe.items()),
                      key=lambda r: -(int(r[1].split("/")[0]) / max(1, int(r[1].split("/")[1]))))
    lead = None
    if rows:
        lead = "Without any security help: " + "; ".join(
            f"{r[0]} failed the security test on {r[4].split(' ')[0]} and was flagged by a scanner on {r[2].split(' ')[0]} of outputs"
            for r in rows) + "."
    return {"id": "RQ1", "question": "With no help, how often does each model write insecure code?",
            "sentence": lead, "verdicts": [],
            "tables": [{"title": "Plain prompt, per model (rate [95% cluster-bootstrap CI])",
                        "columns": ["model", "n", "scanner flag", "flag on own CWE", "security test fails",
                                    "works", "secure and works", "ceiling (<10%)"], "rows": rows},
                       {"title": "Which weaknesses still get through (plain prompt, all models)",
                        "columns": ["CWE", "security test fails", "rate", "scanner flag", "rate"], "rows": cwe_rows}],
            "ceiling": ceil}


def _contrast_rows(gen, contrasts, metrics, ceiling, security=True):
    raw = []
    for m in model_ids():
        for metric in metrics:
            for a, b in contrasts:
                res = stats.paired(_pairs(_by_task_rep(gen, m, a), _by_task_rep(gen, m, b), metric),
                                   D["bootstrap_resamples"])
                raw.append((m, metric, a, b, res))
    qs = stats.bh([r[4]["p_mcnemar"] for r in raw])
    rows, verdicts = [], []
    for (m, metric, a, b, res), q in zip(raw, qs):
        base = res["rate_a"]
        v = verdict(res, q, base if (security and a == "plain") else None, security)
        rows.append([model_label(m), METRIC_LABEL[metric], f"{b} vs {a}", res["n"], _pct(res["rate_a"]),
                     _pct(res["rate_b"]), _pp(res["effect"]), _ci(res["lo"], res["hi"], True),
                     f"{res['b_only']}/{res['a_only']}", _p(res["p_mcnemar"]), _p(q), v])
        verdicts.append({"model": model_label(m), "metric": metric, "contrast": f"{b} vs {a}", "verdict": v,
                         "effect_pp": None if res["effect"] is None else round(100 * res["effect"], 2)})
    return rows, verdicts


CONTRAST_COLS = ["model", "metric", "contrast", "pairs", "rate A", "rate B", "effect (B-A)", "95% CI",
                 "discordant B/A", "McNemar p", "BH q", "verdict"]


def rq2(gen, ceiling):
    rows, verdicts = _contrast_rows(gen, [("plain", "generic"), ("plain", "targeted"), ("generic", "targeted")],
                                    SECURITY_METRICS, ceiling)
    key = [v for v in verdicts if v["contrast"] == "targeted vs generic"]
    sentence = None
    if key:
        sentence = "Does the CWE-specific warning beat the generic line? " + "; ".join(
            f"{v['model']} ({METRIC_LABEL[v['metric']].split(':')[0]}): {v['verdict']}" +
            (f", {v['effect_pp']:+.1f} pp" if v["effect_pp"] is not None else "") for v in key) + "."
    return {"id": "RQ2", "question": "Does a CWE-specific warning reduce insecure code beyond a generic 'write secure code' line?",
            "sentence": sentence, "verdicts": verdicts,
            "tables": [{"title": "Paired by task and repetition. Negative effect = less insecure. "
                                 "Verdict bands: yes = reduction >= 5 pp and BH q < 0.05; no = |effect| < 3 pp or CI inside +/-5 pp; "
                                 "ceiling = baseline under 10%; insufficient = fewer than 10 pairs.",
                        "columns": CONTRAST_COLS, "rows": rows}]}


def rq3(gen):
    rows, verdicts = _contrast_rows(gen, [("plain", "generic"), ("plain", "targeted")], ("fp_pass", "secure_pass"),
                                    None, security=False)
    sentence = "Does adding a security preamble change whether the code works? " + "; ".join(
        f"{v['model']} {v['contrast']}: {v['effect_pp']:+.1f} pp" for v in verdicts
        if v["metric"] == "fp_pass" and v["effect_pp"] is not None) + "." if verdicts else None
    floor = floor_tasks(gen)
    return {"id": "RQ3", "question": "Does a security preamble change whether the code works?",
            "sentence": sentence, "verdicts": verdicts,
            "tables": [{"title": "Paired by task and repetition. Negative effect = fewer outputs work (verdict 'yes' = a cost of at least 5 pp).",
                        "columns": CONTRAST_COLS, "rows": rows},
                       {"title": "Sensitivity: tasks whose functional test fails every output of every model and arm "
                                 "(uninformative for this contrast; listed, and the contrast is unchanged by them because pairs are within task)",
                        "columns": ["task", "CWE", "outputs tested"], "rows": floor}]}


def floor_tasks(gen):
    tasks = task_map()
    agg = defaultdict(list)
    for (t, m, a, r), c in gen.items():
        v = outcome(c, "fp_pass")
        if v is not None:
            agg[t].append(v)
    return [[t, tasks[t]["cwe"], len(v)] for t, v in sorted(agg.items()) if v and sum(v) == 0]


def _strategies(gen, rep_cells):
    """Per (task, model, rep): outcome cells and token totals for each strategy applied to the plain output."""
    reps_avail = sorted({r for (_, _, _, r) in gen})
    out = defaultdict(dict)
    for (t, m, a, r), c in gen.items():
        if a == "plain":
            out[(t, m, r)]["none"] = (c, tokens(c), c["cost_usd"] or 0.0)
    for (t, m, kind, r), c in rep_cells.items():
        base = gen.get((t, m, "plain", r))
        if base is not None:
            out[(t, m, r)][kind] = (c, tokens(base) + tokens(c), (base["cost_usd"] or 0.0) + (c["cost_usd"] or 0.0))
    for (t, m, r), d in out.items():
        seq = [rr for rr in reps_avail[reps_avail.index(r):] + reps_avail[:reps_avail.index(r)]]
        used, spent, chosen = 0, 0.0, None
        for rr in seq:
            c = gen.get((t, m, "plain", rr))
            if c is None:
                continue
            used += tokens(c)
            spent += c["cost_usd"] or 0.0
            chosen = c
            if outcome(c, "vuln_task") == 0:
                break
        if chosen is not None:
            d["resample"] = (chosen, used, spent)
    return out


STRATS = ("none", "scan_repair", "blind_repair", "resample")


def rq4(gen, rep_cells):
    S = _strategies(gen, rep_cells)
    rows_rate, rows_cmp, rows_break, raw = [], [], [], []
    for m in model_ids():
        for s in STRATS:
            cells = [d[s][0] for (t, mm, r), d in S.items() if mm == m and s in d]
            toks = [d[s][1] for (t, mm, r), d in S.items() if mm == m and s in d]
            rs = {k: _rate(cells, k) for k in ("secure_pass", "static_clean", "fp_pass", "sp_fail")}
            rows_rate.append([model_label(m), s, len(cells), _pct(rs["static_clean"]["rate"]),
                              _pct(rs["sp_fail"]["rate"]), _pct(rs["fp_pass"]["rate"]),
                              f"{_pct(rs['secure_pass']['rate'])} {_ci(rs['secure_pass']['lo'], rs['secure_pass']['hi'])}",
                              f"{sum(toks) / len(toks):.0f}" if toks else "-"])
        for a, b in (("none", "scan_repair"), ("none", "blind_repair"), ("blind_repair", "scan_repair"),
                     ("resample", "scan_repair"), ("none", "resample")):
            for metric in ("secure_pass", "static_clean"):
                pairs = defaultdict(list)
                for (t, mm, r), d in S.items():
                    if mm == m and a in d and b in d:
                        va, vb = outcome(d[a][0], metric), outcome(d[b][0], metric)
                        if va is not None and vb is not None:
                            pairs[t].append((va, vb))
                raw.append((m, a, b, metric, stats.paired(pairs, D["bootstrap_resamples"])))
        # repairs that broke working code
        for s in ("scan_repair", "blind_repair"):
            worked = broke = flagged_worked = flagged_broke = 0
            for (t, mm, r), d in S.items():
                if mm != m or s not in d or "none" not in d:
                    continue
                if outcome(d["none"][0], "fp_pass") == 1:
                    after = outcome(d[s][0], "fp_pass")
                    if after is None:
                        continue
                    worked += 1
                    broke += 1 - after
                    if d["none"][0]["vuln_task"] == 1:
                        flagged_worked += 1
                        flagged_broke += 1 - after
            rows_break.append([model_label(m), s, worked, broke, _pct(broke / worked) if worked else "-",
                               flagged_worked, flagged_broke, _pct(flagged_broke / flagged_worked) if flagged_worked else "-"])
    qs = stats.bh([r[4]["p_mcnemar"] for r in raw])
    for (m, a, b, metric, res), q in zip(raw, qs):
        rows_cmp.append([model_label(m), METRIC_LABEL[metric], f"{b} vs {a}", res["n"], _pct(res["rate_a"]),
                         _pct(res["rate_b"]), _pp(res["effect"]), _ci(res["lo"], res["hi"], True),
                         f"{res['b_only']}/{res['a_only']}", _p(res["p_mcnemar"]), _p(q)])
    conv = store.q("SELECT model, repair_outcome, COUNT(*) n, AVG(rounds) r FROM cells WHERE kind='scan_repair' "
                   "AND status='done' GROUP BY model, repair_outcome")
    conv_rows = [[model_label(c["model"]), c["repair_outcome"], c["n"], f"{c['r']:.2f}" if c["r"] is not None else "-"]
                 for c in conv]
    return {"id": "RQ4", "question": "Given the plain output, which fix works best: scanner-guided repair, a blind 'fix vulnerabilities' pass, or simply sampling again?",
            "sentence": None, "verdicts": [],
            "tables": [{"title": "Outcome per strategy (applied to the plain output; tokens include the original generation)",
                        "columns": ["model", "strategy", "n", "scanner clean", "security test fails", "works",
                                    "secure and works [CI]", "mean tokens"], "rows": rows_rate},
                       {"title": "Paired comparisons (positive effect = B better for these metrics)",
                        "columns": CONTRAST_COLS[:-1], "rows": rows_cmp},
                       {"title": "Repairs that broke working code (functional test passed before, fails after)",
                        "columns": ["model", "strategy", "worked before", "broken after", "rate",
                                    "of those scanner-flagged: worked", "broken", "rate"], "rows": rows_break},
                       {"title": "Scanner-guided repair: outcome and mean rounds",
                        "columns": ["model", "outcome", "cells", "mean rounds"], "rows": conv_rows}]}


def rq5(gen, rep_cells):
    S = _strategies(gen, rep_cells)
    pts, rows = [], []
    for m in model_ids():
        base = None
        series = [(arm, [(c, tokens(c), c["cost_usd"] or 0.0) for (t, mm, a, r), c in gen.items() if mm == m and a == arm])
                  for arm in ("plain", "generic", "targeted")]
        for s in ("scan_repair", "blind_repair", "resample"):
            series.append(("plain+" + s, [d[s] for (t, mm, r), d in S.items() if mm == m and s in d]))
        for name, items in series:
            if not items:
                continue
            sp = [outcome(it[0], "secure_pass") for it in items]
            sp = [v for v in sp if v is not None]
            rate = sum(sp) / len(sp) if sp else None
            mean_tok = sum(it[1] for it in items) / len(items)
            cost = sum(it[2] for it in items) / len(items)
            if name == "plain":
                base = (rate, mean_tok)
            d_rate = (rate - base[0]) if (base and rate is not None and base[0] is not None) else None
            d_tok = mean_tok - base[1] if base else None
            per = (d_tok / (100 * d_rate)) if (d_rate and d_rate > 0) else None
            rows.append([model_label(m), name, len(items), _pct(rate), f"{mean_tok:.0f}",
                         "-" if d_tok is None else f"{d_tok:+.0f}", _pp(d_rate),
                         "-" if per is None else f"{per:.0f}", f"${cost * 1000:.3f}"])
            pts.append({"model": model_label(m), "strategy": name, "rate": rate, "tokens": mean_tok})
    added = []
    for arm in ("generic", "targeted"):
        for m in model_ids():
            diffs = []
            for (t, mm, a, r), c in gen.items():
                if mm == m and a == arm:
                    p = gen.get((t, m, "plain", r))
                    if p and c["n_calls"] == 1 and p["n_calls"] == 1:
                        diffs.append((c["tokens_in"] or 0) - (p["tokens_in"] or 0))
            if diffs:
                added.append([model_label(m), arm, len(diffs), f"{sum(diffs) / len(diffs):.1f}"])
    return {"id": "RQ5", "question": "What does each strategy cost in tokens per additional secure-and-working output?",
            "sentence": None, "verdicts": [], "points": pts,
            "tables": [{"title": "Cost-effectiveness per strategy (secure and works rate vs mean tokens per task attempt)",
                        "columns": ["model", "strategy", "n", "secure and works", "mean tokens", "extra tokens vs plain",
                                    "change vs plain", "extra tokens per +1 pp", "mean cost per 1,000 attempts"],
                        "rows": rows},
                       {"title": "Prompt tokens added by each preamble (measured from provider usage, paired with plain)",
                        "columns": ["model", "arm", "pairs", "mean added prompt tokens"], "rows": added}]}


# ------------------------------------------------------------------ instrument validity
def validity(cells, gen):
    ext = store.q("SELECT model, arm, extract, COUNT(*) n FROM cells WHERE status='done' AND kind='gen' "
                  "GROUP BY model, arm, extract ORDER BY model, arm, extract")
    tst = store.q("SELECT fp_result r, COUNT(*) n FROM cells WHERE test_status='done' GROUP BY 1")
    tsp = store.q("SELECT sp_result r, COUNT(*) n FROM cells WHERE test_status='done' GROUP BY 1")
    a, b = [], []
    agree = Counter()
    for c in gen.values():
        v1, v2 = outcome(c, "vuln_task"), outcome(c, "sp_fail")
        if v1 is not None and v2 is not None:
            a.append(v1)
            b.append(v2)
            agree[(v1, v2)] += 1
    k = stats.cohen_kappa(a, b)
    f = store.q1("SELECT COUNT(*) n, SUM(on_scaffolding) s FROM findings f JOIN cells c ON c.id=f.cell_id WHERE c.kind='gen'")
    tools = store.q("SELECT CASE WHEN vuln_bandit=1 AND vuln_semgrep=1 THEN 'both' WHEN vuln_bandit=1 THEN 'bandit only' "
                    "WHEN vuln_semgrep=1 THEN 'semgrep only' ELSE 'neither' END t, COUNT(*) n FROM cells "
                    "WHERE kind='gen' AND judge_status='done' GROUP BY 1")
    rules = store.q("SELECT f.tool, f.rule, COUNT(*) n, SUM(f.on_scaffolding) s FROM findings f JOIN cells c ON c.id=f.cell_id "
                    "WHERE c.kind='gen' GROUP BY f.tool, f.rule ORDER BY n DESC LIMIT 15")
    au = audit_summary()
    calls = store.q("SELECT model, COUNT(*) n, SUM(ok) ok, SUM(CASE WHEN finish_reason='length' THEN 1 ELSE 0 END) trunc "
                    "FROM calls GROUP BY model")
    sens = []
    for m in model_ids():
        for arm in STUDY["arms"]:
            cs = [c for (t, mm, a, r), c in gen.items() if mm == m and a == arm]
            row = [model_label(m), arm]
            for met in ("fp_pass", "fp_pass_strict", "sp_fail", "sp_fail_strict", "secure_pass", "secure_pass_strict"):
                v = [x for x in (outcome(c, met) for c in cs) if x is not None]
                row.append(f"{_pct(sum(v) / len(v)) if v else '-'} (n={len(v)})")
            sens.append(row)
    return {"id": "VALIDITY", "question": "Can the instruments be trusted? (reported with every RQ)",
            "sentence": None, "verdicts": [],
            "tables": [
                {"title": "Lenient (primary) vs published strict test scoring. Lenient accepts any exception where a test "
                          "requires the input to be rejected; lenient security results use only the 45 tasks where the "
                          "lenient security test still fails the insecure reference.",
                 "columns": ["model", "arm", "works", "works (strict)", "security test fails", "security fails (strict)",
                             "secure and works", "secure and works (strict)"], "rows": sens},
                {"title": "Scanner verdict vs security-test verdict on the same outputs (Cohen's kappa "
                          + ("-" if k[0] is None else f"{k[0]:.2f}") + f", n={k[2]})",
                 "columns": ["", "security test passes", "security test fails"],
                 "rows": [["scanner clean", agree[(0, 0)], agree[(0, 1)]], ["scanner flags", agree[(1, 0)], agree[(1, 1)]]]},
                {"title": "False-positive audit of scanner findings",
                 "columns": ["annotator", "labelled", "true positive", "false positive", "unsure"], "rows": au["rows"]},
                {"title": "Agreement between annotators: " + au["kappa_text"], "columns": [], "rows": []},
                {"title": "Which analyser flagged the generation outputs", "columns": ["analyser", "outputs"],
                 "rows": [[t["t"], t["n"]] for t in tools]},
                {"title": f"Findings on scaffolding (app.run / __main__): {f['s'] or 0} of {f['n'] or 0}, excluded from the primary metric",
                 "columns": [], "rows": []},
                {"title": "Most frequent rules (generation outputs)", "columns": ["tool", "rule", "findings", "on scaffolding"],
                 "rows": [[r["tool"], r["rule"], r["n"], r["s"]] for r in rules]},
                {"title": "Code extraction by model and arm", "columns": ["model", "arm", "extraction", "outputs"],
                 "rows": [[model_label(r["model"]), r["arm"], r["extract"], r["n"]] for r in ext]},
                {"title": "Functional test outcome classes", "columns": ["result", "outputs"], "rows": [[r["r"], r["n"]] for r in tst]},
                {"title": "Security test outcome classes", "columns": ["result", "outputs"], "rows": [[r["r"], r["n"]] for r in tsp]},
                {"title": "Model calls: attempts, successes, truncations (gate: truncation under 2%)",
                 "columns": ["model", "attempts", "ok", "truncated", "truncation rate"],
                 "rows": [[model_label(r["model"]), r["n"], r["ok"], r["trunc"], _pct((r["trunc"] or 0) / r["ok"]) if r["ok"] else "-"]
                          for r in calls]},
            ]}


# ------------------------------------------------------------------ audit
def draw_audit_sample(frac=0.10, lo=30, hi=150):
    if store.q1("SELECT COUNT(*) n FROM audit_sample")["n"]:
        return store.q1("SELECT COUNT(*) n FROM audit_sample")["n"]
    ids = [r["id"] for r in store.q("SELECT f.id FROM findings f JOIN cells c ON c.id=f.cell_id "
                                    "WHERE c.kind='gen' AND f.on_scaffolding=0 ORDER BY f.id")]
    if not ids:
        return 0
    k = min(len(ids), max(lo, min(hi, round(frac * len(ids)))))
    pick = sorted(random.Random(STUDY["seed"]).sample(ids, k))
    now = time.time()
    store.xmany("INSERT INTO audit_sample(finding_id, drawn_at) VALUES (?,?)", [(i, now) for i in pick])
    store.event(f"audit sample drawn: {k} of {len(ids)} task findings")
    return k


def audit_summary():
    labs = store.q("SELECT annotator, label, COUNT(*) n FROM audit a JOIN audit_sample s ON s.finding_id=a.finding_id "
                   "GROUP BY annotator, label")
    by = defaultdict(Counter)
    for r in labs:
        by[r["annotator"]][r["label"]] += r["n"]
    rows = [[a, sum(c.values()), c["tp"], c["fp"], c["unsure"]] for a, c in sorted(by.items())]
    names = sorted(by)
    kappa_text = "needs two annotators"
    if len(names) >= 2:
        x = {r["finding_id"]: r["label"] for r in store.q("SELECT * FROM audit WHERE annotator=?", (names[0],))}
        y = {r["finding_id"]: r["label"] for r in store.q("SELECT * FROM audit WHERE annotator=?", (names[1],))}
        common = sorted(set(x) & set(y))
        k = stats.cohen_kappa([x[i] for i in common], [y[i] for i in common])
        kappa_text = (f"{names[0]} vs {names[1]}: kappa {k[0]:.2f}, raw agreement {_pct(k[1])}, n={k[2]}"
                      if k[0] is not None else "no overlapping labels yet")
    return {"rows": rows, "kappa_text": kappa_text}


# ------------------------------------------------------------------ Engine A offline evaluation
def engine_a_eval():
    out = {}
    held = json.load(open(os.path.join(DATA_DIR, "heldout.json"), encoding="utf-8"))
    sets = {"held-out (119 eligible CodeSecEval tasks not in the study)": [(h["prompt"], h["cwe"]) for h in held],
            "study tasks (56)": [(t["prompt"], t["cwe"]) for t in task_map().values()]}
    for name, items in sets.items():
        hit = none = 0
        n_w, toks = [], []
        for prompt, cwe in items:
            r = enrich.analyze(prompt)
            got = {w["cwe"] for w in r["warnings"]}
            hit += bool(got & judge.target_set(cwe))
            none += not got
            n_w.append(len(got))
            toks.append(r["tokens"])
        n = len(items)
        out[name] = {"tasks": n, "target_cwe_in_warnings": round(hit / n, 3), "no_warning": round(none / n, 3),
                     "mean_warnings": round(sum(n_w) / n, 2), "mean_tokens": round(sum(toks) / n, 1),
                     "max_tokens": max(toks)}
    return out


# ------------------------------------------------------------------ assembly and export
def progress():
    rows = store.q("SELECT model, arm, kind, rep, status, COUNT(*) n FROM cells GROUP BY 1,2,3,4,5")
    return rows


def results():
    cells = load_cells()
    gen, rep_cells = _index(cells)
    r1 = rq1(cells, gen)
    sections = [r1, rq2(gen, r1["ceiling"]), rq3(gen), rq4(gen, rep_cells), rq5(gen, rep_cells), validity(cells, gen)]
    meta = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "study_hash": study_hash(),
            "db_study_hash": store.get_meta("study_hash"), "cells_done": len(cells),
            "cells_total": store.q1("SELECT COUNT(*) n FROM cells")["n"],
            "reps_complete": _reps_complete(), "judge": store.get_meta("judge_provenance"),
            "models": [m["id"] for m in MODELS["models"]]}
    return {"meta": meta, "sections": sections}


def _reps_complete():
    r = store.q("SELECT rep, SUM(CASE WHEN status IN ('done','failed') THEN 1 ELSE 0 END) d, COUNT(*) n FROM cells GROUP BY rep")
    return [x["rep"] for x in r if x["d"] == x["n"]]


def _latex(table):
    cols = table["columns"]
    if not cols:
        return ""
    esc = lambda s: str(s).replace("%", r"\%").replace("&", r"\&").replace("_", r"\_").replace("#", r"\#")
    lines = [r"\begin{table}[t]\centering\small", r"\caption{" + esc(table["title"]) + "}",
             r"\begin{tabular}{" + "l" * len(cols) + "}", r"\toprule", " & ".join(esc(c) for c in cols) + r" \\", r"\midrule"]
    lines += [" & ".join(esc(c) for c in row) + r" \\" for row in table["rows"]]
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    return "\n".join(lines)


def export():
    out = os.path.join(RUN_DIR, "export")
    os.makedirs(out, exist_ok=True)
    for table, q in (("cells", "SELECT * FROM cells ORDER BY ord"), ("calls", "SELECT * FROM calls ORDER BY id"),
                     ("findings", "SELECT * FROM findings ORDER BY id"), ("repair_rounds", "SELECT * FROM repair_rounds"),
                     ("audit", "SELECT * FROM audit"), ("events", "SELECT * FROM events ORDER BY id")):
        rows = store.q(q)
        with open(os.path.join(out, table + ".csv"), "w", newline="", encoding="utf-8") as f:
            if rows:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
    res = results()
    res["engine_a"] = engine_a_eval()
    with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, default=str)
    with open(os.path.join(out, "tables.tex"), "w", encoding="utf-8") as f:
        for s in res["sections"]:
            f.write(f"% {s['id']}: {s['question']}\n")
            for t in s["tables"]:
                f.write(_latex(t))
    manifest = {"study_hash": study_hash(), "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "config": {n: json.load(open(os.path.join(RUN_DIR, "..", "config", n), encoding="utf-8"))
                           for n in ("study.json", "models.json", "prices.json")},
                "judge": store.get_meta("judge_provenance"), "planned": store.get_meta("planned")}
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    return out
