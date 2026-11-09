"""Figures and numbers for the paper and the report, computed from the run database (read only, no API calls).

    python paper/make_figures.py            # uses run/leblanc.db (or LEBLANC_DB)
Writes paper/figures/*.pdf|png, paper/numbers.json (every number the documents quote), paper/tables/*.tex.
"""
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from leblanc import report, stats, store  # noqa: E402
from leblanc.config import STUDY, model_ids, model_label  # noqa: E402
from leblanc.dataset import task_map  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = os.path.join(HERE, "figures")
TAB = os.path.join(HERE, "tables")
os.makedirs(FIG, exist_ok=True)
os.makedirs(TAB, exist_ok=True)

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9.5, "axes.spines.top": False,
                     "axes.spines.right": False, "savefig.dpi": 220, "savefig.bbox": "tight"})
ARM_C = {"plain": "#000000", "generic": "#E69F00", "targeted": "#0072B2"}
STRAT_C = {"plain": "#000000", "generic": "#E69F00", "targeted": "#0072B2", "plain+scan_repair": "#009E73",
           "plain+blind_repair": "#D55E00", "plain+resample": "#CC79A7"}
MODELS = model_ids()
LAB = {m: model_label(m) for m in MODELS}
N = {}


def save(fig, name):
    fig.savefig(os.path.join(FIG, name + ".pdf"))
    fig.savefig(os.path.join(FIG, name + ".png"))
    plt.close(fig)


def pct(x):
    return None if x is None else round(100 * x, 1)


cells = report.load_cells()
gen, rep_cells = report._index(cells)
tasks = task_map()

# ------------------------------------------------------------------ census
N["cells_total"] = store.q1("SELECT COUNT(*) n FROM cells")["n"]
N["cells_done"] = len(cells)
N["cells_failed"] = store.q1("SELECT COUNT(*) n FROM cells WHERE status='failed'")["n"]
c = store.q1("SELECT COUNT(*) n, SUM(ok) ok, SUM(cost_usd) cost, SUM(prompt_tokens) tin, SUM(completion_tokens) tout, "
             "SUM(reasoning_tokens) tr, MIN(created_at) t0, MAX(created_at) t1, SUM(http_status=429) r429 FROM calls")
N["calls"] = {"attempts": c["n"], "ok": c["ok"], "cost_usd": round(c["cost"] or 0, 4), "tokens_in": c["tin"],
              "tokens_out": c["tout"], "tokens_reasoning": c["tr"], "rate_limited": c["r429"],
              "minutes": round(((c["t1"] or 0) - (c["t0"] or 0)) / 60, 1)}
N["calls_by_model"] = {LAB[r["model"]]: {"attempts": r["n"], "ok": r["ok"], "truncated": r["tr"],
                                         "cost_usd": round(r["c"] or 0, 4), "mean_latency_s": round(r["lat"] or 0, 1)}
                       for r in store.q("SELECT model, COUNT(*) n, SUM(ok) ok, SUM(finish_reason='length') tr, "
                                        "SUM(cost_usd) c, AVG(CASE WHEN ok=1 THEN latency_s END) lat FROM calls GROUP BY model")}
N["hosts"] = [dict(r) for r in store.q("SELECT model, provider, COUNT(*) n FROM calls WHERE ok=1 GROUP BY 1,2")]
N["reps_complete"] = report._reps_complete()
N["extraction"] = [dict(r) for r in store.q("SELECT kind, extract, COUNT(*) n FROM cells WHERE status='done' GROUP BY 1,2")]
N["tasks"] = len(tasks)
N["sp_valid_tasks"] = sum(bool(t.get("sp_valid")) for t in tasks.values())
N["cwe_types"] = len({t["cwe"] for t in tasks.values()})

# ------------------------------------------------------------------ RQ1 baseline
NL = chr(10)
METRICS = [("vuln_task", "Scanner flags" + NL + "task code"), ("sp_fail", "Security test" + NL + "fails"),
           ("fp_pass", "Functional test" + NL + "passes"), ("secure_pass", "Secure and" + NL + "works")]
N["rq1"] = {}
fig, ax = plt.subplots(figsize=(7.2, 3.0))
w = 0.26
for i, m in enumerate(MODELS):
    plain = [c for (t, mm, a, r), c in gen.items() if mm == m and a == "plain"]
    N["rq1"][LAB[m]] = {}
    for j, (k, _) in enumerate(METRICS):
        r = report._rate(plain, k)
        N["rq1"][LAB[m]][k] = {"rate": pct(r["rate"]), "lo": pct(r["lo"]), "hi": pct(r["hi"]), "n": r["n"], "tasks": r["tasks"]}
        for k2 in ("sp_fail_strict", "fp_pass_strict", "secure_pass_strict", "vuln_target", "vuln_raw"):
            r2 = report._rate(plain, k2) if k2 != "vuln_raw" else None
            if r2:
                N["rq1"][LAB[m]][k2] = {"rate": pct(r2["rate"]), "lo": pct(r2["lo"]), "hi": pct(r2["hi"]), "n": r2["n"]}
        x = j + (i - 1) * w
        if r["rate"] is not None:
            ax.bar(x, 100 * r["rate"], w, color=["#4D4D4D", "#0072B2", "#E69F00"][i], label=LAB[m] if j == 0 else None)
            ax.errorbar(x, 100 * r["rate"], yerr=[[100 * (r["rate"] - r["lo"])], [100 * (r["hi"] - r["rate"])]],
                        color="black", capsize=2, lw=0.8)
ax.set_xticks(range(len(METRICS)))
ax.set_xticklabels([l for _, l in METRICS])
ax.set_ylabel("% of plain outputs")
ax.set_ylim(0, 100)
ax.legend(frameon=False, ncol=3, loc="upper left")
save(fig, "fig1_baseline")

# residual CWEs (plain, all models, lenient security where valid)
by = defaultdict(lambda: [0, 0])
for (t, m, a, r), c in gen.items():
    if a == "plain":
        v = report.outcome(c, "sp_fail")
        if v is not None:
            by[tasks[t]["cwe"]][0] += v
            by[tasks[t]["cwe"]][1] += 1
N["rq1_cwe"] = sorted(([k, v[0], v[1]] for k, v in by.items()), key=lambda x: (-x[1] / max(1, x[2]), -x[2]))

# ------------------------------------------------------------------ RQ2 / RQ3 paired contrasts
def contrasts(arms_pairs, metrics):
    raw = []
    for m in MODELS:
        for metric in metrics:
            for a, b in arms_pairs:
                res = stats.paired(report._pairs(report._by_task_rep(gen, m, a), report._by_task_rep(gen, m, b), metric))
                raw.append((m, metric, a, b, res))
    qs = stats.bh([r[4]["p_mcnemar"] for r in raw])
    out = []
    for (m, metric, a, b, res), q in zip(raw, qs):
        sec = metric in ("vuln_task", "sp_fail")
        v = report.verdict(res, q, res["rate_a"] if (sec and a == "plain") else None, sec)
        out.append({"model": LAB[m], "metric": metric, "a": a, "b": b, "n": res["n"], "rate_a": pct(res["rate_a"]),
                    "rate_b": pct(res["rate_b"]), "effect_pp": pct(res["effect"]), "lo": pct(res["lo"]), "hi": pct(res["hi"]),
                    "b_only": res["b_only"], "a_only": res["a_only"], "p": res["p_mcnemar"], "q": q, "verdict": v})
    return out


N["rq2"] = contrasts([("plain", "generic"), ("plain", "targeted"), ("generic", "targeted")], ("sp_fail", "vuln_task"))
N["rq2_strict"] = contrasts([("plain", "generic"), ("plain", "targeted"), ("generic", "targeted")], ("sp_fail_strict",))
N["rq3"] = contrasts([("plain", "generic"), ("plain", "targeted")], ("fp_pass", "secure_pass"))


def forest(rows, metric, title, name, xlabel):
    rows = [r for r in rows if r["metric"] == metric and r["effect_pp"] is not None]
    fig, ax = plt.subplots(figsize=(6.4, 0.32 * len(rows) + 0.9))
    for i, r in enumerate(reversed(rows)):
        col = {"generic": "#E69F00", "targeted": "#0072B2"}[r["b"]] if r["a"] == "plain" else "#555555"
        ax.plot([r["lo"], r["hi"]], [i, i], color=col, lw=1.6)
        ax.plot(r["effect_pp"], i, "o", color=col, ms=5)
    ax.axvline(0, color="black", lw=0.8)
    for s in (-5, 5):
        ax.axvline(s, color="#999999", lw=0.6, ls=":")
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{r['model']}: {r['b']} vs {r['a']}" for r in reversed(rows)])
    ax.set_xlabel(xlabel)
    ax.set_title(title, fontsize=10, loc="left")
    save(fig, name)


forest(N["rq2"], "sp_fail", "Security-test failure: paired difference (95% cluster-bootstrap CI)", "fig2_rq2_security",
       "percentage points (negative = fewer insecure outputs)")
forest(N["rq2"], "vuln_task", "Scanner finding: paired difference (95% cluster-bootstrap CI)", "fig3_rq2_static",
       "percentage points (negative = fewer flagged outputs)")
forest(N["rq3"], "fp_pass", "Functional test pass: paired difference (95% cluster-bootstrap CI)", "fig4_rq3_function",
       "percentage points (negative = fewer working outputs)")

# ------------------------------------------------------------------ RQ4 strategies
S = report._strategies(gen, rep_cells)
N["rq4"] = {}
raw = []
for m in MODELS:
    N["rq4"][LAB[m]] = {}
    for s in report.STRATS:
        cs = [d[s][0] for (t, mm, r), d in S.items() if mm == m and s in d]
        tok = [d[s][1] for (t, mm, r), d in S.items() if mm == m and s in d]
        cost = [d[s][2] for (t, mm, r), d in S.items() if mm == m and s in d]
        N["rq4"][LAB[m]][s] = {k: (lambda r: {"rate": pct(r["rate"]), "lo": pct(r["lo"]), "hi": pct(r["hi"]), "n": r["n"]})(report._rate(cs, k))
                               for k in ("secure_pass", "static_clean", "fp_pass", "sp_fail")}
        N["rq4"][LAB[m]][s]["mean_tokens"] = round(sum(tok) / len(tok)) if tok else None
        N["rq4"][LAB[m]][s]["mean_cost_usd"] = (sum(cost) / len(cost)) if cost else None
    for a, b in (("none", "scan_repair"), ("none", "blind_repair"), ("blind_repair", "scan_repair"),
                 ("resample", "scan_repair"), ("none", "resample")):
        for metric in ("secure_pass", "sp_fail", "static_clean", "fp_pass"):
            pairs = defaultdict(list)
            for (t, mm, r), d in S.items():
                if mm == m and a in d and b in d:
                    va, vb = report.outcome(d[a][0], metric), report.outcome(d[b][0], metric)
                    if va is not None and vb is not None:
                        pairs[t].append((va, vb))
            raw.append((m, a, b, metric, stats.paired(pairs)))
qs = stats.bh([r[4]["p_mcnemar"] for r in raw])
N["rq4_contrasts"] = [{"model": LAB[m], "a": a, "b": b, "metric": metric, "n": res["n"], "rate_a": pct(res["rate_a"]),
                       "rate_b": pct(res["rate_b"]), "effect_pp": pct(res["effect"]), "lo": pct(res["lo"]), "hi": pct(res["hi"]),
                       "b_only": res["b_only"], "a_only": res["a_only"], "p": res["p_mcnemar"], "q": q}
                      for (m, a, b, metric, res), q in zip(raw, qs)]
N["rq4_repair_outcomes"] = [dict(r) for r in store.q(
    "SELECT model, repair_outcome, COUNT(*) n, AVG(rounds) rounds FROM cells WHERE kind='scan_repair' AND status='done' GROUP BY 1,2")]
N["rq4_blind_outcomes"] = [dict(r) for r in store.q(
    "SELECT model, repair_outcome, extract, COUNT(*) n FROM cells WHERE kind='blind_repair' AND status='done' GROUP BY 1,2,3")]
brk = {}
for m in MODELS:
    for s in ("scan_repair", "blind_repair"):
        worked = broke = 0
        for (t, mm, r), d in S.items():
            if mm == m and s in d and "none" in d and report.outcome(d["none"][0], "fp_pass") == 1:
                after = report.outcome(d[s][0], "fp_pass")
                if after is not None:
                    worked += 1
                    broke += 1 - after
        brk[f"{LAB[m]}|{s}"] = {"worked_before": worked, "broken_after": broke, "rate": pct(broke / worked) if worked else None}
N["rq4_broke"] = brk

fig, axes = plt.subplots(1, len(MODELS), figsize=(8.2, 2.9), sharey=True)
names = {"none": "plain", "scan_repair": "scan" + NL + "repair", "blind_repair": "blind" + NL + "repair",
         "resample": "re-" + NL + "sample"}
cols = {"none": "#000000", "scan_repair": "#009E73", "blind_repair": "#D55E00", "resample": "#CC79A7"}
for ax, m in zip(axes, MODELS):
    for i, s in enumerate(report.STRATS):
        r = N["rq4"][LAB[m]][s]["secure_pass"]
        if r["rate"] is not None:
            ax.bar(i, r["rate"], color=cols[s], width=0.7)
            ax.errorbar(i, r["rate"], yerr=[[r["rate"] - r["lo"]], [r["hi"] - r["rate"]]], color="black", capsize=2, lw=0.8)
    ax.set_xticks(range(len(report.STRATS)))
    ax.set_xticklabels([names[s] for s in report.STRATS], fontsize=8)
    ax.set_title(LAB[m], fontsize=9.5)
axes[0].set_ylabel("% secure and works")
save(fig, "fig5_rq4_strategies")

# ------------------------------------------------------------------ RQ5 tokens
res = report.results()
rq5 = next(s for s in res["sections"] if s["id"] == "RQ5")
N["rq5_points"] = rq5["points"]
N["rq5_table"] = rq5["tables"][0]["rows"]
N["rq5_added_tokens"] = rq5["tables"][1]["rows"]
fig, axes = plt.subplots(1, len(MODELS), figsize=(7.6, 2.8), sharey=True)
for ax, m in zip(axes, MODELS):
    for p in [p for p in rq5["points"] if p["model"] == LAB[m] and p["rate"] is not None]:
        mk = "o" if p["strategy"] in ("plain", "generic", "targeted") else ("s" if "repair" in p["strategy"] else "D")
        face = "none" if p["strategy"] == "plain" else STRAT_C[p["strategy"]]
        ax.scatter(p["tokens"], 100 * p["rate"], marker=mk, s=46, facecolors=face, edgecolors=STRAT_C[p["strategy"]],
                   linewidths=1.6, label=p["strategy"], zorder=5 if p["strategy"] == "plain" else 3)
    ax.set_title(LAB[m], fontsize=9.5)
    ax.set_xlabel("mean tokens per attempt")
    ax.grid(alpha=0.25)
axes[0].set_ylabel("% secure and works")
h, l = axes[0].get_legend_handles_labels()
fig.legend(h, l, frameon=False, ncol=6, loc="upper center", bbox_to_anchor=(0.5, 1.08), fontsize=8)
save(fig, "fig6_rq5_tokens")

# ------------------------------------------------------------------ validity
agree = Counter()
a_, b_ = [], []
for c in gen.values():
    v1, v2 = report.outcome(c, "vuln_task"), report.outcome(c, "sp_fail")
    if v1 is not None and v2 is not None:
        agree[f"{v1}{v2}"] += 1
        a_.append(v1)
        b_.append(v2)
k = stats.cohen_kappa(a_, b_)
N["scanner_vs_test"] = {"clean_pass": agree["00"], "clean_fail": agree["01"], "flag_pass": agree["10"], "flag_fail": agree["11"],
                        "kappa": None if k[0] is None else round(k[0], 3), "n": k[2]}
f = store.q1("SELECT COUNT(*) n, SUM(on_scaffolding) s FROM findings fd JOIN cells c ON c.id=fd.cell_id WHERE c.kind='gen'")
N["findings_gen"] = {"total": f["n"], "on_scaffolding": f["s"]}
N["top_rules"] = [dict(r) for r in store.q("SELECT fd.tool, fd.rule, COUNT(*) n FROM findings fd JOIN cells c ON c.id=fd.cell_id "
                                           "WHERE c.kind='gen' AND fd.on_scaffolding=0 GROUP BY 1,2 ORDER BY n DESC LIMIT 10")]
N["analyser_split"] = [dict(r) for r in store.q(
    "SELECT CASE WHEN vuln_bandit=1 AND vuln_semgrep=1 THEN 'both' WHEN vuln_bandit=1 THEN 'bandit only' "
    "WHEN vuln_semgrep=1 THEN 'semgrep only' ELSE 'neither' END t, COUNT(*) n FROM cells WHERE kind='gen' AND judge_status='done' GROUP BY 1")]
N["test_classes_lenient"] = {"fp": dict(Counter(c["fpl_result"] for c in cells if c["test_status"] == "done")),
                             "sp": dict(Counter(c["spl_result"] for c in cells if c["test_status"] == "done"))}
N["floor_tasks"] = report.floor_tasks(gen)
N["engine_a"] = report.engine_a_eval()
N["audit"] = report.audit_summary()
sens = {}
for m in MODELS:
    for arm in STUDY["arms"]:
        cs = [c for (t, mm, a, r), c in gen.items() if mm == m and a == arm]
        sens[f"{LAB[m]}|{arm}"] = {}
        for met in ("fp_pass", "fp_pass_strict", "sp_fail", "sp_fail_strict", "secure_pass", "secure_pass_strict", "vuln_task"):
            v = [x for x in (report.outcome(c, met) for c in cs) if x is not None]
            sens[f"{LAB[m]}|{arm}"][met] = {"rate": pct(sum(v) / len(v)) if v else None, "n": len(v)}
N["arm_rates"] = sens
N["config"] = {"temperature": STUDY["temperature"], "max_tokens": STUDY["max_tokens"], "reps": STUDY["reps"],
               "reasoning_effort": STUDY["reasoning_effort"], "max_rounds": STUDY["scan_repair_max_rounds"],
               "generic_line": STUDY["generic_line"], "judge": store.get_meta("judge_provenance")}

# fig7: what the scanner verdict says about the security-test verdict (generation outputs, all arms)
sv = N["scanner_vs_test"]
fig, ax = plt.subplots(figsize=(7.0, 1.9))
rows7 = [("Scanner said flagged", sv["flag_pass"], sv["flag_fail"]), ("Scanner said clean", sv["clean_pass"], sv["clean_fail"])]
for i, (lab, ok, bad) in enumerate(rows7):
    tot = ok + bad
    ax.barh(i, 100 * ok / tot, color="#009E73", height=0.55, label="security test passes" if i == 0 else None)
    ax.barh(i, 100 * bad / tot, left=100 * ok / tot, color="#D55E00", height=0.55,
            label="security test fails" if i == 0 else None)
    ax.text(100 * ok / tot / 2, i, f"{ok}", ha="center", va="center", color="white", fontsize=9)
    ax.text(100 * ok / tot + 100 * bad / tot / 2, i, f"{bad}", ha="center", va="center", color="white", fontsize=9)
    ax.text(101, i, f"n = {tot}", va="center", fontsize=8.5)
ax.set_yticks(range(len(rows7)))
ax.set_yticklabels([r[0] for r in rows7])
ax.set_xlim(0, 112)
ax.set_xticks([0, 25, 50, 75, 100])
ax.set_xlabel("% of outputs")
ax.legend(frameon=False, ncol=2, loc="upper center", bbox_to_anchor=(0.45, 1.42), fontsize=8.5)
save(fig, "fig7_scanner_vs_test")

# fig8: plain-prompt security-test failure per CWE (all models pooled)
cw = [r for r in N["rq1_cwe"] if r[2] > 0]
fig, ax = plt.subplots(figsize=(6.6, 0.17 * len(cw) + 0.8))
for i, (cwe, k, n) in enumerate(reversed(cw)):
    ax.barh(i, 100 * k / n, color="#0072B2" if k < n else "#D55E00", height=0.7)
    ax.text(100 * k / n + 1, i, f"{k}/{n}", va="center", fontsize=6.5)
ax.set_yticks(range(len(cw)))
ax.set_yticklabels([r[0] for r in reversed(cw)], fontsize=7)
ax.set_xlim(0, 112)
ax.set_xlabel("% of plain outputs failing the security test (all three models)")
ax.set_ylim(-0.7, len(cw) - 0.3)
save(fig, "fig8_cwe")

with open(os.path.join(HERE, "numbers.json"), "w", encoding="utf-8") as fh:
    json.dump(N, fh, indent=1, default=str)
print("figures:", sorted(os.listdir(FIG)))
print("cells", N["cells_done"], "/", N["cells_total"], "reps complete", N["reps_complete"], "cost", N["calls"]["cost_usd"])


# ------------------------------------------------------------------ LaTeX macros and tables
sys.path.insert(0, HERE)
from tex_out import write_all  # noqa: E402

write_all(N, MODELS, LAB, HERE)
