"""Local web UI (http://127.0.0.1:8765). Reads the database; the runner is a separate process."""
import difflib
import html
import json
import os
import subprocess
import sys
import time

from flask import Flask, abort, redirect, render_template_string, request, send_from_directory

from .. import enrich, report, runner, store
from ..config import MODELS, PRICES, ROOT, RUN_DIR, STUDY, get_key, model_ids, model_label, study_hash
from ..dataset import load_tasks, task_map
from . import templates as T

app = Flask(__name__)
NAV = [("/", "Run"), ("/results", "Results"), ("/runs", "Runs"), ("/audit", "Audit"), ("/dataset", "Dataset"),
       ("/setup", "Setup"), ("/export", "Export")]
_cache = {"t": 0, "res": None}


def page(title, body_tpl, active, refresh=None, **ctx):
    body = render_template_string(body_tpl, **ctx)
    return render_template_string(T.BASE, title=title, body=body, css=T.CSS, nav=NAV, active=active, refresh=refresh)


def _fmt_t(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""


# ------------------------------------------------------------------ Run
@app.route("/")
def run_page():
    total = store.q1("SELECT COUNT(*) n FROM cells")["n"]
    done = store.q1("SELECT COUNT(*) n FROM cells WHERE status='done'")["n"]
    failed = store.q1("SELECT COUNT(*) n FROM cells WHERE status='failed'")["n"]
    arms = STUDY["arms"] + STUDY["repair_arms"]
    grid = []
    for m in model_ids():
        cells, tot_d, tot_n = {}, 0, 0
        for a in arms:
            r = store.q1("SELECT SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) d, COUNT(*) n FROM cells WHERE model=? AND arm=?", (m, a))
            cells[a] = f"{r['d'] or 0} / {r['n']}"
            tot_d += r["d"] or 0
            tot_n += r["n"]
        grid.append({"label": model_label(m), "cells": cells, "total": f"{tot_d} / {tot_n}"})
    recent = store.q1("SELECT COUNT(*) n, MIN(finished_at) t0 FROM cells WHERE status='done' AND finished_at > ?", (time.time() - 900,))
    left = total - done - failed
    eta, rate = "-", "no recent progress"
    if recent["n"] and recent["n"] > 1:
        per_s = recent["n"] / max(60.0, time.time() - recent["t0"])
        rate = f"{per_s * 60:.1f} cells per minute (last 15 min)"
        eta = time.strftime("%H:%M", time.localtime(time.time() + left / per_s)) if left else "done"
    stage = {
        "llm_wait": store.q1("SELECT COUNT(*) n FROM cells WHERE status IN ('pending','leased')")["n"],
        "llm_done": done,
        "judge_wait": store.q1("SELECT COUNT(*) n FROM cells WHERE status='done' AND judge_status='pending'")["n"],
        "judge_done": store.q1("SELECT COUNT(*) n FROM cells WHERE judge_status='done'")["n"],
        "test_wait": store.q1("SELECT COUNT(*) n FROM cells WHERE judge_status='done' AND test_status='pending'")["n"],
        "test_done": store.q1("SELECT COUNT(*) n FROM cells WHERE test_status='done'")["n"]}
    models = []
    for m in MODELS["models"]:
        r = store.q1("SELECT COUNT(*) n, SUM(ok) ok, SUM(prompt_tokens) tin, SUM(completion_tokens) tout, SUM(cost_usd) cost "
                     "FROM calls WHERE model=?", (m["id"],))
        e = store.q1("SELECT error FROM calls WHERE model=? AND ok=0 ORDER BY id DESC LIMIT 1", (m["id"],))
        models.append({"label": m["label"], "host": ", ".join(m.get("provider_order") or ["any"]), "n": r["n"],
                       "ok": r["ok"] or 0, "tin": r["tin"] or 0, "tout": r["tout"] or 0, "cost": r["cost"] or 0.0,
                       "err": (e["error"][:160] if e else "")})
    events = [{"t": _fmt_t(e["ts"]), "level": e["level"], "msg": e["msg"][:400]}
              for e in store.q("SELECT * FROM events ORDER BY id DESC LIMIT 50")]
    cur = store.q1("SELECT MIN(rep) r FROM cells WHERE status IN ('pending','leased')")["r"]
    return page("Run", T.RUN, "/", refresh=10, state=runner.state(), pid=runner.runner_pid(), done=done, total=total,
                pct=f"{100 * done / total:.1f}%" if total else "", spend=runner.spend(), cap=STUDY["max_spend_usd"],
                eta=eta, rate=rate, failed=failed, arms=arms, grid=grid, stage=stage, models=models, events=events,
                cur_rep=cur, reps_done=", ".join(str(r) for r in report._reps_complete()))


@app.route("/control", methods=["POST"])
def control():
    a = request.form.get("action")
    if a == "start" and not runner.runner_pid():
        log = open(os.path.join(RUN_DIR, "runner.log"), "a", encoding="utf-8")
        flags = (subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008) if os.name == "nt" else 0
        subprocess.Popen([sys.executable, "-m", "leblanc", "run"], cwd=ROOT, stdout=log, stderr=log,
                         stdin=subprocess.DEVNULL, creationflags=flags, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        store.event("start requested from the web page")
        time.sleep(2)
    elif a in ("pause", "stop"):
        store.set_control("state", "paused" if a == "pause" else "stopping")
        store.event(f"{a} requested from the web page")
    return redirect("/")


# ------------------------------------------------------------------ Results
STRAT_STYLE = [  # Okabe-Ito colour-blind-safe palette; plain is a larger hollow ring so overlaps stay visible
    ("plain", "#000000", "ring"), ("generic", "#E69F00", "dot"), ("targeted", "#0072B2", "dot"),
    ("plain+scan_repair", "#009E73", "square"), ("plain+blind_repair", "#D55E00", "square"),
    ("plain+resample", "#CC79A7", "diamond")]


def _mark(shape, x, y, color):
    if shape == "ring":
        return f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="none" stroke="{color}" stroke-width="2"/>'
    if shape == "square":
        return f'<rect x="{x - 5:.1f}" y="{y - 5:.1f}" width="10" height="10" fill="{color}"/>'
    if shape == "diamond":
        return f'<path d="M{x:.1f},{y - 7:.1f} L{x + 7:.1f},{y:.1f} L{x:.1f},{y + 7:.1f} L{x - 7:.1f},{y:.1f} Z" fill="{color}"/>'
    return f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5.5" fill="{color}"/>'


def _chart(points):
    pts = [p for p in points if p["rate"] is not None]
    if not pts:
        return ""
    models = []
    for p in pts:
        if p["model"] not in models:
            models.append(p["model"])
    style = {n: (c, sh) for n, c, sh in STRAT_STYLE}
    xmax = max(p["tokens"] for p in pts) * 1.1 or 1
    W, H, L, B, Tm, R = 440, 330, 60, 52, 34, 24
    legend = ['<div style="display:flex;flex-wrap:wrap;gap:8px 26px;margin:10px 0 18px">']
    for n, c, sh in STRAT_STYLE:
        legend.append(f'<span style="display:inline-flex;align-items:center;gap:8px"><svg width="20" height="20">'
                      f'{_mark(sh, 10, 10, c)}</svg>{html.escape(n)}</span>')
    legend.append("</div>")
    out = ["".join(legend), '<div style="display:flex;flex-wrap:wrap;gap:36px 56px">']
    for m in models:
        s = [f'<svg width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="{html.escape(m)}">',
             f'<text x="{L}" y="18" font-size="15" font-weight="700">{html.escape(m)}</text>']
        for i in range(5):
            y = Tm + (H - Tm - B) * (1 - i / 4)
            s.append(f'<line x1="{L}" x2="{W - R}" y1="{y:.1f}" y2="{y:.1f}" stroke="#e4e4e4"/>')
            s.append(f'<text x="{L - 8}" y="{y + 4:.1f}" font-size="12" text-anchor="end" fill="#555">{i * 25}%</text>')
        for i in range(5):
            x = L + (W - L - R) * i / 4
            s.append(f'<text x="{x:.1f}" y="{H - B + 18}" font-size="12" text-anchor="middle" fill="#555">{xmax * i / 4:,.0f}</text>')
        s.append(f'<line x1="{L}" x2="{L}" y1="{Tm}" y2="{H - B}" stroke="#111"/>'
                 f'<line x1="{L}" x2="{W - R}" y1="{H - B}" y2="{H - B}" stroke="#111"/>')
        s.append(f'<text x="{(L + W - R) / 2}" y="{H - 10}" font-size="12" text-anchor="middle" fill="#555">mean tokens per task attempt</text>')
        s.append(f'<text transform="translate(14,{(Tm + H - B) / 2}) rotate(-90)" font-size="12" text-anchor="middle" fill="#555">secure and works</text>')
        for n, c, sh in reversed(STRAT_STYLE):
            for p in [p for p in pts if p["model"] == m and p["strategy"] == n]:
                x = L + (W - L - R) * p["tokens"] / xmax
                y = Tm + (H - Tm - B) * (1 - p["rate"])
                s.append(f'<g><title>{html.escape(n)}: {100 * p["rate"]:.1f}% at {p["tokens"]:,.0f} tokens</title>{_mark(sh, x, y, c)}</g>')
        s.append("</svg>")
        out.append("".join(s))
    out.append("</div>")
    return "".join(out)


@app.route("/results")
def results_page():
    if time.time() - _cache["t"] > 20 or _cache["res"] is None:
        res = report.results()
        res["engine_a"] = report.engine_a_eval()
        _cache.update(t=time.time(), res=res)
    res = _cache["res"]
    pts = next((s.get("points") for s in res["sections"] if s["id"] == "RQ5"), [])
    return page("Results", T.RESULTS, "/results", meta=res["meta"], sections=res["sections"], chart=_chart(pts),
                engine_a=res["engine_a"])


# ------------------------------------------------------------------ Runs and cell detail
@app.route("/runs")
def runs_page():
    fields = {"model": "model", "arm": "arm", "kind": "kind", "task": "task_id", "rep": "rep", "status": "status",
              "extract": "extract", "functional": "fpl_result", "security": "spl_result", "scanner": "vuln_task"}
    where, args = [], []
    for k, col in fields.items():
        v = request.args.get(k)
        if v:
            where.append(f"{col}=?")
            args.append(int(v) if col in ("rep", "vuln_task") else v)
    sql = " WHERE " + " AND ".join(where) if where else ""
    n = store.q1(f"SELECT COUNT(*) n FROM cells{sql}", args)["n"]
    rows = store.q(f"SELECT * FROM cells{sql} ORDER BY ord LIMIT 500", args)
    opts = lambda col: [r["v"] for r in store.q(f"SELECT DISTINCT {col} v FROM cells WHERE {col} IS NOT NULL ORDER BY 1")]
    filters = [(k, opts(col)) for k, col in fields.items()]
    return page("Runs", T.RUNS, "/runs", rows=rows, n=n, filters=filters, args=request.args)


def _code_rows(code, hit_lines=(), scaf=()):
    return [(i, ln, "hit" if i in hit_lines else ("scaf" if i in scaf else ""))
            for i, ln in enumerate((code or "").splitlines(), 1)]


@app.route("/cell/<cid>")
def cell_page(cid):
    from .. import judge
    c = store.q1("SELECT * FROM cells WHERE id=?", (cid,))
    if not c:
        abort(404)
    task = task_map()[c["task_id"]]
    findings = store.q("SELECT * FROM findings WHERE cell_id=? ORDER BY line", (cid,))
    prompt_html = html.escape(c["prompt_sent"] or "")
    if c["added_text"]:
        e = html.escape(c["added_text"])
        prompt_html = prompt_html.replace(e, f"<mark>{e}</mark>")
    rounds = []
    prev = None
    base = store.q1("SELECT code FROM cells WHERE id=?", (c["base_cell"],)) if c["base_cell"] else None
    prev = base["code"] if base else None
    for r in store.q("SELECT * FROM repair_rounds WHERE cell_id=? ORDER BY round", (cid,)):
        diff = "".join(difflib.unified_diff((prev or "").splitlines(True), (r["code"] or "").splitlines(True),
                                            "before", f"after round {r['round']}"))
        rounds.append({"round": r["round"], "n_findings": r["n_findings"], "diff": diff or "(no change)"})
        prev = r["code"] or prev
    calls = store.q("SELECT * FROM calls WHERE cell_id=? ORDER BY id", (cid,))
    return page(cid, T.CELL, "/runs", c=c, task=task, sp_valid=task.get("sp_valid"), prompt_html=prompt_html, findings=findings, rounds=rounds,
                calls=calls, added_tokens=enrich.est_tokens(c["added_text"] or ""),
                code_rows=_code_rows(c["code"], {f["line"] for f in findings}, judge.scaffolding_lines(c["code"] or "")))


# ------------------------------------------------------------------ Audit
@app.route("/audit")
def audit_page():
    who = (request.args.get("who") or request.cookies.get("annotator") or "").strip()
    n = store.q1("SELECT COUNT(*) n FROM audit_sample")["n"]
    item, ctx, done = None, [], 0
    if who and n:
        done = store.q1("SELECT COUNT(*) n FROM audit WHERE annotator=?", (who,))["n"]
        item = store.q1("SELECT f.*, c.code, c.task_id FROM audit_sample s JOIN findings f ON f.id=s.finding_id "
                        "JOIN cells c ON c.id=f.cell_id WHERE s.finding_id NOT IN (SELECT finding_id FROM audit WHERE annotator=?) "
                        "ORDER BY s.finding_id LIMIT 1", (who,))
        if item:
            item["cwe"] = task_map()[item["task_id"]]["cwe"]
            rows = _code_rows(item["code"], {item["line"]})
            ctx = rows
    resp = app.make_response(page("Audit", T.AUDIT, "/audit", who=who, sample_n=n, item=item, ctx=ctx, done=done,
                                  summary=report.audit_summary()))
    if who:
        resp.set_cookie("annotator", who, max_age=3600 * 24 * 90)
    return resp


@app.route("/audit/draw", methods=["POST"])
def audit_draw():
    report.draw_audit_sample()
    return redirect("/audit")


@app.route("/audit/label", methods=["POST"])
def audit_label():
    who, fid, label = request.form["who"].strip(), int(request.form["fid"]), request.form["label"]
    if label in ("tp", "fp", "unsure") and who:
        store.x("INSERT OR REPLACE INTO audit(finding_id, annotator, label, note, ts) VALUES (?,?,?,?,?)",
                (fid, who, label, request.form.get("note", ""), time.time()))
    return redirect(f"/audit?who={who}")


# ------------------------------------------------------------------ Dataset and tasks
@app.route("/dataset", methods=["GET", "POST"])
def dataset_page():
    prompt = request.form.get("prompt", "") if request.method == "POST" else ""
    analysis = enrich.analyze(prompt) if prompt.strip() else None
    ex = json.load(open(os.path.join(ROOT, "data", "exclusions.json"), encoding="utf-8"))
    sample = enrich.warning_line("CWE-89")
    return page("Dataset", T.DATASET, "/dataset", tasks=load_tasks(), prompt=prompt, analysis=analysis,
                generic=STUDY["generic_line"], generic_tok=enrich.est_tokens(STUDY["generic_line"]), example=sample,
                example_tok=enrich.est_tokens(sample), excluded=ex["excluded"])


@app.route("/task/<tid>")
def task_page(tid):
    t = task_map().get(tid) or abort(404)
    return page(tid, T.TASK, "/dataset", t=t, warning=enrich.warning_line(t["cwe"]))


# ------------------------------------------------------------------ Setup
_check = {}


@app.route("/setup")
def setup_page():
    keys = [(MODELS["key_env"], bool(get_key(MODELS["key_env"])))]
    return page("Setup", T.SETUP, "/setup", keys=keys, models=MODELS["models"], prices=PRICES["usd_per_million_tokens"],
                pin_note=MODELS.get("pinning_note", ""), hash=study_hash(), db_hash=store.get_meta("study_hash"),
                study=STUDY, study_json=json.dumps(STUDY, indent=1), check=_check.get("last"))


@app.route("/setup/selfcheck", methods=["POST"])
def setup_selfcheck():
    from .. import selfcheck
    lines = []
    ok = selfcheck.run(verbose=False, out=lines.append)
    _check["last"] = {"title": "Selfcheck: " + ("all checks passed" if ok else "FAILED"), "text": "\n".join(lines)}
    return redirect("/setup")


@app.route("/setup/preflight", methods=["POST"])
def setup_preflight():
    from .. import preflight
    _check["last"] = {"title": "Preflight", "text": json.dumps(preflight.run(), indent=1)}
    return redirect("/setup")


# ------------------------------------------------------------------ Export
EXPORT_DIR = os.path.join(RUN_DIR, "export")


@app.route("/export", methods=["GET", "POST"])
def export_page():
    if request.method == "POST":
        report.export()
        return redirect("/export")
    files = []
    if os.path.isdir(EXPORT_DIR):
        files = [(f, f"{os.path.getsize(os.path.join(EXPORT_DIR, f)):,} bytes") for f in sorted(os.listdir(EXPORT_DIR))]
    return page("Export", T.EXPORT, "/export", files=files)


@app.route("/export/<path:name>")
def export_file(name):
    return send_from_directory(EXPORT_DIR, name, as_attachment=True)


def serve(port=8765):
    print(f"LeBlanc UI: http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
