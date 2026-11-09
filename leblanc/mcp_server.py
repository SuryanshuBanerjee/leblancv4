"""LeBlanc MCP server (stdio). Thin wrappers over the same package the study uses; no logic of its own.

Register with Claude Code:
  claude mcp add leblanc-v4 -e PYTHONPATH=D:\\LYPROJECT\\v4 -- python -m leblanc.mcp_server

A scanner-clean verdict is never described as "secure": the analysers miss whole weakness classes.
"""
import json
import os

from mcp.server.fastmcp import FastMCP

from . import enrich, judge, llm, report, runner, store
from .config import STUDY, model_ids, model_label

mcp = FastMCP("leblanc-v4", instructions=(
    "LeBlanc: security checks for LLM-generated Python. analyze_prompt before generating code (returns warning text "
    "and its token cost); scan_code or audit_response after; repair_code to have a model fix findings (spends money, "
    "needs confirm_spend=true). results_summary and recommend report what the LeBlanc study measured. "
    "'No findings' means the analysers found nothing, not that the code is secure."))

WORKSPACE = os.path.realpath(os.environ.get("LEBLANC_WORKSPACE", os.getcwd()))
CAVEAT = "No findings means Bandit and Semgrep found nothing; it does not mean the code is secure."


def _scan(code):
    fs = judge.scan_batch({"c": code})["c"]
    task = [f for f in fs if not f["on_scaffolding"]]
    return {"findings": fs, "task_findings": len(task), "scaffolding_findings": len(fs) - len(task),
            "verdict": "flagged" if task else ("flagged only in scaffolding" if fs else "no findings"), "note": CAVEAT}


@mcp.tool()
def analyze_prompt(prompt: str, mode: str = "retrieve") -> str:
    """Security warning text to append to a coding prompt, and what it costs in tokens.

    mode: "retrieve" (at most 3 CWE warnings matched from the prompt, 80-token cap; may return none),
          "generic" (the study's one-line generic instruction).
    """
    if mode == "generic":
        t = STUDY["generic_line"]
        return json.dumps({"text": t, "tokens": enrich.est_tokens(t), "warnings": []}, indent=1)
    return json.dumps(enrich.analyze(prompt), indent=1)


@mcp.tool()
def scan_code(code: str) -> str:
    """Scan Python source with Bandit and Semgrep (pinned rules). Findings carry tool, rule, CWE, line,
    severity and whether they sit on scaffolding (app.run / __main__)."""
    try:
        compile(code, "code.py", "exec")
    except SyntaxError as e:
        return json.dumps({"error": f"code does not compile: {e}"})
    return json.dumps(_scan(code), indent=1)


@mcp.tool()
def audit_response(text: str) -> str:
    """Take a raw model reply: extract the first python block, check it compiles, and scan it."""
    status, code = judge.extract(text)
    if status != "ok":
        return json.dumps({"extraction": status})
    return json.dumps(dict(extraction="ok", code=code, **_scan(code)), indent=1)


@mcp.tool()
def scan_path(path: str) -> str:
    """Scan a .py file or a folder of .py files. Only paths inside the workspace are allowed."""
    p = os.path.realpath(path if os.path.isabs(path) else os.path.join(WORKSPACE, path))
    try:
        inside = os.path.commonpath([p, WORKSPACE]) == WORKSPACE
    except ValueError:  # different drives on Windows
        inside = False
    if not inside:
        return json.dumps({"error": f"path outside the workspace {WORKSPACE}"})
    files = [p] if os.path.isfile(p) else [os.path.join(r, f) for r, _, fs in os.walk(p) for f in fs if f.endswith(".py")]
    files = files[:200]
    items = {}
    for f in files:
        try:
            items[os.path.relpath(f, WORKSPACE)] = open(f, encoding="utf-8", errors="replace").read()
        except OSError:
            pass
    res = judge.scan_batch(items)
    return json.dumps({"files": len(items), "results": {k: v for k, v in res.items() if v}, "note": CAVEAT}, indent=1)


@mcp.tool()
def repair_code(code: str, model: str = "", mode: str = "scanner", confirm_spend: bool = False) -> str:
    """Ask a model to fix the code. mode "scanner" sends the analyser findings; "blind" asks it to look for
    vulnerabilities itself. Spends API credit: refuses unless confirm_spend is true. Returns the new code and its scan."""
    if not confirm_spend:
        return json.dumps({"refused": "this calls a paid model; call again with confirm_spend=true"})
    model = model or model_ids()[0]
    if model not in model_ids():
        return json.dumps({"error": f"unknown model; choose one of {model_ids()}"})
    before = _scan(code)
    task = {"prompt": "(not given)"}
    from .runner import _messages, _repair_prompt
    if mode == "scanner":
        fs = [f for f in before["findings"] if not f["on_scaffolding"]]
        if not fs:
            return json.dumps({"result": "nothing to repair", "scan": before})
        prompt = _repair_prompt(STUDY["scan_repair_instruction"], task, code, fs)
    else:
        prompt = _repair_prompt(STUDY["blind_repair_instruction"], task, code)
    res = llm.chat(model, _messages(prompt))
    status, new = judge.extract(res["content"], res["finish_reason"])
    out = {"model": model, "mode": mode, "extraction": status, "cost_usd": res["cost_usd"],
           "tokens": (res["prompt_tokens"] or 0) + (res["completion_tokens"] or 0), "before": before}
    if status == "ok":
        out.update(code=new, after=_scan(new))
    return json.dumps(out, indent=1)


@mcp.tool()
def project_status() -> str:
    """Progress of the LeBlanc study run: state, cells done, spend."""
    rows = store.q("SELECT kind, status, COUNT(*) n FROM cells GROUP BY kind, status")
    return json.dumps({"state": runner.state(), "runner_pid": runner.runner_pid(), "spend_usd": round(runner.spend(), 4),
                       "cap_usd": STUDY["max_spend_usd"], "cells": rows}, indent=1)


@mcp.tool()
def results_summary(model: str = "") -> str:
    """The study's headline numbers (computed from the database), optionally for one model label or id."""
    res = report.results()
    out = {"meta": res["meta"], "sections": []}
    for s in res["sections"]:
        if s["id"] == "VALIDITY":
            continue
        tables = []
        for t in s["tables"]:
            rows = [r for r in t["rows"] if not model or (r and str(r[0]) in (model, model_label(model)))]
            tables.append({"title": t["title"], "columns": t["columns"], "rows": rows})
        out["sections"].append({"id": s["id"], "question": s["question"], "sentence": s["sentence"], "tables": tables})
    return json.dumps(out, indent=1, default=str)


@mcp.tool()
def recommend(model: str) -> str:
    """Which strategy the measured results support for a model: the highest secure-and-works rate, preferring the
    cheaper strategy when two are within 2 percentage points. Says 'insufficient' when there is too little data."""
    res = report.results()
    rq5 = next(s for s in res["sections"] if s["id"] == "RQ5")
    label = model_label(model) if model in model_ids() else model
    pts = [p for p in rq5.get("points", []) if p["model"] == label and p["rate"] is not None]
    rows = [r for r in rq5["tables"][0]["rows"] if r[0] == label]
    if not pts or min(int(r[2]) for r in rows) < 30:
        return json.dumps({"model": label, "recommendation": "insufficient", "reason": "fewer than 30 attempts per strategy so far",
                           "measured": rows})
    best = max(pts, key=lambda p: p["rate"])
    near = [p for p in pts if best["rate"] - p["rate"] <= 0.02]
    pick = min(near, key=lambda p: p["tokens"])
    return json.dumps({"model": label, "recommendation": pick["strategy"],
                       "secure_and_works": round(pick["rate"], 3), "mean_tokens": round(pick["tokens"]),
                       "best_rate_strategy": best["strategy"], "measured": rows,
                       "note": "secure-and-works uses the dataset's own functional and security tests; see Results for intervals"},
                      indent=1)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
