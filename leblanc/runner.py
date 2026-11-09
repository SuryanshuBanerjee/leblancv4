"""Resumable runner.

Cells are rows. Workers lease a cell, do it, and mark it done; a crash or Ctrl-C leaves leases that are
returned to `pending` on the next start, so nothing is lost or duplicated. Repetition is the outermost
loop: no cell of repetition r+1 is started while a cell of repetition r is unfinished, so an interrupted
run is always a balanced dataset with fewer repetitions.

Three stages run concurrently:
  LLM workers   per-model thread pools: generation, scan_repair (inline judging), blind_repair
  judge thread  batches finished cells through Bandit + Semgrep
  test thread   batches judged cells through the sandbox (Test-FP and Test-SP)
"""
import json
import os
import threading
import time
import traceback

from . import enrich, judge, llm, sandbox, store
from .config import PRICES, RUN_DIR, STUDY, model_ids, model_label, study_hash
from .dataset import load_tasks, task_map

LOCK_FILE = os.path.join(RUN_DIR, "runner.lock")
LEASE_S = 900
PER_MODEL_THREADS = int(os.environ.get("LEBLANC_THREADS", STUDY.get("threads_per_model", 4)))
MAX_ATTEMPTS = 3
_claim_lock = threading.Lock()


# ------------------------------------------------------------------ planning
def cell_id(rep, task_id, model, arm):
    return f"r{rep}.{task_id}.{model_label(model)}.{arm}"


def plan(reps=None, task_limit=None, task_ids=None):
    tasks = load_tasks()[:task_limit] if task_limit else load_tasks()
    if task_ids:
        tasks = [t for t in tasks if t["id"] in set(task_ids)]
    reps = reps or STUDY["reps"]
    sh = study_hash()
    prev = store.get_meta("study_hash")
    n_existing = store.q1("SELECT COUNT(*) n FROM cells")["n"]
    if prev and prev != sh and n_existing:
        raise SystemExit(f"Study definition changed since this database was planned ({prev} -> {sh}). "
                         "Use a new database (set LEBLANC_DB) instead of mixing designs.")
    rows, ordn = [], 0
    now = time.time()
    for rep in range(1, reps + 1):
        for kind_order, kinds in ((0, STUDY["arms"]), (1, STUDY["repair_arms"])):
            for t in tasks:
                for m in model_ids():
                    for arm in kinds:
                        ordn += 1
                        kind = "gen" if kind_order == 0 else arm
                        base = cell_id(rep, t["id"], m, STUDY["repair_base_arm"]) if kind_order else None
                        rows.append((cell_id(rep, t["id"], m, arm), kind, t["id"], m, arm, rep, base,
                                     rep * 1_000_000 + ordn, now))
    store.xmany("INSERT OR IGNORE INTO cells(id, kind, task_id, model, arm, rep, base_cell, ord, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)", rows)
    store.set_meta("study_hash", sh)
    store.set_meta("planned", {"reps": reps, "tasks": len(tasks), "models": model_ids(),
                               "arms": STUDY["arms"], "repair_arms": STUDY["repair_arms"], "at": now})
    store.event(f"planned {len(rows)} cells ({len(tasks)} tasks x {len(model_ids())} models, {reps} reps)")
    return len(rows)


# ------------------------------------------------------------------ control
def spend():
    r = store.q1("SELECT COALESCE(SUM(cost_usd),0) s, COUNT(*) n FROM calls")
    return r["s"] or 0.0


def state():
    return store.get_control("state", "idle")


def _should_stop():
    return state() in ("paused", "stopping", "idle")


def _record_call(cell_id_, rnd):
    def rec(a):
        store.x("INSERT INTO calls(cell_id, round, model, provider, ok, http_status, error, prompt_tokens, "
                "completion_tokens, reasoning_tokens, cost_usd, latency_s, finish_reason, retries, temperature, "
                "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cell_id_, rnd, a["model"], a.get("provider"), a["ok"], a.get("http_status"), a.get("error"),
                 a.get("prompt_tokens"), a.get("completion_tokens"), a.get("reasoning_tokens"),
                 a.get("cost_usd") if a.get("cost_usd") is not None else _est_cost(a),
                 a.get("latency_s"), a.get("finish_reason"), a.get("retries"), a.get("temperature"),
                 a.get("created_at")))
    return rec


def _est_cost(a):
    p = PRICES["usd_per_million_tokens"].get(a["model"])
    if not p or a.get("prompt_tokens") is None:
        return 0.0
    return ((a.get("prompt_tokens") or 0) * p["input"] + (a.get("completion_tokens") or 0) * p["output"]) / 1e6


def _add_usage(cell, res):
    cell["tokens_in"] += res.get("prompt_tokens") or 0
    cell["tokens_out"] += res.get("completion_tokens") or 0
    cell["tokens_reasoning"] += res.get("reasoning_tokens") or 0
    cell["cost_usd"] += res.get("cost_usd") or 0.0
    cell["latency_s"] += res.get("latency_s") or 0.0
    cell["n_calls"] += 1
    cell["provider"] = res.get("provider")


def _check_budget():
    s = spend()
    if s >= STUDY["max_spend_usd"]:
        if state() == "running":
            store.set_control("state", "stopping")
            store.event(f"spend cap reached: ${s:.4f} >= ${STUDY['max_spend_usd']}; stopping", "warn")
        return False
    return True


# ------------------------------------------------------------------ claiming
def _current_rep():
    r = store.q1("SELECT MIN(rep) r FROM cells WHERE status IN ('pending','leased')")
    return r["r"]


def _claim(model):
    with _claim_lock:
        rep = _current_rep()
        if rep is None:
            return None
        now = time.time()
        cands = store.q(
            "SELECT c.* FROM cells c LEFT JOIN cells b ON b.id = c.base_cell "
            "WHERE c.status='pending' AND c.model=? AND c.rep=? AND COALESCE(c.lease_until,0) <= ? AND ("
            " c.kind='gen' OR (c.kind='blind_repair' AND b.status IN ('done','failed')) OR "
            " (c.kind='scan_repair' AND b.status IN ('done','failed') AND b.judge_status IN ('done','na','error'))"
            ") ORDER BY c.ord LIMIT 1", (model, rep, now))
        if not cands:
            return None
        c = cands[0]
        store.update_cell(c["id"], status="leased", lease_until=now + LEASE_S, attempts=c["attempts"] + 1)
        c["attempts"] += 1
        return c


# ------------------------------------------------------------------ cell execution
def _messages(user_text):
    return [{"role": "system", "content": STUDY["system_prompt"]}, {"role": "user", "content": user_text}]


def _fresh_usage():
    return {"tokens_in": 0, "tokens_out": 0, "tokens_reasoning": 0, "cost_usd": 0.0, "latency_s": 0.0,
            "n_calls": 0, "provider": None}


def _finish(cell_id_, **f):
    f.update(status="done", finished_at=time.time(), lease_until=None, last_error=None)
    store.update_cell(cell_id_, **f)


def run_gen(c, task):
    prompt, extra = enrich.build_prompt(c["arm"], task)
    u = _fresh_usage()
    res = llm.chat(c["model"], _messages(prompt), on_attempt=_record_call(c["id"], 0))
    _add_usage(u, res)
    status, code = judge.extract(res["content"], res["finish_reason"])
    stripped = judge.strip_scaffolding(code)[0] if status == "ok" else None
    na = status != "ok"
    _finish(c["id"], prompt_sent=prompt, added_text=extra, added_chars=len(extra), response_text=res["content"],
            finish_reason=res["finish_reason"], extract=status, code=code or None, code_stripped=stripped,
            judge_status="na" if na else "pending", test_status="na" if na else "pending", **u)


def _repair_prompt(instruction, task, code, findings=None):
    parts = [instruction, "", "Original task:", task["prompt"].strip(), ""]
    if findings is not None:
        parts += ["Analyser findings:"]
        for f in findings:
            parts.append(f"- line {f['line']}: [{f['tool']} {f['rule']}, {', '.join(f['cwes'])}] {f['message']}")
        parts.append("")
    parts += ["Code:", "```python", code.rstrip(), "```"]
    return "\n".join(parts)


def _copy_base(c, base, **extra):
    fields = {k: base[k] for k in ("code", "code_stripped", "vuln_task", "vuln_raw", "vuln_bandit", "vuln_semgrep",
                                   "vuln_target", "n_findings")}
    _finish(c["id"], extract=base["extract"] if base["extract"] else "no_base", judge_status="done",
            test_status="pending", **fields, **extra)


def run_blind(c, task, base):
    if base["status"] != "done" or base["extract"] != "ok":
        _finish(c["id"], extract="no_base", judge_status="na", test_status="na", repair_outcome="no_base")
        return
    u = _fresh_usage()
    prompt = _repair_prompt(STUDY["blind_repair_instruction"], task, base["code"])
    res = llm.chat(c["model"], _messages(prompt), on_attempt=_record_call(c["id"], 1))
    _add_usage(u, res)
    status, code = judge.extract(res["content"], res["finish_reason"])
    ok = status == "ok"
    _finish(c["id"], prompt_sent=prompt, response_text=res["content"], finish_reason=res["finish_reason"],
            extract=status, code=code or None, code_stripped=judge.strip_scaffolding(code)[0] if ok else None,
            rounds=1, repair_outcome="done" if ok else "broke_extraction",
            judge_status="pending" if ok else "na", test_status="pending" if ok else "na", **u)


def run_scan_repair(c, task, base):
    if base["status"] != "done" or base["extract"] != "ok" or base["judge_status"] != "done":
        _finish(c["id"], extract="no_base", judge_status="na", test_status="na", repair_outcome="no_base")
        return
    if not base["vuln_task"]:
        _copy_base(c, base, rounds=0, repair_outcome="not_needed")
        return
    code = base["code"]
    findings = [dict(f, cwes=json.loads(f["cwes"])) for f in store.q(
        "SELECT * FROM findings WHERE cell_id=? AND on_scaffolding=0", (base["id"],))]
    u = _fresh_usage()
    store.x("DELETE FROM repair_rounds WHERE cell_id=?", (c["id"],))
    outcome, last_status, last_res, verdict, final_findings = "not_converged", "ok", None, None, findings
    for rnd in range(1, STUDY["scan_repair_max_rounds"] + 1):
        prompt = _repair_prompt(STUDY["scan_repair_instruction"], task, code, findings)
        res = llm.chat(c["model"], _messages(prompt), on_attempt=_record_call(c["id"], rnd))
        _add_usage(u, res)
        last_res = res
        last_status, new_code = judge.extract(res["content"], res["finish_reason"])
        if last_status != "ok":
            outcome = "broke_extraction"
            store.x("INSERT OR REPLACE INTO repair_rounds VALUES (?,?,?,?,?)", (c["id"], rnd, new_code, None, None))
            break
        code = new_code
        fs = judge.scan_batch({"k": code})["k"]
        verdict = judge.verdicts(fs, task["cwe"])
        findings = [f for f in fs if not f["on_scaffolding"]]
        final_findings = fs
        store.x("INSERT OR REPLACE INTO repair_rounds VALUES (?,?,?,?,?)",
                (c["id"], rnd, code, len(findings), json.dumps(findings)))
        c["rounds_done"] = rnd
        if not verdict["vuln_task"]:
            outcome = "fixed"
            break
    rounds = store.q1("SELECT MAX(round) r FROM repair_rounds WHERE cell_id=?", (c["id"],))["r"] or 0
    if outcome == "broke_extraction":
        _finish(c["id"], prompt_sent=prompt, response_text=last_res["content"], finish_reason=last_res["finish_reason"],
                extract=last_status, code=None, code_stripped=None, rounds=rounds, repair_outcome=outcome,
                judge_status="na", test_status="na", **u)
        return
    _save_findings(c["id"], final_findings)
    _finish(c["id"], prompt_sent=prompt, response_text=last_res["content"], finish_reason=last_res["finish_reason"],
            extract="ok", code=code, code_stripped=judge.strip_scaffolding(code)[0], rounds=rounds,
            repair_outcome=outcome, judge_status="done", test_status="pending", **verdict, **u)


def _save_findings(cell_id_, fs):
    store.x("DELETE FROM findings WHERE cell_id=?", (cell_id_,))
    store.xmany("INSERT INTO findings(cell_id, round, which, tool, rule, cwes, severity, line, message, "
                "on_scaffolding, snippet) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(cell_id_, 0, "raw", f["tool"], f["rule"], json.dumps(f["cwes"]), f["severity"], f["line"],
                  f["message"], f["on_scaffolding"], f.get("snippet", "")) for f in fs])


def _llm_worker(model, tasks, stop_evt):
    while not stop_evt.is_set():
        if _should_stop() or not _check_budget():
            return
        c = _claim(model)
        if c is None:
            if store.q1("SELECT COUNT(*) n FROM cells WHERE model=? AND status IN ('pending','leased')",
                        (model,))["n"] == 0:
                return
            time.sleep(2)
            continue
        task = tasks[c["task_id"]]
        try:
            if c["kind"] == "gen":
                run_gen(c, task)
            else:
                base = store.q1("SELECT * FROM cells WHERE id=?", (c["base_cell"],))
                (run_blind if c["kind"] == "blind_repair" else run_scan_repair)(c, task, base)
        except llm.FatalLLMError as e:
            store.update_cell(c["id"], status="pending", lease_until=None, attempts=c["attempts"] - 1,
                              last_error=str(e)[:300])
            store.event(f"fatal provider error, stopping: {e}", "error")
            store.set_control("state", "stopping")
            return
        except llm.CallFailed as e:
            final = c["attempts"] >= MAX_ATTEMPTS
            store.update_cell(c["id"], status="failed" if final else "pending",
                              lease_until=None if final else time.time() + 300, last_error=str(e)[:300])
            store.event(f"{c['id']}: call failed after retries ({'gave up' if final else 'will retry'}): {e}", "warn")
        except Exception as e:  # a bug, not a model outcome: retry later, never record as a result
            store.update_cell(c["id"], status="pending" if c["attempts"] < MAX_ATTEMPTS else "failed",
                              lease_until=time.time() + 60, last_error=f"{type(e).__name__}: {e}"[:300])
            store.event(f"{c['id']}: internal error {type(e).__name__}: {e}\n{traceback.format_exc()[-600:]}", "error")


# ------------------------------------------------------------------ judge and test stages
def judge_pending(limit=80):
    rows = store.q("SELECT c.id, c.code, c.task_id FROM cells c WHERE c.status='done' AND c.judge_status='pending' "
                   "AND c.extract='ok' ORDER BY c.ord LIMIT ?", (limit,))
    if not rows:
        return 0
    tasks = task_map()
    try:
        res = judge.scan_batch({r["id"]: r["code"] for r in rows})
    except Exception as e:
        store.event(f"judge batch failed (will retry): {e}", "warn")
        time.sleep(10)
        return 0
    for r in rows:
        fs = res[r["id"]]
        _save_findings(r["id"], fs)
        store.update_cell(r["id"], judge_status="done", **judge.verdicts(fs, tasks[r["task_id"]]["cwe"]))
    return len(rows)


def test_pending(limit=40):
    rows = store.q("SELECT id, code_stripped, task_id FROM cells WHERE status='done' AND judge_status='done' "
                   "AND test_status='pending' AND code_stripped IS NOT NULL ORDER BY ord LIMIT ?", (limit,))
    if not rows:
        return 0
    tasks = task_map()
    jobs = []
    for r in rows:
        t = tasks[r["task_id"]]
        for suffix, field in (("fp", "test_fp"), ("sp", "test_sp"), ("fpl", "test_fp_lenient"), ("spl", "test_sp_lenient")):
            jobs.append({"id": r["id"] + "|" + suffix, "code": r["code_stripped"], "test": t[field], "entry": t["entry_point"]})
    res = sandbox.run_jobs(jobs)
    for r in rows:
        fp, sp, fpl, spl = (res[r["id"] + "|" + s] for s in ("fp", "sp", "fpl", "spl"))
        store.update_cell(r["id"], test_status="done", fp_result=fp["status"], sp_result=sp["status"],
                          fp_detail=fp["detail"][:600], sp_detail=sp["detail"][:600],
                          fpl_result=fpl["status"], spl_result=spl["status"],
                          fpl_detail=fpl["detail"][:600], spl_detail=spl["detail"][:600])
    return len(rows)


def _stage_loop(fn, stop_evt, can_exit):
    while not stop_evt.is_set():
        try:
            n = fn()
        except Exception as e:
            store.event(f"{fn.__name__} error: {type(e).__name__}: {e}", "error")
            n = 0
        if n == 0:
            if can_exit():
                if fn() == 0:
                    return
            time.sleep(3)


# ------------------------------------------------------------------ entry point
def _pid_alive(pid):
    try:
        import ctypes
        if os.name == "nt":
            h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if not h:
                return False
            code = ctypes.c_ulong()
            ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
            ctypes.windll.kernel32.CloseHandle(h)
            return code.value == 259
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def runner_pid():
    if os.path.exists(LOCK_FILE):
        try:
            pid = int(open(LOCK_FILE).read().strip())
            if _pid_alive(pid):
                return pid
        except Exception:
            pass
    return None


def _keep_awake(on):
    """Ask Windows not to sleep while this process runs (released automatically when it exits)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0))
    except Exception:
        pass


def run():
    if runner_pid():
        raise SystemExit(f"a runner is already active (pid {runner_pid()})")
    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))
    _keep_awake(True)
    try:
        if not store.q1("SELECT COUNT(*) n FROM cells")["n"]:
            plan()
        n = store.x("UPDATE cells SET status='pending', lease_until=NULL WHERE status='leased'").rowcount
        if n:
            store.event(f"recovered {n} interrupted cells")
        store.set_control("state", "running")
        store.set_meta("judge_provenance", judge.provenance())
        store.event(f"runner started (pid {os.getpid()}); spend so far ${spend():.4f} of ${STUDY['max_spend_usd']}")
        tasks = task_map()
        stop_evt, llm_done = threading.Event(), threading.Event()
        workers = [threading.Thread(target=_llm_worker, args=(m, tasks, stop_evt), daemon=True)
                   for m in model_ids() for _ in range(PER_MODEL_THREADS)]
        judge_t = threading.Thread(target=_stage_loop, args=(judge_pending, stop_evt, llm_done.is_set), daemon=True)
        test_t = threading.Thread(target=_stage_loop, daemon=True, args=(
            test_pending, stop_evt, lambda: llm_done.is_set() and not judge_t.is_alive()))
        stages = [judge_t, test_t]
        for t in workers + stages:
            t.start()
        try:
            for t in workers:
                while t.is_alive():
                    t.join(1)
                    store.set_meta("heartbeat", time.time())
            llm_done.set()
            for t in stages:
                while t.is_alive():
                    t.join(1)
                    store.set_meta("heartbeat", time.time())
        except KeyboardInterrupt:
            stop_evt.set()
            store.event("interrupted (Ctrl-C); leased cells will be recovered on restart", "warn")
        st = state()
        left = store.q1("SELECT COUNT(*) n FROM cells WHERE status IN ('pending','leased')")["n"]
        final = "paused" if st == "paused" else ("complete" if left == 0 else "stopped")
        store.set_control("state", "complete" if final == "complete" else ("paused" if final == "paused" else "idle"))
        store.event(f"runner exited: {final}; {left} cells remaining; spend ${spend():.4f}")
    finally:
        _keep_awake(False)
        try:
            os.remove(LOCK_FILE)
        except OSError:
            pass
