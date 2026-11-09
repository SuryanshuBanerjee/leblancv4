"""Command line: python -m leblanc <command>.

  plan          create all cells (idempotent)
  run           run until done, paused, stopped or the spend cap is reached (resumable)
  start         start the runner in the background (detached; survives closing this window)
  pause         workers finish their current call, then stop; `start` resumes
  stop          same as pause, recorded as a stop
  status        progress, spend, state
  preflight     one real call per model
  selfcheck     every offline check (no API calls)
  web           the UI at http://127.0.0.1:8765
  export        CSV/JSON/LaTeX tables into run/export/
  audit-sample  draw the frozen false-positive audit sample
  engine-a-eval evaluate Engine A retrieval on held-out tasks (offline)
"""
import argparse
import json
import os
import subprocess
import sys

from . import store
from .config import ROOT, STUDY


def cmd_status(_):
    from . import runner
    rows = store.q("SELECT kind, status, COUNT(*) n FROM cells GROUP BY kind, status ORDER BY kind, status")
    print("state:", runner.state(), "| runner pid:", runner.runner_pid())
    print(f"spend: ${runner.spend():.4f} of ${STUDY['max_spend_usd']}")
    for r in rows:
        print(f"  {r['kind']:13s} {r['status']:8s} {r['n']}")
    j = store.q("SELECT judge_status, test_status, COUNT(*) n FROM cells WHERE status='done' GROUP BY 1,2")
    for r in j:
        print(f"  judged={r['judge_status']:8s} tested={r['test_status']:8s} {r['n']}")


def cmd_start(_):
    from . import runner
    if runner.runner_pid():
        print("already running, pid", runner.runner_pid())
        return
    log = open(os.path.join(ROOT, "run", "runner.log"), "a", encoding="utf-8")
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED_PROCESS
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    p = subprocess.Popen([sys.executable, "-m", "leblanc", "run"], cwd=ROOT, stdout=log, stderr=log,
                         stdin=subprocess.DEVNULL, creationflags=flags, env=env, close_fds=True)
    print("runner started, pid", p.pid, "- log: run/runner.log")


def _ids(a):
    return [x.strip() for x in a.task_ids.split(",")] if getattr(a, "task_ids", None) else None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="leblanc", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command")
    ap.add_argument("--reps", type=int)
    ap.add_argument("--tasks", type=int, help="plan only the first N tasks (dry runs)")
    ap.add_argument("--task-ids", help="comma-separated task ids to plan (dry runs)")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args(argv)
    c = a.command
    if c == "plan":
        from . import runner
        print("cells:", runner.plan(reps=a.reps, task_limit=a.tasks, task_ids=_ids(a)))
    elif c == "run":
        from . import runner
        if a.tasks or a.reps or a.task_ids:
            runner.plan(reps=a.reps, task_limit=a.tasks, task_ids=_ids(a))
        runner.run()
        cmd_status(a)
    elif c == "start":
        cmd_start(a)
    elif c in ("pause", "stop"):
        store.set_control("state", "paused" if c == "pause" else "stopping")
        store.event(f"{c} requested")
        print(f"{c} requested; workers stop after their current call")
    elif c == "status":
        cmd_status(a)
    elif c == "preflight":
        from . import preflight
        print(json.dumps(preflight.run(), indent=1))
    elif c == "selfcheck":
        from . import selfcheck
        ok = selfcheck.run(verbose=True)
        sys.exit(0 if ok else 1)
    elif c == "web":
        from .web.app import serve
        serve(a.port)
    elif c == "export":
        from . import report
        print("written to", report.export())
    elif c == "audit-sample":
        from . import report
        print("sample size:", report.draw_audit_sample())
    elif c == "engine-a-eval":
        from . import report
        print(json.dumps(report.engine_a_eval(), indent=1))
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
