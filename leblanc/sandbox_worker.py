"""Sandbox worker. Runs INSIDE WSL (Linux), outside the jail; it is trusted code.

Each job's untrusted code runs in its own bubblewrap jail:
  - no network (all namespaces unshared),
  - no Windows drives (/mnt is never mounted), no home directory,
  - read-only system and library directories, a fresh empty /work and /tmp,
  - empty environment except PATH, HOME and dummy configuration values,
  - CPU-time, memory, file-size and process-count limits, plus a wall-clock timeout.

Protocol: one JSON object on stdin {"venv": str, "parallel": int, "jobs": [job, ...]},
job = {"id": str, "code": str, "test": str, "entry": str, "timeout": int}.
Writes one JSON line per job to stdout: {"id", "status", "detail", "seconds"}.
status: pass | fail | error | import_error | no_entry | timeout | sandbox_error
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

MARK = "@@LEBLANC_RESULT@@"

DUMMY_ENV = {
    "DB_HOST": "localhost", "DB_USER": "app", "DB_PASSWORD": "dummy-password", "DB_NAME": "appdb",
    "SECRET_KEY": "dummy-secret-key-0123456789abcdef", "ENCRYPTION_KEY": "0123456789abcdef0123456789abcdef",
    "AES_KEY": "0123456789abcdef", "API_KEY": "dummy-api-key", "JWT_SECRET": "dummy-jwt-secret",
    "ADMIN_PASSWORD": "dummy-admin-password", "PASSWORD": "dummy-password",
}

HARNESS = r'''
import contextlib, io, json, resource, sys, traceback
MARK = "@@LEBLANC_RESULT@@"
real_out = sys.__stdout__
def emit(status, detail=""):
    real_out.write(MARK + json.dumps({"status": status, "detail": str(detail)[:600]}) + "\n")
    real_out.flush()
try:
    resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
except Exception:
    pass
sys.path.insert(0, "/work")
spec = json.load(open("/work/job.json", encoding="utf-8"))
sink = io.StringIO()
try:
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        import solution
except BaseException as e:
    emit("import_error", "%s: %s" % (type(e).__name__, e)); sys.exit(0)
cand = getattr(solution, spec["entry"], None)
if cand is None:
    emit("no_entry", "entry point %r not defined" % spec["entry"]); sys.exit(0)
ns = {"__name__": "leblanc_test"}
try:
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        exec(compile(spec["test"], "test.py", "exec"), ns)
        ns["check"](cand)
    emit("pass")
except AssertionError as e:
    tb = traceback.extract_tb(e.__traceback__)
    lineno = next((f.lineno for f in reversed(tb) if f.filename == "test.py"), None)
    src = spec["test"].splitlines()
    line = src[lineno - 1].strip() if lineno and 0 < lineno <= len(src) else ""
    emit("fail", "AssertionError: %s | at: %s" % (e, line))
except BaseException as e:
    emit("error", "%s: %s" % (type(e).__name__, e))
'''


def run_job(job, venv):
    t0 = time.time()
    work = tempfile.mkdtemp(prefix="lbsbx_")
    try:
        with open(os.path.join(work, "solution.py"), "w", encoding="utf-8") as f:
            f.write(job["code"])
        with open(os.path.join(work, "job.json"), "w", encoding="utf-8") as f:
            json.dump({"test": job["test"], "entry": job["entry"]}, f)
        with open(os.path.join(work, "_harness.py"), "w", encoding="utf-8") as f:
            f.write(HARNESS)
        py = os.path.join(venv, "bin", "python")
        cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
               "--ro-bind", "/usr", "/usr",
               "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
               "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
               "--ro-bind", venv, venv,
               "--bind", work, "/work", "--chdir", "/work",
               "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
               "--setenv", "PATH", venv + "/bin:/usr/bin:/bin",
               "--setenv", "HOME", "/work", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
               "--setenv", "PYTHONHASHSEED", "0", "--setenv", "LANG", "C.UTF-8"]
        for k, v in DUMMY_ENV.items():
            cmd += ["--setenv", k, v]
        cmd += [py, "-I", "/work/_harness.py"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=job.get("timeout", 30),
                               encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return {"id": job["id"], "status": "timeout", "detail": "", "seconds": round(time.time() - t0, 2)}
        res = None
        for line in p.stdout.splitlines():
            if line.startswith(MARK):
                res = json.loads(line[len(MARK):])
        if res is None:
            tail = (p.stderr or p.stdout).strip().splitlines()[-3:]
            status = "error" if p.returncode not in (None,) else "sandbox_error"
            res = {"status": status, "detail": "no result; exit %s; %s" % (p.returncode, " | ".join(tail))[:600]}
        res.update({"id": job["id"], "seconds": round(time.time() - t0, 2)})
        return res
    except Exception as e:  # infrastructure failure, never a model failure
        return {"id": job["id"], "status": "sandbox_error", "detail": repr(e)[:600],
                "seconds": round(time.time() - t0, 2)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    spec = json.load(sys.stdin)
    venv = spec["venv"]
    with ThreadPoolExecutor(max(1, int(spec.get("parallel", 8)))) as ex:
        for r in ex.map(lambda j: run_job(j, venv), spec["jobs"]):
            sys.stdout.write(json.dumps(r) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
