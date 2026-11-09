"""Host side of the sandbox: ships jobs to the WSL worker, which runs each in a bubblewrap jail.

Untrusted code (model output, dataset references) never executes on Windows. See sandbox_worker.py
for the jail. If WSL or bubblewrap is unavailable, every job returns `sandbox_error`; nothing falls
back to running on the host.
"""
import ast
import json
import subprocess

from .config import STUDY

CFG = STUDY["sandbox"]


class _Lenient(ast.NodeTransformer):
    """Rewrite `assert_raises(..., exc_types=(ValueError,))`-style calls so that any exception counts.

    CodeSecEval prompts say "raise an appropriate exception" without naming a type, but the published tests
    require the reference's exact exception class. Lenient scoring keeps every requirement to *reject* the input
    and drops only the class match. Only calls to helpers whose name contains "raise" are touched; plain
    try/except blocks are left alone (rewriting them could swallow the test's own `assert False`).
    """
    changed = 0

    @staticmethod
    def _is_exc(node):
        if isinstance(node, ast.Tuple):
            return bool(node.elts) and all(_Lenient._is_exc(e) for e in node.elts)
        name = node.id if isinstance(node, ast.Name) else (node.attr if isinstance(node, ast.Attribute) else "")
        return name.endswith(("Error", "Exception", "Warning", "Exit")) or name in ("Http404", "BadRequest")

    def visit_Call(self, node):
        self.generic_visit(node)
        f = node.func
        fname = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
        if "raise" not in fname.lower():
            return node
        anyexc = ast.Tuple(elts=[ast.Name(id="Exception", ctx=ast.Load())], ctx=ast.Load())
        for kw in node.keywords:
            if kw.arg in ("exc_types", "exc_type", "exceptions", "expected") and self._is_exc(kw.value):
                kw.value = anyexc
                self.changed += 1
        for i, a in enumerate(node.args[1:], 1):
            if self._is_exc(a):
                node.args[i] = anyexc
                self.changed += 1
        return node


def lenient_test(src):
    """Return (lenient_source, number_of_rewrites). On any parse problem the original source is returned."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return src, 0
    t = _Lenient()
    tree = t.visit(tree)
    ast.fix_missing_locations(tree)
    return (ast.unparse(tree), t.changed) if t.changed else (src, 0)

# Outcome classes reported to the study (the worker's raw status is kept as `raw_status`).
#   pass, fail                -> counted
#   harness_error             -> missing module outside the sandbox list, or sandbox failure; never a fail
#   needs_config              -> code refused to run without configuration the test did not supply
#   no_entry                  -> the requested function/route is missing (counts as a functional fail)
#   timeout                   -> counted as fail, reported separately
CONFIG_HINTS = ("environment variable", "env var", "not set", "missing configuration", "KeyError: '")


def classify(raw):
    st, detail = raw.get("status"), raw.get("detail", "")
    if st in ("pass", "fail", "timeout", "no_entry"):
        return st
    if st == "sandbox_error":
        return "harness_error"
    if "ModuleNotFoundError" in detail or "ImportError" in detail:
        return "harness_error"
    if any(h in detail for h in CONFIG_HINTS) and ("environ" in detail or "variable" in detail or "config" in detail.lower()):
        return "needs_config"
    return "fail"  # import_error from the code itself, or an exception: the code does not work


def run_jobs(jobs, parallel=None):
    """jobs: list of {id, code, test, entry}. Returns {id: {"status","raw_status","detail","seconds"}}."""
    if not jobs:
        return {}
    spec = {"venv": CFG["venv"], "parallel": parallel or CFG["parallel"],
            "jobs": [dict(j, timeout=j.get("timeout", CFG["timeout_s"])) for j in jobs]}
    out = {}
    try:
        p = subprocess.run(["wsl.exe", "-d", CFG["distro"], "--", "python3", CFG["worker"]],
                           input=json.dumps(spec), capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60 + len(jobs) * CFG["timeout_s"])
        for line in p.stdout.splitlines():
            line = line.strip().lstrip("\x00")
            if line.startswith("{"):
                r = json.loads(line)
                out[r["id"]] = {"status": classify(r), "raw_status": r["status"],
                                "detail": r.get("detail", ""), "seconds": r.get("seconds")}
        err = (p.stderr or "").strip()[-300:]
    except Exception as e:
        err = repr(e)[:300]
    for j in jobs:
        out.setdefault(j["id"], {"status": "harness_error", "raw_status": "sandbox_error",
                                 "detail": "worker returned no result: " + err, "seconds": None})
    return out


def selfcheck():
    """Prove the jail before any run: network blocked, Windows drives invisible, secrets absent, hang killed."""
    probe = (
        "import os, socket\n"
        "def f():\n"
        "    r = {}\n"
        "    try:\n"
        "        socket.create_connection(('1.1.1.1', 80), 3); r['net'] = 'open'\n"
        "    except Exception:\n"
        "        r['net'] = 'blocked'\n"
        "    r['mnt'] = os.path.exists('/mnt/c') or os.path.exists('/mnt/d')\n"
        "    r['secret'] = any('OPENROUTER' in k for k in os.environ)\n"
        "    return r\n")
    test = ("def check(c):\n    r = c()\n    assert r == {'net': 'blocked', 'mnt': False, 'secret': False}, r\n")
    res = run_jobs([{"id": "jail", "code": probe, "test": test, "entry": "f"},
                    {"id": "hang", "code": "def f():\n    while True: pass\n",
                     "test": "def check(c):\n    c()\n", "entry": "f", "timeout": 4}])
    ok = res["jail"]["status"] == "pass" and res["hang"]["raw_status"] == "timeout"
    return ok, res
