"""Paths and configuration. Every tunable lives in config/*.json; nothing is hard-coded elsewhere."""
import hashlib
import json
import os

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_DIR = os.path.join(ROOT, "config")
DATA_DIR = os.path.join(ROOT, "data")
RUN_DIR = os.path.join(ROOT, "run")
DB_PATH = os.environ.get("LEBLANC_DB", os.path.join(RUN_DIR, "leblanc.db"))
ENV_FILES = [os.path.join(ROOT, ".env"), os.path.join(os.path.dirname(ROOT), ".env")]

os.makedirs(RUN_DIR, exist_ok=True)


def _load(name):
    with open(os.path.join(CONFIG_DIR, name), encoding="utf-8") as f:
        return json.load(f)


STUDY = _load("study.json")
MODELS = _load("models.json")
PRICES = _load("prices.json")


def model_ids():
    return [m["id"] for m in MODELS["models"]]


def model_label(mid):
    for m in MODELS["models"]:
        if m["id"] == mid:
            return m["label"]
    return mid


def study_hash():
    """Hash of the frozen study definition: config files plus the task list."""
    h = hashlib.sha256()
    for name in ("study.json", "models.json"):
        with open(os.path.join(CONFIG_DIR, name), "rb") as f:
            h.update(f.read())
    for name in ("tasks.json", "tasks_lenient.json", "kb.json"):
        p = os.path.join(DATA_DIR, name)
        if os.path.exists(p):
            with open(p, "rb") as f:
                h.update(f.read())
    return h.hexdigest()[:16]


def get_key(name):
    """Read a secret from the environment or a .env file. Never logged, never returned to the UI."""
    if os.environ.get(name):
        return os.environ[name]
    for path in ENV_FILES:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.startswith(name + "="):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None
