"""The study's task list (data/tasks.json), produced by scripts/select_tasks.py."""
import json
import os
from functools import lru_cache

from .config import DATA_DIR

TASKS_PATH = os.path.join(DATA_DIR, "tasks.json")


LENIENT_PATH = os.path.join(DATA_DIR, "tasks_lenient.json")


@lru_cache(maxsize=1)
def _load():
    with open(TASKS_PATH, encoding="utf-8") as f:
        tasks = json.load(f)
    if os.path.exists(LENIENT_PATH):
        with open(LENIENT_PATH, encoding="utf-8") as f:
            len_ = json.load(f)
        for t in tasks:
            t.update(len_.get(t["id"], {}))
    return tasks


def load_tasks():
    return list(_load())


def task_map():
    return {t["id"]: t for t in _load()}
