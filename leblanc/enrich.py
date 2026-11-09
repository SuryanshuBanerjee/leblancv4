"""Engine A v4: the text added to a prompt by each arm.

Study arms:
  plain     nothing added
  generic   one fixed sentence (config/study.json)
  targeted  the knowledge-base warning for the task's own CWE (oracle). This measures what the
            *content* of a correct warning adds over generic priming, separated from whether a
            retriever can find the right warning.
Product (MCP, Dataset page): analyze(prompt) retrieves warnings from the prompt text alone,
  at most 3 warnings and at most 80 estimated tokens; zero warnings is allowed.
  Its accuracy is measured offline on the 119 held-out CodeSecEval tasks (python -m leblanc engine-a-eval).
"""
import json
import os
import re

from .config import DATA_DIR, STUDY

with open(os.path.join(DATA_DIR, "kb.json"), encoding="utf-8") as _f:
    KB = json.load(_f)
_BY_CWE = {e["cwe"]: e for e in KB}

MAX_WARNINGS = 3


def est_tokens(text):
    """Rough token estimate (about 4 characters per token). Real counts come from provider usage."""
    return max(1, round(len(text) / 4)) if text else 0


def warning_line(cwe):
    e = _BY_CWE.get(cwe)
    return f"Security note ({cwe}): {e['warning']}" if e else None


def added_text(arm, task):
    if arm == "plain":
        return ""
    if arm == "generic":
        return STUDY["generic_line"]
    if arm == "targeted":
        line = warning_line(task["cwe"])
        if not line:
            raise KeyError(f"no knowledge-base warning for {task['cwe']}")
        return line
    raise ValueError(arm)


def build_prompt(arm, task):
    extra = added_text(arm, task)
    return (task["prompt"].rstrip() + "\n\n" + extra) if extra else task["prompt"], extra


def _kw_hit(text, kw):
    return re.search(r"(?<![a-z0-9_])" + re.escape(kw.lower()) + r"(?![a-z0-9_])", text) is not None


def analyze(prompt, max_warnings=MAX_WARNINGS, max_tokens=None):
    """Retrieve warnings for an arbitrary prompt. Returns dict(warnings, text, tokens, matches)."""
    max_tokens = max_tokens or STUDY["warning_max_tokens"]
    low = prompt.lower()
    scored = []
    for e in KB:
        strong = [k for k in e["strong"] if _kw_hit(low, k)]
        if not strong:
            continue
        weak = [k for k in e["weak"] if _kw_hit(low, k)]
        scored.append((len(strong) * 1.0 + 0.25 * len(weak), e, strong, weak))
    scored.sort(key=lambda s: (-s[0], int(s[1]["cwe"].split("-")[1])))
    chosen, lines, total = [], [], 0
    for score, e, strong, weak in scored:
        if len(chosen) >= max_warnings:
            break
        line = f"Security note ({e['cwe']}): {e['warning']}"
        t = est_tokens(line) + 1
        if total + t > max_tokens:
            continue
        chosen.append({"cwe": e["cwe"], "name": e["name"], "score": round(score, 2), "strong": strong, "weak": weak})
        lines.append(line)
        total += t
    text = "\n".join(lines)
    return {"warnings": chosen, "text": text, "tokens": est_tokens(text)}
