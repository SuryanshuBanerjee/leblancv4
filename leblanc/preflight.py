"""Preflight: one real study-style call per model through the pinned host. Costs a fraction of a cent."""
from . import enrich, judge, llm
from .config import STUDY, model_ids
from .dataset import load_tasks


def run(task_index=0, arm="targeted"):
    task = load_tasks()[task_index]
    prompt, _ = enrich.build_prompt(arm, task)
    msgs = [{"role": "system", "content": STUDY["system_prompt"]}, {"role": "user", "content": prompt}]
    out = []
    for m in model_ids():
        row = {"model": m}
        try:
            res = llm.chat(m, msgs)
            status, code = judge.extract(res["content"], res["finish_reason"])
            row.update(ok=status == "ok", extract=status, finish_reason=res["finish_reason"],
                       provider=res["provider"], prompt_tokens=res["prompt_tokens"],
                       completion_tokens=res["completion_tokens"], reasoning_tokens=res["reasoning_tokens"],
                       cost_usd=res["cost_usd"], latency_s=res["latency_s"],
                       has_entry=(task["entry_point"] in code) if code else False)
        except Exception as e:
            row.update(ok=False, error=f"{type(e).__name__}: {e}"[:300])
        out.append(row)
    return {"task": task["id"], "arm": arm, "results": out}
