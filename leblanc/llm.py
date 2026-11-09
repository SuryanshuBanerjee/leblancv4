"""OpenRouter client. Stdlib only. Records every attempt; never turns a failed call into a result."""
import json
import random
import time
import urllib.error
import urllib.request

from .config import MODELS, STUDY, get_key


class FatalLLMError(Exception):
    """The run must stop: no credit, bad key."""


class CallFailed(Exception):
    def __init__(self, msg, attempts):
        super().__init__(msg)
        self.attempts = attempts


def _model_cfg(model_id):
    for m in MODELS["models"]:
        if m["id"] == model_id:
            return m
    return {"id": model_id}


def _post(body, timeout):
    key = get_key(MODELS["key_env"])
    if not key:
        raise FatalLLMError(f"{MODELS['key_env']} is not set (put it in .env)")
    req = urllib.request.Request(MODELS["base_url"], data=json.dumps(body).encode("utf-8"), headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
        "X-Title": "LeBlanc v4 research run"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


def chat(model_id, messages, on_attempt=None, max_tokens=None, temperature=None):
    """Return dict(content, finish_reason, usage..., provider, latency_s, retries).

    on_attempt(dict) is called for every attempt, successful or not, so the calls table is complete.
    Raises CallFailed after max_retries, FatalLLMError on 401/402.
    """
    cfg = _model_cfg(model_id)
    body = {"model": model_id, "messages": messages,
            "max_tokens": max_tokens or STUDY["max_tokens"],
            "temperature": STUDY["temperature"] if temperature is None else temperature,
            "usage": {"include": True}}
    if cfg.get("reasoning") and STUDY.get("reasoning_effort"):
        body["reasoning"] = {"effort": STUDY["reasoning_effort"]}
    if cfg.get("provider_order"):
        body["provider"] = {"order": cfg["provider_order"], "allow_fallbacks": False}
        if cfg.get("quantizations"):
            body["provider"]["quantizations"] = cfg["quantizations"]
    retries = STUDY["max_retries"]
    last = ""
    for attempt in range(retries + 1):
        t0 = time.time()
        rec = {"model": model_id, "retries": attempt, "temperature": body["temperature"], "created_at": t0}
        try:
            status, d = _post(body, STUDY["request_timeout_s"])
            dt = time.time() - t0
            if "error" in d and not d.get("choices"):
                err = d["error"]
                code = err.get("code") if isinstance(err, dict) else None
                raise urllib.error.HTTPError(MODELS["base_url"], int(code) if str(code).isdigit() else 502,
                                             json.dumps(err)[:300], None, None)
            ch = d["choices"][0]
            u = d.get("usage") or {}
            res = {
                "content": (ch.get("message") or {}).get("content") or "",
                "finish_reason": ch.get("finish_reason") or ch.get("native_finish_reason"),
                "prompt_tokens": u.get("prompt_tokens"), "completion_tokens": u.get("completion_tokens"),
                "reasoning_tokens": (u.get("completion_tokens_details") or {}).get("reasoning_tokens"),
                "cost_usd": u.get("cost"), "provider": d.get("provider"), "latency_s": round(dt, 3),
                "retries": attempt,
            }
            if ch.get("error"):
                raise urllib.error.HTTPError(MODELS["base_url"], 502, json.dumps(ch["error"])[:300], None, None)
            if on_attempt:
                on_attempt(dict(rec, ok=1, http_status=status, error=None, **{k: res[k] for k in (
                    "prompt_tokens", "completion_tokens", "reasoning_tokens", "cost_usd", "provider",
                    "latency_s", "finish_reason")}))
            return res
        except urllib.error.HTTPError as e:
            code = e.code
            try:
                detail = e.read().decode("utf-8", "replace")[:300] if hasattr(e, "read") and e.fp else str(e.msg)
            except Exception:
                detail = str(e.msg)
            last = f"HTTP {code}: {detail}"
            if on_attempt:
                on_attempt(dict(rec, ok=0, http_status=code, error=last, latency_s=round(time.time() - t0, 3)))
            if code == 402 and "in_flight" in detail:
                # OpenRouter reserves max_tokens x price per request; wait for in-flight calls to settle.
                if on_attempt is None or attempt < retries:
                    time.sleep(20 + random.random() * 10)
                    continue
            if code in (401, 402, 403):
                raise FatalLLMError(last)
            if code == 400 and "context" not in detail.lower():
                raise CallFailed(last, attempt + 1)
            wait = None
            if code == 429 and e.headers is not None:
                ra = e.headers.get("Retry-After")
                if ra and ra.replace(".", "", 1).isdigit():
                    wait = float(ra)
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError, KeyError, IndexError) as e:
            last = f"{type(e).__name__}: {str(e)[:200]}"
            wait = None
            if on_attempt:
                on_attempt(dict(rec, ok=0, http_status=None, error=last, latency_s=round(time.time() - t0, 3)))
        if attempt < retries:
            time.sleep(wait if wait else min(120, (2 ** attempt) * 2 + random.random() * 2))
    raise CallFailed(last, retries + 1)
