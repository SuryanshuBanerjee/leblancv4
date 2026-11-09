"""Statistics. One module, no external dependencies, fixed seeds.

- wilson(k, n): display interval for a single rate.
- cluster_rate(groups): rate with a cluster-bootstrap CI, resampling tasks (repetitions are nested in tasks).
- paired(pairs_by_task): mean paired difference with a cluster-bootstrap CI, plus exact McNemar.
- bh(pvals): Benjamini-Hochberg adjusted p-values.
- cohen_kappa(a, b): agreement between two annotators.
"""
import math
import random

SEED = 2026


def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    i = (len(xs) - 1) * q
    lo, hi = math.floor(i), math.ceil(i)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)


def cluster_rate(groups, resamples=2000):
    """groups: {task: [0/1, ...]}. Returns dict(rate, k, n, lo, hi, tasks)."""
    groups = {k: v for k, v in groups.items() if v}
    vals = [x for v in groups.values() for x in v]
    n = len(vals)
    if n == 0:
        return {"rate": None, "k": 0, "n": 0, "lo": None, "hi": None, "tasks": 0}
    k = sum(vals)
    keys = sorted(groups)
    rng = random.Random(SEED)
    boots = []
    for _ in range(resamples):
        s = t = 0
        for _ in keys:
            g = groups[keys[rng.randrange(len(keys))]]
            s += sum(g)
            t += len(g)
        boots.append(s / t)
    return {"rate": k / n, "k": k, "n": n, "lo": _pct(boots, 0.025), "hi": _pct(boots, 0.975), "tasks": len(keys)}


def binom_two_sided(k, n):
    """Exact two-sided binomial test against p=0.5 (McNemar on discordant pairs)."""
    if n == 0:
        return 1.0
    k = min(k, n - k)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def paired(pairs_by_task, resamples=2000):
    """pairs_by_task: {task: [(a, b), ...]} with 0/1 outcomes; effect = mean(b) - mean(a).

    Returns dict(effect, lo, hi, n, b_only, a_only, p_mcnemar, rate_a, rate_b, tasks).
    """
    pairs_by_task = {k: v for k, v in pairs_by_task.items() if v}
    allp = [p for v in pairs_by_task.values() for p in v]
    n = len(allp)
    if n == 0:
        return {"effect": None, "lo": None, "hi": None, "n": 0, "b_only": 0, "a_only": 0, "p_mcnemar": None,
                "rate_a": None, "rate_b": None, "tasks": 0}
    ra = sum(a for a, _ in allp) / n
    rb = sum(b for _, b in allp) / n
    b_only = sum(1 for a, b in allp if b and not a)
    a_only = sum(1 for a, b in allp if a and not b)
    keys = sorted(pairs_by_task)
    rng = random.Random(SEED)
    boots = []
    for _ in range(resamples):
        s = t = 0
        for _ in keys:
            g = pairs_by_task[keys[rng.randrange(len(keys))]]
            s += sum(b - a for a, b in g)
            t += len(g)
        boots.append(s / t)
    return {"effect": rb - ra, "lo": _pct(boots, 0.025), "hi": _pct(boots, 0.975), "n": n, "b_only": b_only,
            "a_only": a_only, "p_mcnemar": binom_two_sided(b_only, b_only + a_only), "rate_a": ra, "rate_b": rb,
            "tasks": len(keys)}


def bh(pvals):
    """Benjamini-Hochberg. pvals: list (None allowed). Returns adjusted list in the same order."""
    idx = [i for i, p in enumerate(pvals) if p is not None]
    m = len(idx)
    out = [None] * len(pvals)
    if not m:
        return out
    order = sorted(idx, key=lambda i: pvals[i])
    prev = 1.0
    for rank in range(m, 0, -1):
        i = order[rank - 1]
        prev = min(prev, pvals[i] * m / rank)
        out[i] = prev
    return out


def cohen_kappa(a, b):
    """a, b: equal-length label lists. Returns (kappa, agreement, n)."""
    pairs = [(x, y) for x, y in zip(a, b) if x is not None and y is not None]
    n = len(pairs)
    if n == 0:
        return (None, None, 0)
    labels = sorted({x for p in pairs for x in p})
    po = sum(1 for x, y in pairs if x == y) / n
    pe = sum((sum(1 for x, _ in pairs if x == l) / n) * (sum(1 for _, y in pairs if y == l) / n) for l in labels)
    kappa = 1.0 if pe == 1 else (po - pe) / (1 - pe)
    return (kappa, po, n)
