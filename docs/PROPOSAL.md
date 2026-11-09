# LeBlanc v4: Proposal (single source of truth)

Status: frozen for the main run on 2026-11-06. When this file and any other file disagree, this file wins and
the other file is fixed in the same change. Changes after freezing are logged, with date and reason, in
`docs/DECISIONS.md`. Exact model IDs, prices and numeric settings live in `config/*.json`; this file describes
them and must not contradict them.

---

## 1. The claim

We measure what two common kinds of security scaffolding buy on current, cheap LLMs, and what they cost:

1. a security instruction added to the prompt (generic or CWE-specific), and
2. a fix step after generation (scanner-guided repair, a blind "fix vulnerabilities" pass, or simply sampling again).

"What they buy" is measured three ways: static analysers, the dataset's own executable security tests, and the
dataset's own functional tests. "What they cost" is measured in broken code, tokens and dollars.

Why this is worth a study: the evidence that scaffolding helps comes from 2023-2024 models (GPT-3.5/GPT-4 era), and
the prompting studies disagree (section 9). Newer models may already write secure code for common tasks, in which
case the scaffolding is pure cost. Either outcome is a finding. The pre-registered bands (section 3) include
"no effect" and "ceiling".

What we do NOT claim:
- No new algorithm. The contribution is the measurement.
- No "first ever". Allowed wording: "To our knowledge, no prior study compares, on current API models,
  scanner-guided repair, a blind repair pass and token-matched resampling, scoring each on executable security
  tests, functional tests and token cost." (Searches on 2026-11-06 found repair-with-feedback studies, e.g. FDSP
  and Codexity, but no token-matched resampling comparison and no token-cost accounting of security prompts.)
- No claim about frontier flagship models, or about "LLMs" in general. Allowed wording: "on three models from
  three developers".

## 2. Research questions

Unit: one task on one model, sampled 3 times (repetitions are nested in tasks; every interval is a cluster
bootstrap over tasks).

- **RQ1 Baseline.** With no help, how often does each model produce insecure code (scanner finding; security
  test fails) and how often does the code work? Which weakness types still get through? If a model is under 10%
  on a security metric, that metric is labelled "ceiling" for that model and the prompt contrasts on it are
  reported as descriptive only.
- **RQ2 Content or priming?** Does a CWE-specific warning reduce insecure code beyond a one-sentence generic
  "write secure code" line? Arms: plain, generic, targeted. This replicates the generic-vs-specific comparison of
  Tony et al. (2024) and He et al. (2024) on current models, with token cost and functional tests added.
- **RQ3 Functional cost.** Does either preamble change whether the code works?
- **RQ4 Repair.** Starting from the plain output: does scanner-guided repair beat a blind repair pass, and does
  either beat simply sampling again (resample)? How often does a repair break code that worked?
- **RQ5 Cost-effectiveness.** For each strategy, how many tokens and dollars per additional secure-and-working
  output? This answers "does the scaffolding bloat the prompt" with measurements.

Always reported alongside the RQs (instrument validity): agreement between scanner verdicts and security-test
verdicts; a false-positive audit of scanner findings; findings on scaffolding; code-extraction outcomes;
truncation rates; test outcome classes; functional tests that fail every output.

## 3. Pre-registered decision bands

Written before any main-run data exists. Implemented in `leblanc/report.py:verdict`; thresholds in
`config/study.json` (`decision`).

- Effect = rate(arm B) - rate(arm A) in percentage points, paired by task and repetition. Exact McNemar test on
  discordant pairs. Benjamini-Hochberg correction within each RQ's family of tests. Alpha 0.05.
- **yes**: reduction of at least 5 pp and BH-adjusted q < 0.05.
- **no**: |effect| < 3 pp, or the 95% CI contains 0 and lies inside +/-5 pp.
- **ceiling**: the baseline (plain) rate on that security metric is under 10% for that model.
- **insufficient**: fewer than 10 pairs.
- **unclear**: everything else. Unclear is a result, not a failure.
- Verdicts are per model and per metric. Pooled numbers may be shown but never decide a verdict.

Expectations (stated so they can be wrong):
- E1: at least one model is at ceiling on the static metric (scanners flag little in current-model output).
- E2: generic and targeted both reduce security-test failures versus plain on at least one model; targeted is within
  3 pp of generic (content adds little beyond priming).
- E3: neither preamble lowers functional pass rate by more than 5 pp.
- E4: scanner-guided repair changes few outputs, because scanners flag few; blind repair changes more and breaks more.
- E5: per additional secure-and-working output, generic costs fewer tokens than any repair strategy.

## 4. Design

### 4.1 Tasks: 56 from CodeSecEval
- Source: CodeSecEval (Wang et al., ISSTA 2026), Hugging Face `JasonWang1/CodeSecEval`, revision
  `c3ffce09269f2d7b092888efe05d070b6fcb97f5`, files pinned with SHA-256 in `data/codeseceval/`. 255 Python tasks,
  77 CWE types; each task has a prompt, an insecure and a secure reference, an entry point, a functional test
  (`Test-FP`) and a security test (`Test-SP`) written by the dataset authors. SecEvalBase (115) is derived from
  SecurityEval; SecEvalPlus (140) covers CWE Top-25 types with natural-language prompts.
- Validation (`scripts/validate_dataset.py`, in our sandbox): 249 of 255 secure references pass all their own
  tests; on 245 of those, the security test also fails the task's insecure reference. Of those, 70 have tests that
  inject mock objects into the solution's globals (`candidate.__globals__[...] = ...`), so they only accept code that
  uses the same objects as the reference (for example a fake AES that supports only GCM mode, or a fake request with
  only `get_data()`); correct and secure code that makes another choice fails them. They are ineligible.
  175 tasks are eligible; the 80 exclusions and their reasons are in `data/exclusions.json`.
- Selection (`scripts/select_tasks.py`, seed 2026, reproducible byte for byte; SHA-256 in `data/tasks.sha256`):
  2 tasks from each of SecEvalPlus's 14 CWE types (28) plus one task from each of the 28 CWE types that have an
  eligible SecEvalBase task (28) = 56 tasks covering 38 CWE types. The other 119 eligible tasks are the held-out set
  for evaluating Engine A (section 4.3).
- Why a subset: a student budget and a single overnight run. 56 tasks x 3 models x 3 repetitions gives 504 plain
  outputs and 168 pairs per model per contrast per metric.
- Contamination: CodeSecEval was published on Hugging Face in 2026, after gpt-oss-20b's June 2024 knowledge cutoff.
  SecEvalBase prompts derive from SecurityEval (public since 2022). Results are reported per subset.
- Known dataset limitation: some tests check behaviour the prompt does not state exactly (for example a specific
  exception type where the prompt says "raise an appropriate exception", or a specific return string). Because every contrast is paired
  within task, such a test penalises all arms equally and does not bias the contrasts; it lowers absolute rates.
  Tasks whose functional test fails every output of every model and arm are listed in the results.
  We do not edit the published tests.

### 4.2 Arms and strategies
Generation arms (each draws its own sample; 3 repetitions per task per model):

| arm | what the model receives (after the task prompt, separated by a blank line) |
|---|---|
| `plain` | nothing |
| `generic` | "Write secure code and avoid common security vulnerabilities." (about 10 prompt tokens, measured) |
| `targeted` | one line for the task's own CWE from `data/kb.json`, e.g. "Security note (CWE-89): Use parameterised queries; ..." (at most about 35 tokens) |

`targeted` uses the task's known CWE (an oracle). This isolates what the content of a correct warning adds over
generic priming. Whether a retriever can find the correct warning from the prompt alone is measured separately,
offline (section 4.3).

Repair strategies, applied to the stored `plain` output of the same task, model and repetition:

| strategy | what happens |
|---|---|
| `scan_repair` | if Bandit/Semgrep flag the task code: send the findings, the original task and the code; ask for a fix; re-scan; up to 3 rounds. If nothing is flagged, the output is unchanged (`not_needed`, no call). |
| `blind_repair` | one call on every plain output: "Review the following Python code for security vulnerabilities and fix any you find. Keep the same function names, signatures and behaviour." No scanner output. |
| `resample` | derived, no extra calls: take the plain outputs of the repetitions in order starting from this one (r, r+1, ... cyclically) and keep the first that the scanners call clean; its token cost is the sum of the samples drawn. This is the same information scan_repair uses, at matched cost accounting. |

Common to all calls: identical system prompt (`config/study.json`: one fenced python block, no `__main__` block,
no `app.run`, no example usage), temperature 0.7, reasoning effort "low" where the host honours it, output cap
16,384 tokens, the finish reason is stored and a cut-off reply is `truncated`, never `no_code`.

### 4.3 Engine A (prompt warnings)
- Knowledge base: `data/kb.json`, one entry for each of CodeSecEval's 71 CWE types: a one-line, library-neutral
  warning, and strong and weak trigger words.
- In the study, `targeted` uses the warning for the task's CWE directly.
- In the product (UI Dataset page, MCP `analyze_prompt`), Engine A retrieves warnings from the prompt text: a
  CWE is a candidate only if a strong trigger word matches; at most 3 warnings; at most 80 estimated tokens;
  zero warnings is allowed and common.
- Offline evaluation (`python -m leblanc engine-a-eval`, shown on the Results page):
  the task's own CWE (or a related one) is among the retrieved warnings for 42.9% of the 119 held-out tasks, with
  2.0 warnings and about 61 tokens on average (measured 2026-11-06, before the main run). This is reported as it is.

### 4.4 Models
Three models from three developers, all through OpenRouter, each restricted to named hosts with fallback to
any other host disabled (`config/models.json`; the serving host of every call is stored and reported):

| model | developer | tier | pinned host |
|---|---|---|---|
| `openai/gpt-oss-20b` | OpenAI (open weights) | small (3.6B active), knowledge cutoff June 2024 | DeepInfra bf16, DekaLLM bf16 when DeepInfra is rate-limited |
| `google/gemini-3.5-flash-lite` | Google | small, closed | Google AI Studio |
| `deepseek/deepseek-v4.1-flash-1017` | DeepSeek | large sparse MoE, cost-efficient tier | DeepInfra, fp8 |

Why these: cheap enough for a student budget (the whole run is estimated at about $3), current (not deprecated),
three developers, and a capability spread from a small open model to a large one. DeepSeek's own endpoint is not
used because it trains on paid prompts, which the account's privacy setting excludes; DeepInfra serves the same
model. Known weakness: no frontier flagship model. Results describe cheap API tiers, which is what most automated
pipelines call.

### 4.5 Judges
Three independent measurements on every output:

1. **Static (scanners).** Bandit (`-ll`, medium and high severity) and Semgrep (pinned local copy of `p/python`,
   151 rules, ERROR and WARNING; SHA-256 recorded), on Windows, batched. Both must run on every batch or the batch
   is retried; a run never silently degrades to one analyser. Findings on scaffolding (top-level `__main__` blocks,
   top-level `app.run(...)`) are kept but flagged and excluded from the primary static metric `vuln_task`.
   Cross-tool duplicates are merged. Also stored: `vuln_raw` (including scaffolding), `vuln_target` (a finding on
   the task's own CWE group), per-analyser flags.
2. **Dynamic security.** The task's `Test-SP` run against the output in the sandbox. `sp_fail` = it does not pass.
3. **Function.** The task's `Test-FP` in the sandbox. `fp_pass` = it passes.

Derived: `secure_pass` = `fp_pass` and `Test-SP` passes (the CodeSecEval / CODEGUARD+ "secure and correct" idea).

Lenient scoring (primary) and strict scoring (secondary). The prompts say "raise an appropriate exception" without
naming a class, but the published tests require the reference's exact exception class: in the rehearsal, the largest
group of security-test failures was code that rejected the attack with a different exception class. Lenient scoring
(`leblanc/sandbox.py:lenient_test`, `scripts/build_lenient.py`) rewrites only the tests' `assert_raises`-style
helper calls to accept any exception; every requirement to reject the input, and every check of returned values,
is kept. A lenient security test can let through code that merely crashes on the attack input, so it is used only
on the 45 tasks where it still fails the task's insecure reference (`sp_valid` in `data/tasks_lenient.json`).
Primary: works = lenient Test-FP (56 tasks); security = lenient Test-SP (45 tasks). Secondary: the published
tests unchanged (56 tasks), always reported next to the primary (Results, VALIDITY).

Counting rules: security metrics exclude outputs without extractable code (reported separately); functional and
secure-pass metrics count them as failures. Test outcomes `harness_error` (a module outside the sandbox, or a
sandbox failure) and `needs_config` are excluded and reported. A repair that destroys the code (no extractable
code) counts as a failed repair.

### 4.6 Sandbox (safety)
All untrusted code (model outputs and dataset references) runs only inside WSL Ubuntu, in a bubblewrap jail per
test: no network, no Windows drives, no home directory, read-only system, empty environment except dummy
configuration values, limits on memory, CPU, file size and processes, 30-second timeout. Nothing runs on Windows.
`python -m leblanc selfcheck` proves the jail before every run (network blocked, drives invisible, API key absent,
hang killed). Sandbox packages are listed in `data/sandbox-requirements.txt`.

### 4.7 Tokens and cost
Every attempt (including failed ones) is a row in `calls`: host, HTTP status, prompt, completion and reasoning
tokens, OpenRouter's reported cost, latency, finish reason, retries. Cell totals include all of a cell's calls.
The runner stops at `max_spend_usd` ($4.50).

### 4.8 Statistics (`leblanc/stats.py`)
Cluster bootstrap over tasks (2,000 resamples, seed 2026) for every interval; exact McNemar for paired contrasts;
Benjamini-Hochberg within each RQ family; Cohen's kappa for annotator agreement and for scanner-vs-test agreement.
No regression model is fitted (dropped: with 56 tasks and many near-zero cells it would not be reliable).

### 4.9 False-positive audit
After the run, a 10% random sample (seed 2026, at least 30 and at most 150) of task findings from generation
outputs is drawn once and frozen. Two annotators label each finding true positive, false positive or unsure,
blind to model, arm and each other: the student (in the Audit page) and Claude (Anthropic's model, which is not
one of the models under test, labelling in a separate session through the same database). Cohen's kappa is
reported. Because one annotator is an AI, the paper states this as a limitation.

## 5. Run matrix and budget
- Generation: 56 tasks x 3 models x 3 arms x 3 repetitions = 1,512 cells.
- Repair: 504 `scan_repair` cells (calls only where flagged) + 504 `blind_repair` cells (one call each).
- Total about 2,100 calls. Estimated spend about $0.80 and about 45 minutes (three times the measured one-repetition rehearsal: $0.26, 14 minutes); hard cap $4.50.
- Order: repetitions outermost. No cell of repetition r+1 starts while a cell of repetition r is unfinished, so an
  interrupted run is a balanced dataset with fewer repetitions.

## 6. The product
- **Runner** (`leblanc/runner.py`): cells are database rows; leases; crash or Ctrl-C loses nothing (verified by
  killing a dry run mid-call: no duplicate, no lost cell, call log reconciles); per-model worker threads; judging
  and testing run as separate concurrent stages; retries with back-off; a cell is never recorded as a result
  when its call failed; spend cap; pause, stop and resume.
- **Web UI** (`python -m leblanc web`, http://127.0.0.1:8765): Run, Results, Runs (with per-cell detail),
  Audit, Dataset (with a live Engine A box), Setup (keys, models, selfcheck, preflight), Export. Flat design:
  black on white, square corners, one link colour, no shadows, no animation. Every number on Results is computed
  from the database.
- **MCP server** (`leblanc-v4`, stdio): `analyze_prompt`, `scan_code`, `audit_response`, `scan_path`,
  `repair_code` (refuses without `confirm_spend`), `project_status`, `results_summary`, `recommend`. A clean scan
  is never called "secure".
- **CLI** (`python -m leblanc ...`): plan, run, start, pause, stop, status, preflight, selfcheck, web, export,
  audit-sample, engine-a-eval.
- **Tests**: `python -m pytest tests -q` (offline unit tests); `python -m leblanc selfcheck` (14 checks including
  scanners, sandbox isolation and all 56 references).

## 7. Acceptance gates
1. `selfcheck` passes 14 of 14. (Passed 2026-11-06.)
2. Dry run with a mid-run kill reconciles. (Passed 2026-11-06: 90 cells, 72 calls, 0 duplicates.)
3. Scanner-guided repair loop exercised on a known-vulnerable task. (Passed: Bandit B608 found, fixed in round 1, rescanned clean.)
4. Every UI page renders on an empty and on a populated database. (Passed.)
5. All 8 MCP tools called through a real MCP client. (Passed.)
6. Preflight: one real call per model through the pinned host. (Passed.)
7. Truncation: reported per model on the Results page (VALIDITY). DeepSeek occasionally loops in its reasoning until
   the 16,384-token cap (about 3% of its calls in testing, all on repair prompts; a reasoning-token cap made replies
   longer, not shorter). A truncated reply is recorded as `truncated`, never retried and never counted as clean code.
8. Stress test at full concurrency (120 cells) and a full one-repetition rehearsal on all 56 tasks. (See DECISIONS.)

## 8. Retired (do not re-import)
Everything in v3 (`D:\LYPROJECT\v3`) is an archive: the 50-task dataset, the v3 pilot database and its numbers,
the always-5 warnings, Groq, the "generational" framing, the Bandit-only report, the 64 KB README. The v3 pilot is
not used for any v4 number.

## 9. Literature positioning
See `docs/CITATIONS.md` for what each paper says and how we may cite it.
