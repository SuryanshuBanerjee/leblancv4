# Decisions log

Dated record of every change to the design. Newest last.

## 2026-11-05 (planning, before any v4 code)
- v4 rebuilt from scratch; v3 kept as an archive and not used for any v4 number.
- Judge is Bandit union Semgrep (Bandit alone has no rule for many target CWEs); Bandit-only and Semgrep-only are reported as rows.
- Semgrep severities ERROR and WARNING kept, INFO dropped (all WARNING rules in the pinned pack have medium or high confidence).

## 2026-11-06
- **Provider: OpenRouter only.** Groq dropped (daily token caps would stretch the run over days). One key, one client.
- **Models: three.** `openai/gpt-oss-20b`, `google/gemini-3.5-flash-lite`, `deepseek/deepseek-v4.1-flash-1017`.
  `deepseek-v4-pro` dropped as too expensive for the budget; `gpt-oss-120b` dropped earlier.
- **Hosts pinned, fallbacks off.** gpt-oss-20b on DeepInfra bf16; Gemini on Google AI Studio (supports temperature);
  DeepSeek on DeepInfra fp8, because DeepSeek's own endpoint trains on paid prompts and the account's privacy setting excludes it.
- **Premise changed to allow a ceiling.** The study asks whether scaffolding is still worth it on current models,
  with a pre-registered "ceiling" verdict (plain rate under 10%).
- **RQ2 reframed as a replication.** Tony et al. (2024) and He et al. (2024) already compared generic and
  CWE-specific prompts on 2023-era models, with conflicting results.
- **Repair applied to the plain output** (not the targeted one): this is how "generate, scan, fix" is deployed, and
  it keeps RQ4 independent of the prompt arms and maximises the number of flagged outputs.
- **Dataset: CodeSecEval, 60 tasks** (seeded selection, see PROPOSAL 4.1) replaces the v3 50-task set. Reason:
  every task has author-written functional and security tests; the v3 set had tests for 20 of 50 and 13 tasks no
  scanner could judge. Custom Semgrep rules, once planned for those 13, are not needed and were not written.
- **Validation before selection**: tasks whose secure reference fails its own tests in our sandbox (6), or whose
  security test does not catch the insecure reference (4), are ineligible.
- **targeted arm uses the task's known CWE (oracle)**; Engine A retrieval is evaluated offline on the 185 held-out
  CodeSecEval tasks instead of on teammate-written prompts.
- **Untrusted code runs only in a WSL bubblewrap jail** (no network, no Windows drives, no secrets).
- **Output cap 16,384 tokens** (8,192 truncated one DeepSeek reply in the dry run, entirely reasoning tokens).
- **Spend cap $4.50** against the $5 key limit.
- **Published tests are not edited.** Some tests check behaviour the prompt does not state (e.g. T03). Contrasts
  are paired within task, so this does not bias them; tasks whose functional test fails every output are listed.
- **FP audit annotators**: the student and Claude (not a model under test), blind to each other; stated as a limitation.
- **No regression model** (unstable with near-zero cells); contrasts use paired McNemar with cluster-bootstrap intervals.

## 2026-11-06 (after the stress test, before the main run)
- **Mock-injecting tests excluded.** The 120-cell stress test showed every model failing tasks whose tests replace
  objects inside the solution (`candidate.__globals__[...]`) with fakes that support only the reference's choices
  (e.g. AES GCM only). Such tests reward copying the reference, and can favour the targeted arm when its warning
  happens to name the same choice. New eligibility rule: no test may inject into the solution's globals.
  Tasks reselected by the same seeded procedure: 56 tasks (28 SecEvalPlus + 28 SecEvalBase, 38 CWE types);
  held-out set 119. The stress-test outputs were used only to find this defect; no task was chosen or dropped
  by looking at model results.
- **Truncation is an outcome, not a gate.** DeepSeek occasionally reasons until the 16,384-token cap (about 3% of
  its calls, repair prompts). `reasoning.max_tokens` is not honoured by the host (replies got longer), and
  `effort: low` with `max_tokens` is rejected. Truncated replies are recorded as `truncated` and not retried.
- **Failure messages** now show the failing assert line of the test.
- **Lenient test scoring is primary; the published tests are secondary.** In the 56-task rehearsal the largest group
  of security-test failures (125) was "Raised an unexpected exception type": the code rejected the attack, with a
  different exception class than the reference. Prompts do not name the class. Lenient scoring accepts any
  exception in the tests' assert_raises helpers. Validated on references only: all 56 secure references pass it;
  on 11 tasks the insecure reference also passes the lenient security test (it crashes on the attack), so lenient
  security results use the other 45 tasks. Rules fixed before the main run.
- **gpt-oss-20b gets a second bf16 host (DekaLLM).** DeepInfra rejected 84 of 316 gpt-oss calls (27%) as
  rate-limited upstream in the rehearsal. Same full-precision weights; the serving host is stored per call.

## 2026-11-06 (main run)
- **Main run complete**: 2,520 of 2,520 cells, 0 failed, 2,098 successful calls, 39 minutes, $0.78. 48 call attempts
  failed during a brief local network outage and were retried automatically. 4 DeepSeek repair replies truncated.
- **Audit**: 30 findings drawn (seed 2026, frozen). Annotator "claude" labelled all 30 blind (22 fp, 5 tp, 3 unsure).
  The human annotation in the Audit page is pending; Cohen's kappa appears on Results when it is done.
- **Documents**: paper/leblanc_paper.pdf (research paper) and report/leblanc_report.pdf (project report). Every
  number comes from paper/make_figures.py over run/leblanc.db (paper/numbers.json, paper/tables/).

## 2026-11-06 Draft documents for supervisor review
- Added figures generated from the run database: fig7 (security-test outcome split by scanner verdict) and fig8
  (plain-prompt security-test failure per CWE). Added a TikZ pipeline diagram (`paper/figures/pipeline.tex`) shared by
  the paper, the report and the guide. Put the existing fig3 (static RQ2) and fig4 (functional RQ3) into the paper.
  Fixed overlapping x-axis labels in fig5.
- Added `guide/leblanc_guide.pdf`, a plain-language companion for the viva. No numbers or analysis changed.
- Removed the stale `leblanc` MCP registration that pointed at v3; only `leblanc-v4` is registered now.
