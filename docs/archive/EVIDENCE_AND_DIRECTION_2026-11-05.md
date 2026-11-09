> ARCHIVED 2026-11-06. Written for the 50-task v3 design before the switch to CodeSecEval and OpenRouter.
> Superseded by docs/PROPOSAL.md (design) and docs/CITATIONS.md (literature). Kept only as a record of the reasoning.

# Evidence and direction

What the literature, the old proposal and our own pilot actually say, and the course of action that
follows. `PROPOSAL.md` is the specification; this file is the reasoning behind it. Where a number is
marked (verified) it was checked against the PDF text. Where it is marked (read, not re-checked) it comes
from a full read of the paper by a helper and was not re-checked against the text.

---

## Part A. The papers

### A1. Pearce et al. 2022, "Asleep at the Keyboard" (cited by every paper below; not in our folder)
- Reveals: about 40% of Copilot completions in security-relevant scenarios were vulnerable (40.73% over all
  languages, 36.54% for Python, per the replication in A8 (verified)).
- Consequence: it is a Copilot-2021 number. It is not "the average LLM". We cite it as that, never as a baseline for 2026 models.

### A2. Yan et al. 2025, "Guiding AI to Fix Its Own Flaws" (One.pdf)
- Did: 8 models (CodeLlama 7B/34B, Llama3.1-8B, Llama3.2-3B, StarCoder2-15B, DeepSeekV2-16B, GPT-3.5, GPT-4o)
  on SecCodePLT (1,071 tasks) and SecurityEval (121). CodeQL only. Three questions: how vulnerable; do
  self-generated hints help; do models fix code given CodeQL output or a GPT-4o explanation of it.
- Reveals (verified): average target-CWE rate 8.5% and any-vulnerability rate 13.2% on SecCodePLT; 20.7% and 33.4% on SecurityEval.
- Reveals (read, not re-checked): GPT-4o is more vulnerable than GPT-3.5 on both benchmarks; hints help
  only when they name the right weakness and irrelevant hints raise vulnerability; explained feedback beats raw
  CodeQL output for strong models; the four small open models gained nothing from repair on SecurityEval.
- Limits they state: static analysis only, Python only, single-turn, no functional check.
- Consequences for us:
  1. Capability modulates every effect. We need a weak and a strong model, or we cannot say who benefits.
  2. Report two rates, as they do: target-CWE and any-vulnerability. They diverge.
  3. Log whether a warning named the right CWE, and split results on it (`target_hit`).
  4. A newer or bigger model is not automatically safer. Our reversed pilot ordering is not a bug.

### A3. Wang et al. 2023, SecuCoGen (Two.pdf)
- Did: 180 Python tasks, 21 CWE types, 4 models (InCoder, CodeGen, StarCoder, GPT-3.5). Manual SEC@k
  (function correct AND secure), judged by students on half the data because CodeQL did poorly.
- Reveals (verified, Tables 3-4): GPT-3.5 SEC@1/SEC@2 is 0.2667/0.3111 plain, 0.5000/0.5889 with a 1-shot
  example, 0.7333/0.8556 with a CWE-aware problem statement. So "31% to 86%" is SEC@2, plain to CWE-aware.
- Reveals: the CWE-aware text was written by humans per task. InCoder stays near zero.
- Consequence: the 31-to-86 figure is best-of-2 on a human-written warning. It is the upper bound of what a
  hand-tuned warning does on 2023 GPT-3.5, not a benchmark for an automatic lookup table on 2026 models.
  The old spreadsheet row that "corrects" this is wrong.

### A4. Wang et al. 2024, CodeSecEval (Three.pdf)
- Did: 180 tasks, 44 CWE types, with secure and insecure code and tests that check function and security. 7 models. Pass@k.
- Reveals (verified): direct-generation Pass@1 is 12.44 (GPT-4) and 13.83 (Claude 3 Opus); with a hand-written
  vulnerability-aware problem, Claude goes 13.83 to 39.89.
- Reveals (read, not re-checked): GPT-4 got worse on CWE-78 and CWE-89 with vulnerability-aware prompts; repair is single-turn.
- Consequence: executable security tests exist and are the gold standard. It overlaps with our S-tasks (partly
  derived from SecurityEval) and could extend our tested subset later. Warnings can hurt, so we report discordant pairs in both directions.

### A5. Fu et al. 2024, CODEGUARD+ (Five.pdf)
- Did: 91 tasks with unit tests, Python and C/C++, security by CodeQL union Sonar. New metrics: secure-pass@k and secure@kpass.
- Reveals (verified): SVEN looked 71.91% secure, but only 29.14% secure-pass@1, 3.07 points above its baseline.
  Secure-but-broken output was being counted as success.
- Consequence: "secure but broken" is established. Our contribution is not discovering it. We measure it inside a
  repair loop, per model, against controls. We adopt secure-pass@1 as the formula.

### A6. Hasan et al. 2025, DiSCo and LPO (Four.pdf)
- Did: fine-tuning with synthetic preference data from GPT-4o; evaluated with CodeQL and Bandit on four security testbeds.
- Reveals (verified): one scanner-feedback refinement round cut issues in their synthetic data from 37.4% to 12.7%;
  three rounds gave 9.4% but caused over-engineered code and lower quality.
- Reveals (read, not re-checked): prompted frontier models still show 46-61% any-issue rates on SecurityEval.
  Alignment without regularisation produced unparseable code that analysers call secure.
- Consequence: a multi-round scanner loop has been run (on data creation, not on end-user generation), and rounds
  past the first showed diminishing and harmful returns. We report gain per round. Unparseable output is its own class, never "clean".

### A7. Hajipour et al. 2024, HexaCoder (Seven.pdf)
- Did: GPT-4-turbo repairs vulnerable code using a CodeQL report plus a hint, to build fine-tuning data; then fine-tunes open models.
- Reveals (verified): repair rate 42.66% with no report, 63.33% with the CodeQL report, 83.99% with report plus hint (150 codes, five CWEs, one sample).
- Consequence: "no scanner output" is a real arm. Without it you cannot say the scanner information is what helps. Our `blind_repair` arm is this control.
  They also state repair may change functionality. That is the RQ3/RQ4 concern.

### A8. Majdinasab et al. 2023, Copilot replication (Eight.pdf)
- Did: re-ran Pearce's scenarios on a newer Copilot with CodeQL 2.12.4. 12 CWEs, 29 scenarios, Python only.
- Reveals (verified): vulnerable share fell from 36.54% to 27.25% (the intro says 35.35% to 25.06%). The paper states it studies only the
  diversity-of-weakness dimension, not prompt phrasing. The original Copilot version is unknown.
- Consequence: the drop cannot be called "version drift": different dedup, different CodeQL, an unknown baseline version, and a 2023 vulnerability filter.
  Our spreadsheet row claiming "prompt phrasing significantly influences Copilot's security... supports Engine A" has no basis in the paper. We pin model IDs and dates per run for exactly this reason.

### A9. Zhu et al. 2025, DomainEval (Six.pdf)
- Did: 2,454 functional tasks over 6 domains, 12 models. Functional correctness only. No security.
- Reveals (verified): average Pass@1 82.44% on computation, 33.08% on cryptography; gap up to 68.94 points.
- Consequence: domain sizes range from 100 to 1,705, so per-domain results need macro-averaging and visible n. Our Web/Request category has 3 tasks and gets no interval. It is not a security paper and is not evidence about contamination.

### A10. Siddiq and Santos 2022, SecurityEval (source of 40 of our tasks; not in the folder)
- 121 prompts, 69 CWEs per Yan and CodeSecEval's table (the notes in `dataset_notes.txt` say about 130, which one
  paper also writes in its text). Public since 2022, so it may be in model training data. The 10 authored tasks are our hedge.

---

## Part B. What the old documents claimed

| Claim (source) | Verdict | Why |
|---|---|---|
| "9-42% of LLM output contains exploitable flaws" (proposal) | Fix | CodeQL-flagged rates, not exploitability |
| "No paper combines enrichment, real static analysis, multi-turn repair and cross-model benchmarking in one system" (proposal) | Narrow | DiSCo ran 1-3 scanner rounds on data creation; HexaCoder repairs with GPT-4; each lacks the other pieces |
| "Every paper is single-turn" (proposal, tex) | Drop | DiSCo ran up to 3 rounds; SecuCoGen and CodeSecEval score repair functionally |
| "SecuCoGen has no multi-model comparison" (proposal, notes) | Drop | It evaluated 4 models |
| 5 repair iterations (proposal) | Replace | 3, because DiSCo found harm beyond one to three rounds |
| 100-200 prompts, VS Code extension (proposal) | Replace | 50 tasks frozen; MCP server instead |
| RQ5 generational gap, "LLaMA-3-8B vs GPT-4o" (proposal, metrics_spec) | Drop | Models differ in size and vendor; Yan found newer is not safer |
| "Newer models ~0 initial vulnerability" (metrics_spec) | Drop | Pilot plain rates were 45-59% |
| Plain 0.6-0.9, enriched 0.4-0.7 expected (metrics_spec) | Drop | Not what the pilot shows; bands are now pre-registered in `PROPOSAL.md` |
| Convergence rate over all repair runs (metrics_spec) | Fix | Must be over initially vulnerable runs, and repair-caused failures count |
| "Pearce 40% is the average LLM" (presentation) | Fix | Copilot only |
| "45 authentic fragments", "feature inflation bypasses guardrails" (presentation, notes) | Drop | Not what v3 built; unsupported claim about safety filters |
| "Full scale analysis executed" (presentation slide 10) | Drop | Never ran |
| "Pilot shows little benefit from enrichment" (Aug-22 reports) | Drop | Archived pilot shows 14-22 pp benefit |
| Remove Semgrep WARNING findings (sprint plan) | Reject | All 92 WARNING rules have medium or high confidence; open-redirect is WARNING |
| Bandit is the only judge (Oct report) | Reject | Bandit has a rule for the target CWE on 26 of 50 tasks |
| Spreadsheet rows: SecuCoGen, CodeSecEval, DiSCo, CODEGUARD+, DomainEval, HexaCoder, Copilot | Rewrite from Part A | Several wrong numbers and some invented findings |

---

## Part C. What our own pilot reveals (450 runs, 1 repetition, archived in v3)

- Plain-code flag rates were 45-59% per model, and the ordering was the reverse of the old "newer is safer" hypothesis.
- 62% of findings sat on `app.run` or `__main__` boilerplate. One model's rate fell from 54.3% to 17.4% excluding it and the noisy rules.
- The false-positive triage was 53.6% (28 findings, one annotator who built the pipeline).
- `debug=True` fell from 11-14 plain outputs per model to 0-4 enriched, although only 4 of 50 prompts carried that warning.
- Enrichment added about 158 tokens per prompt (+290%), always 4-5 warnings, 23% precise against the dataset's own target CWEs.
- Functional failure was 19% plain and 63% enriched. Part of this is sandbox dependencies (`bcrypt`, `argon2`, `django`), part is models being stricter than the
  reference (missing environment variables, rejecting the test's input), part is unknown.
- Scanner coverage: Bandit has a rule for the target CWE on 26 of 50 tasks, Bandit plus Semgrep on 37, neither on 13.
- Gemini 2.5 Flash lost half its enriched outputs to extraction failure.
- 7 of 44 repairs ended in unparseable output and were dropped from the repair statistics.

---

## Part D. What is known, what is open, so what do we study

Known: CWE-aware text helps (A3, A4, A2 when precise); strong models use scanner feedback, weak ones do not (A2);
the first feedback round does most of the work (A6); a scanner report beats none (A7); security gains can hide functional loss (A5, A7);
analysers are inaccurate and a metric can be gamed by unparseable or empty code (A4, A6).

Open, and visible in our own data: (1) does the warning's content matter, or is any security-flavoured preamble enough; (2) how much of "vulnerability" is
scaffolding and noise rather than the requested code; (3) what a warning does to functionality, measured with the sandbox fixed; (4) whether scanner repair
beats blind repair and beats resampling at the same token budget; (5) the token and dollar price of each secure outcome.

So the study is a measurement-validity and cost study of prompt-level and repair-level scaffolding on current API-served models. The five RQs in
`PROPOSAL.md` are those five open points. It is not a claim that scaffolding is dead, and not a claim to have discovered secure-but-broken code.

---

## Part E. Course of action

Order, with the gate that must pass before the next step (details in `PROPOSAL.md` section 7):

1. Set up `v4/`: copy the frozen dataset, tests, offline harness, pinned Semgrep rules; write config, DB schema and `selfcheck`.
2. Engines: LLM client with usage logging; Engine A v4; judge (scaffold stripping, Bandit plus Semgrep, coverage table); sandbox with dependencies and the failure taxonomy; the two repair arms.
3. Offline validation on the archived pilot: re-judge, re-test, produce the coverage table, and list the tests that fail most outputs for human review.
4. Runner: resumable queue, rate limiting, spend cap, pause and resume, repetition-outermost order.
5. UI (7 pages), MCP server (8 tools), CLI.
6. Gates: selfcheck, 60-cell dry run with a mid-run kill, forced rate-limit test, MCP client test, docs consistency grep.
7. Launch the run. Everything after that is waiting, then reading the generated Results page.
8. The paper is written afterwards from `export/`.
