# Citations: what each paper says, and how we may cite it

Verification marks: **verified** = checked against the paper's PDF text in this project; **abstract** = from the
paper's abstract or landing page only (read the full text before quoting a number); **read** = from a full read by
a helper, not re-checked. Do not cite a number that is not marked verified without checking it first.
The PDFs are in this folder (`docs/One.pdf` ... `docs/Eight.pdf`).

## Dataset and evaluation basis

**Wang et al., CodeSecEval** (Three.pdf is the 2024 arXiv version, 2407.02395; the dataset we use is the extended
ISSTA 2026 version: "Toward Secure Code Generation: Bridging Correctness and Security via Task-Adaptive
Vulnerability Modeling and Execution-Based Benchmarking", 255 tasks, 77 CWE types, Hugging Face
`JasonWang1/CodeSecEval`).
- Verified (2024 PDF): 180 tasks, 44 CWE types, secure and insecure code and executable tests; Pass@1 for direct
  generation 12.44 (GPT-4) and 13.83 (Claude 3 Opus); Claude 13.83 to 39.89 with a hand-written
  vulnerability-aware problem statement. The dataset README states the split tests (Test-FP, Test-SP) should be
  verified locally; we did (PROPOSAL 4.1).
- Cite as: the source of our tasks and tests; evidence that hand-written vulnerability-aware prompts helped on 2024 models.

**Siddiq and Santos 2022, SecurityEval.** 121 prompts, 69 CWEs (per CodeSecEval's table). SecEvalBase is derived from it.

**Fu et al. 2024, CODEGUARD+** (Five.pdf). Verified: SVEN looked 71.91% secure but only 29.14% secure-pass@1.
- Cite as: "secure but broken" output is counted as success unless correctness is tested; origin of the
  secure-pass idea we use.

## Prompting for security (RQ2, RQ3)

**Tony et al. 2024, "Prompting Techniques for Secure Code Generation: A Systematic Investigation"**
(arXiv 2407.07064). Abstract: zero-shot prompts with naive, CWE-specific and comprehensive security cues on GPT-3,
GPT-3.5 and GPT-4 over 150 Python tasks; the best variant differed by model; Recursive Criticism and Improvement
(RCI) reduced weaknesses. Cite as: prior generic-vs-specific comparison on 2023 models; we replicate on current
models and add function and token cost. Read the full text before quoting percentages.

**He et al. 2024, "Instruction Tuning for Secure Code Generation" (SafeCoder, ICML 2024)** (arXiv 2402.09497).
Abstract and search summary: compares a generic and a CWE-specific security instruction and reports that
prompting does not significantly improve security for state-of-the-art instruction-tuned models. Cite as: the
counter-finding that motivates our ceiling hypothesis. Read the full text before quoting numbers.

**Wang et al. 2023, SecuCoGen** (Two.pdf). Verified: GPT-3.5 SEC@1/SEC@2 = 0.2667/0.3111 plain, 0.5000/0.5889
one-shot, 0.7333/0.8556 with a human-written CWE-aware statement ("31% to 86%" is SEC@2). Cite as: upper bound
of a hand-written warning on GPT-3.5, not a benchmark for automatic warnings on 2026 models.

**Yan et al. 2025, "Guiding AI to Fix Its Own Flaws"** (One.pdf). Verified: average target-CWE and any-vulnerability
rates 8.5% and 13.2% on SecCodePLT, 20.7% and 33.4% on SecurityEval (CodeQL). Read: capability modulates every
effect; small open models gained nothing from repair. Cite as: reason for a capability spread and for reporting
target-CWE and any-finding rates.

## Repair and feedback (RQ4)

**Hasan et al. 2025, DiSCo/LPO** (Four.pdf). Verified: one scanner-feedback round cut issues from 37.4% to 12.7% in
their synthetic data; three rounds gave 9.4% with over-engineered, lower-quality code. Cite as: multi-round scanner
feedback has diminishing and harmful returns; reason for our 3-round cap.

**Hajipour et al. 2024, HexaCoder** (Seven.pdf). Verified: GPT-4-turbo repair rate 42.66% with no report, 63.33%
with a CodeQL report, 83.99% with report plus hint (150 codes, five CWEs). Cite as: the no-report condition is a
real control; our `blind_repair` is that control.

**Alrashedy et al., "Can LLMs Patch Security Issues?" (FDSP)** (arXiv 2312.00024). Abstract: Feedback-Driven Security
Patching uses Bandit output to guide LLM fixes. Cite as: closest prior to our `scan_repair`. Read before quoting numbers.

**Kim et al. 2024, Codexity** (arXiv 2405.03927). Abstract: re-queries the model until a secure answer is found or
a query limit is reached. Cite as: a resampling-style loop, not token-matched against repair.

## Context

**Pearce et al. 2022, "Asleep at the Keyboard".** About 40% of Copilot completions in security-relevant scenarios
vulnerable (36.54% for Python, per Majdinasab et al.). Cite as a Copilot-2021 number only.

**Majdinasab et al. 2023, Copilot replication** (Eight.pdf). Verified: vulnerable share 36.54% to 27.25% on a newer
Copilot (Python). Studies weakness diversity only, not prompt phrasing.

**Zhu et al. 2025, DomainEval** (Six.pdf). Verified: average Pass@1 82.44% on computation vs 33.08% on cryptography.
Functional only; no security. Cite only for "function varies a lot by domain".

## Claims we must not make
- "Pearce's 40% is the average LLM." It is Copilot in 2021.
- "Nobody has compared generic and CWE-specific prompts." Tony et al. and He et al. did.
- "No paper runs multi-round scanner repair." DiSCo and FDSP do.
- "First ever". Use the allowed wording in PROPOSAL section 1.
