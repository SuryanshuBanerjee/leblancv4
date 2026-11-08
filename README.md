# LeBlanc

**Do the usual tricks for making AI-written code secure actually work on today's models?**

LeBlanc is a small, reproducible study of the two most common tricks: adding a security line to the prompt, and running a security scanner and asking the model to fix what it finds. It also ships the tool we built to run the study: a test harness, a sandbox, a web UI and an MCP server.

Short answer, from 2,520 scored outputs on three current models:

- **Scanners and real security tests barely agree.** Bandit and Semgrep flagged about 13% of outputs. About 55–60% failed the task's own security test. Agreement between the two: Cohen's κ = 0.004, which is no better than chance.
- **"Scan, then fix" makes the scanner happy and changes nothing else.** After scanner-guided repair, scanner-clean code went from about 87% to 98–100%. The share of code that was both secure and working, as judged by the tests, changed by **0.0 points** on all three models.
- **A one-line security instruction in the prompt is the only thing that clearly helped**, and only on some models. A CWE-specific warning cut security-test failures by 11.5 points on Gemini. A plain "write secure code" line cut them by 11.9 points on DeepSeek. Neither helped gpt-oss-20b. It costs 9–30 extra prompt tokens and did not make the code work worse.
- **The whole run cost $0.78** and took 39 minutes.

The takeaway: if a pipeline says code is secure because a scanner found nothing, that claim is weak. Check security with executable tests.

---

## Contents

- [For AI agents and new contributors](#for-ai-agents-and-new-contributors)
- [Why this exists](#why-this-exists)
- [What earlier papers found](#what-earlier-papers-found)
- [What we did](#what-we-did)
- [Results](#results)
- [What the MCP server is for (and what it isn't)](#what-the-mcp-server-is-for-and-what-it-isnt)
- [Limitations](#limitations)
- [Running it yourself](#running-it-yourself)
- [Repository layout](#repository-layout)
- [Words used in this README](#words-used-in-this-readme)

---

## For AI agents and new contributors

Read this section before you change or run anything.

**Where the truth is**
- `run/leblanc.db` (SQLite) holds every call, output, scan and test result from the main run: 2,520 cells, 0 failed.
- `paper/numbers.json` holds every number in this README and the paper. `python paper/make_figures.py` regenerates it from the database. Do not edit numbers by hand. Regenerate them.
- `docs/PROPOSAL.md` is the frozen design. `docs/DECISIONS.md` logs every change and why. `docs/CITATIONS.md` has notes on every source.

**Entry points**

| What | File |
|---|---|
| CLI: `python -m leblanc <command>` | `leblanc/cli.py`. Commands: `plan`, `run`, `start`, `pause`, `status`, `preflight`, `selfcheck`, `web`, `export`, `audit-sample`, `engine-a-eval` |
| Run loop and cell planning | `leblanc/runner.py` |
| Model calls (OpenRouter) | `leblanc/llm.py` |
| Scanners (Bandit + Semgrep) | `leblanc/judge.py` |
| Sandbox (host side, worker side) | `leblanc/sandbox.py`, `leblanc/sandbox_worker.py` |
| Statistics and verdicts | `leblanc/stats.py`, `leblanc/report.py` |
| Web UI | `leblanc/web/app.py` |
| MCP server | `leblanc/mcp_server.py` |
| All settings | `config/study.json`, `config/models.json`, `config/prices.json` |

**Rules**
1. **Do not run model-written code on the host.** Code in `run/leblanc.db`, `run/export/` and `run/scan_tmp/` came from LLMs, and some of it is deliberately insecure. Run it only through `leblanc/sandbox.py` (WSL + bubblewrap). Static scanning is safe; running the code is not.
2. **Do not weaken the sandbox.** If you change `leblanc/sandbox.py` or `leblanc/sandbox_worker.py`, run `python -m leblanc selfcheck` and confirm the isolation checks still pass.
3. **Know which commands cost money.** `start`, `run` and `preflight` call paid models. So does the MCP tool `repair_code`, which refuses unless `confirm_spend=true`. Every other command is free and offline. A run stops itself at `max_spend_usd` in `config/study.json` ($4.50).
4. **The design is frozen by hash.** `leblanc/config.py:study_hash` hashes `config/study.json`, `config/models.json`, `data/tasks.json`, `data/tasks_lenient.json` and `data/kb.json`. If any of them changes, `start` refuses to add cells to an existing database. For a new experiment, point `LEBLANC_DB` at a new file and log the change in `docs/DECISIONS.md`.
5. **Never print, log or commit an API key.** Keys are read only through `leblanc/config.py:get_key`, from the environment or a `.env` file.
6. **The key in the dataset is fake.** `data/codeseceval/SecEvalBase.jsonl` contains a hard-coded OpenAI-style key. It is part of a benchmark task about hard-coded credentials. Leave it alone: `data/codeseceval/SHA256SUMS` pins the dataset.
7. **Before you call a change done**, run `python -m pytest tests -q` (12 tests). If you touched the sandbox, scanners or tasks, also run `python -m leblanc selfcheck`.

---

## Why this exists

AI models write a lot of code now, and that code is often insecure. Two fixes come up again and again because they need no access to the model itself:

1. **Prompt it.** Tell the model to write secure code, or warn it about a specific weakness (for example "use parameterised SQL queries").
2. **Scan and repair.** Run a static analyser (Bandit, Semgrep, CodeQL) on the output, send the findings back, and ask the model to fix them.

Almost all the evidence for both comes from 2023–2024 models like GPT-3.5 and GPT-4. And most repair studies judge success with the same scanner that drives the repair. So "the scanner stopped complaining" gets counted as "the code became secure". Nobody had checked whether that holds when you test the code by running it.

We wanted to know three things on current, cheap API models: Do these tricks still help? Do they break working code? What do they cost in tokens?

## What earlier papers found

These are the eight papers this project builds on. The PDFs are in [`docs/`](docs/), named by row number, and the arXiv links go to each paper's page.

| # | Paper | PDF | What it found | Why it matters here |
|---|---|---|---|---|
| 1 | Yan et al. 2025, [*Guiding AI to Fix Its Own Flaws*](https://arxiv.org/abs/2506.23034) | [One.pdf](docs/One.pdf) | 8 models write vulnerable code 9.8–42.1% of the time. Hints help strong models; wrong hints make things worse. Repair with explained CodeQL feedback helps strong models. | Judged by CodeQL alone. We check whether scanner-judged gains hold up under executable tests. |
| 2 | Wang et al. 2023, [*SecuCoGen*](https://arxiv.org/abs/2310.16263) | [Two.pdf](docs/Two.pdf) | A hand-written, CWE-aware task description took GPT-3.5 from 31% to 86% secure-and-correct (SEC@2). Repair was weak. | Upper bound for a human-written warning on an old model. |
| 3 | Wang et al. 2024, [*CodeSecEval*](https://arxiv.org/abs/2407.02395) | [Three.pdf](docs/Three.pdf) | Built a benchmark with real functional and security tests. Claude 3 Opus went from 13.8% to 39.9% Pass@1 with a vulnerability-aware prompt. | **Our tasks and tests come from the extended version of this dataset.** |
| 4 | Hasan et al. 2025, [*DiSCo / LPO*](https://arxiv.org/abs/2506.00419) | [Four.pdf](docs/Four.pdf) | One round of scanner feedback cut issues from 37.4% to 12.7%; three rounds reached 9.4% but produced over-engineered code. | Why we cap repair at 3 rounds. Their method needs fine-tuning, which API users can't do. |
| 5 | Fu et al. 2024, [*CODEGUARD+*](https://arxiv.org/abs/2405.00218) | [Five.pdf](docs/Five.pdf) | A defence that looked 71.9% "secure" was only 29.1% secure *and* correct. | Origin of our "secure and working" metric. Security scores without correctness mislead. |
| 6 | Zhu et al. 2024, [*DomainEval*](https://arxiv.org/abs/2408.13204) | [Six.pdf](docs/Six.pdf) | Models pass 82% of computation tasks but only 33% of cryptography tasks. | Code quality varies a lot by domain. Functional only, no security. |
| 7 | Hajipour et al. 2024, [*HexaCoder*](https://arxiv.org/abs/2409.06446) | [Seven.pdf](docs/Seven.pdf) | GPT-4 "repaired" 43% of code with no report, 63% with a CodeQL report, 84% with report plus a hint. | "Repaired" there means CodeQL went quiet. Our `blind_repair` is their no-report control. |
| 8 | Majdinasab et al. 2023, [*Copilot replication*](https://arxiv.org/abs/2311.11177) | [Eight.pdf](docs/Eight.pdf) | Vulnerable Copilot Python suggestions dropped from 36.5% to 27.3% on a newer version. | Models improve over time, so old numbers need re-measuring. |

Two more papers shaped the design but are cited from their abstracts: Tony et al. 2024 ([arXiv 2407.07064](https://arxiv.org/abs/2407.07064)) and He et al. 2024, SafeCoder ([arXiv 2402.09497](https://arxiv.org/abs/2402.09497)). They compared generic and CWE-specific prompts on older models and disagreed about whether prompting helps. Full notes on every source, including which numbers we checked against the PDFs: [`docs/CITATIONS.md`](docs/CITATIONS.md).

**The gap we fill:** papers 1, 4, 7 and 8 measure security with static analysers. Papers 3 and 5 warned that this can mislead. We put both kinds of judge on the same outputs, on current models, and measure the cost.

## What we did

**Tasks.** 56 Python tasks from CodeSecEval, covering 38 weakness types (CWEs). Each task has a prompt, plus a functional test and a security test written by the dataset authors. Before choosing tasks we ran every reference solution in our sandbox and dropped tasks whose tests were broken or only accepted one specific implementation. Selection is seeded and reproducible ([`scripts/select_tasks.py`](scripts/select_tasks.py)). Reasons for every excluded task: [`data/exclusions.json`](data/exclusions.json).

**Models.** Three cheap, current models from three companies, all through OpenRouter, each pinned to named hosts:
`openai/gpt-oss-20b`, `google/gemini-3.5-flash-lite`, `deepseek/deepseek-v4.1-flash`.

**What we compared.** Every task, on every model, 3 times each:

| Strategy | What the model gets |
|---|---|
| `plain` | Just the task. |
| `generic` | The task plus "Write secure code and avoid common security vulnerabilities." |
| `targeted` | The task plus one line about that task's own CWE, e.g. "Use parameterised queries". |
| `scan_repair` | The plain output, its Bandit/Semgrep findings, and "fix these". Up to 3 rounds. |
| `blind_repair` | The plain output and "review this for vulnerabilities and fix any you find". No scanner. |
| `resample` | No new call: just take another plain sample until the scanner is happy. A cost-matched baseline for `scan_repair`. |

**How every output is judged.** Three independent ways:
1. **Scanners:** Bandit + Semgrep (pinned rule set).
2. **Security test:** the dataset's own security test, run in a sandbox.
3. **Functional test:** the dataset's own functional test, run in a sandbox.

"Secure and working" means it passed both tests.

**Safety.** Model-written code runs only inside WSL Ubuntu, in a bubblewrap jail per test: no network, no access to Windows drives, no secrets, CPU, memory and time limits. A self-check proves the jail works before each run.

**Stats.** Pairs are matched by task and repetition. Exact McNemar tests, Benjamini–Hochberg correction, cluster-bootstrap 95% intervals over tasks. The decision rules ("yes / no / unclear / ceiling") were written down before the main run. See [`docs/PROPOSAL.md`](docs/PROPOSAL.md) for the frozen design and [`docs/DECISIONS.md`](docs/DECISIONS.md) for every change and why.

## Results

### With no help (RQ1)

| Model | Scanner flagged | Failed security test | Passed functional test | Secure and working |
|---|---|---|---|---|
| gpt-oss-20b | 12.5% | 56.4% | 57.1% | 36.1% |
| gemini-3.5-flash-lite | 13.1% | 60.7% | 56.7% | 27.4% |
| deepseek-v4.1-flash | 12.5% | 54.1% | 65.0% | 35.1% |

Out of 1,202 outputs judged both ways, 593 were scanner-clean but failed the security test. κ = 0.004.

**Why the scanners miss:** the weaknesses these models leave behind are mostly *missing* checks: no input validation, wrong file permissions, no size limits, no salt, no authorisation. Scanners look for dangerous calls that are *present* (`pickle.loads`, `shell=True`). They can't see what isn't there.

### Prompt preambles (RQ2, RQ3)

Change in security-test failure rate versus `plain`, in percentage points (negative is better):

| Model | `generic` | `targeted` |
|---|---|---|
| gpt-oss-20b | −1.6 (no effect) | +1.5 (no effect) |
| gemini-3.5-flash-lite | −3.0 (no effect) | **−11.5 (yes)** |
| deepseek-v4.1-flash | **−11.9 (yes)** | −5.9 (unclear) |

No preamble significantly reduced the share of working code.

### Repair (RQ4, RQ5)

Secure-and-working rate, and mean tokens per output:

| Model | `plain` | `scan_repair` | `blind_repair` | `resample` |
|---|---|---|---|---|
| gpt-oss-20b | 36.1% · 549 tok | 36.1% · 762 tok | 37.2% · 1,539 tok | 36.1% · 678 tok |
| gemini-3.5-flash-lite | 27.4% · 365 tok | 27.4% · 500 tok | 30.4% · 1,000 tok | 27.4% · 454 tok |
| deepseek-v4.1-flash | 35.1% · 922 tok | 35.1% · 1,053 tok | 36.3% · 4,140 tok | 35.1% · 1,148 tok |

`scan_repair` raised scanner-clean output to 97.6–100% and moved the tested result by exactly zero. `blind_repair` gained at most 3 points for 2.7–4.5× the tokens. Repairs rarely broke working code (0–4.3%).

All numbers above come from [`paper/numbers.json`](paper/numbers.json), which is generated from the run database. Full write-up: [`paper/leblanc_paper.pdf`](paper/leblanc_paper.pdf).

### What a developer should take from this

1. Add a one-line security instruction to your code-generation prompt. It's nearly free. Test which form works for your model.
2. Don't treat "Bandit/Semgrep found nothing" as "secure".
3. Don't count a scan-and-fix loop as a security improvement unless you test the result by running it.

## What the MCP server is for (and what it isn't)

The repo includes an MCP server (`leblanc-v4`) so an AI coding assistant such as Claude Code can call LeBlanc's pieces as tools. Be clear about which tools the results support:

| Tool | What it does | Backed by the results? |
|---|---|---|
| `analyze_prompt` | Returns a security line to add to a coding prompt (generic, or up to 3 matched CWE warnings) and its token cost. | **Yes.** This is the one intervention that helped. Caveat: matching the right CWE from the prompt alone works 43% of the time on held-out tasks. |
| `recommend` | For a model in the study, returns the strategy with the best measured secure-and-working rate, preferring the cheaper one on near-ties. | **Yes.** Reads straight from the measured results. |
| `results_summary`, `project_status` | Report the study's numbers and run progress. | Reporting only. |
| `scan_code`, `scan_path`, `audit_response` | Run Bandit + Semgrep on code. | **Partly.** Good at spotting dangerous calls. Our results show it is *not* a security verdict, and every response says so. |
| `repair_code` | Asks a model to fix code (scanner-guided or blind). Costs money; refuses unless `confirm_spend=true`. | **No, for scanner mode.** The study found scanner-guided repair does not improve tested security. Kept for comparison. |

Put plainly: the research is the contribution. The MCP server is a way to use the parts the research supports inside an assistant. It is not a security guarantee.

## Limitations

- **56 tasks, Python only, 3 repetitions.** Enough for the effects above, too few for small effects. Some results are "unclear" rather than forced into yes or no.
- **Three cheap models.** No frontier flagships. Results describe the cheap tiers that most automated pipelines call.
- **Tests only catch what their authors wrote.** Executable tests underestimate weaknesses no test exercises.
- **Lenient scoring is the primary score.** Prompts say "raise an appropriate exception" without naming one, but published tests demand the reference's exact class. The primary score accepts any exception; the strict published score is always reported next to it.
- **12 tasks fail every output's functional test.** Contrasts are paired within task, so this lowers sensitivity but doesn't bias them.
- **The false-positive audit has one annotator so far, and it is an AI** (Claude, which is not one of the tested models). It labelled 22 of 30 sampled scanner findings as false positives. **The human annotation is still to do** (see below).
- **Training-data contamination is possible** for tasks derived from SecurityEval (public since 2022).

### Still to do

- [ ] Human annotation of the 30-finding audit sample (Audit page in the UI, about an hour). Cohen's κ between annotators appears on the Results page once done.

## Running it yourself

### Requirements

- Windows with **Python 3.13**
- **WSL Ubuntu** with `bubblewrap` and a Python virtual environment holding [`data/sandbox-requirements.txt`](data/sandbox-requirements.txt) (all model-written code runs here, never on Windows)
- An **OpenRouter** API key with credit. The full run costs about $0.80 and stops itself at $4.50.

### Setup

1. Install the Windows-side packages:

   ```bash
   pip install flask bandit semgrep mcp pytest
   ```

2. Set up the sandbox inside WSL Ubuntu. The first line of `data/sandbox-requirements.txt` records the Python version (3.14.4) and is not a package, so filter it out:

   ```bash
   wsl -d Ubuntu
   sudo apt install -y bubblewrap python3-venv
   python3 -m venv ~/leblanc-sbx
   grep -v '^Python' /mnt/<drive>/<path-to-repo>/data/sandbox-requirements.txt > /tmp/sbx-req.txt
   ~/leblanc-sbx/bin/pip install -r /tmp/sbx-req.txt
   ```

3. Point `config/study.json` at your sandbox. Set `sandbox.venv` to your venv (for example `/home/<you>/leblanc-sbx`) and `sandbox.worker` to the WSL path of `leblanc/sandbox_worker.py` in your clone (for example `/mnt/c/code/leblanc/leblanc/sandbox_worker.py`). The shipped values are the paths on the original machine.

   This edit changes the study hash (rule 4 above). The shipped database stays readable, but for a new run, use a fresh database:

   ```bash
   set LEBLANC_DB=run\my_run.db          # cmd
   $env:LEBLANC_DB = "run\my_run.db"     # PowerShell
   ```

4. Put your OpenRouter key in a file named `.env` in this folder or its parent. **Never commit it.** `.env` is in `.gitignore`.

   ```
   OPENROUTER_API_KEY=sk-or-...
   ```

### Check everything works (free)

```bash
python -m pytest tests -q        # unit tests
python -m leblanc selfcheck      # 14 checks: scanners, sandbox isolation, all 56 reference solutions
python -m leblanc preflight      # one real call per model (under $0.01)
```

### Run the study

The easy way: double-click `LeBlanc.bat`. Your browser opens on the Run page; press **Start run**. If anything interrupts it (crash, reboot, network drop), open it again and press **Resume**. Nothing is lost or repeated.

Or from the command line:

```bash
python -m leblanc start      # start the run in the background
python -m leblanc status     # progress and spend
python -m leblanc pause      # stop after current calls; `start` resumes
python -m leblanc web        # the UI at http://127.0.0.1:8765
python -m leblanc export     # CSV, JSON and LaTeX tables into run/export/
```

The UI has pages for Run, Results (all five research questions, computed live from the database), Runs (per-output detail), Audit, Dataset, Setup and Export.

### Use the MCP server in Claude Code

```bash
claude mcp add leblanc-v4 -e PYTHONPATH=/path/to/this/repo -- python -m leblanc.mcp_server
```

### Rebuild the paper from the data

```bash
python paper/make_figures.py     # every number, table and figure from run/leblanc.db
# then run pdflatex twice in paper/, report/ and guide/
```

## Repository layout

```
config/    study.json (all settings)   models.json (models, pinned hosts)   prices.json
data/      tasks.json (the 56 tasks)   kb.json (CWE warnings)   codeseceval/ (pinned dataset copy)   semgrep/ (pinned rules)
leblanc/   the harness: runner, llm client, judge (scanners), sandbox, stats, report, web UI, mcp_server, cli
scripts/   validate_dataset.py   select_tasks.py   build_lenient.py
tests/     unit tests
run/       leblanc.db (every call and result from the main run)   rehearsal.db (small test run)   export/ (CSV, JSON, LaTeX)
paper/     research paper (PDF + LaTeX), figures, numbers.json
report/    project report (PDF + LaTeX)
guide/     plain-language companion guide for the viva (PDF + LaTeX)
docs/      PROPOSAL.md (frozen design)   DECISIONS.md (change log)   CITATIONS.md (sources)
           One.pdf ... Eight.pdf (the eight source papers, numbered as in the table above)
           archive/ (earlier planning notes)
```

## Words used in this README

- **CWE**: Common Weakness Enumeration, a numbered catalogue of software weakness types (CWE-89 is SQL injection).
- **Static analyser / scanner**: a tool that reads code without running it and matches risky patterns. Here: Bandit and Semgrep.
- **Executable test**: code that runs the program and checks its behaviour, for example "does it reject `../../etc/passwd`?".
- **Secure and working**: passes both the task's functional test and its security test.
- **Preamble**: the extra line added after the task prompt.
- **Cohen's κ (kappa)**: agreement between two judges beyond chance. 1 is perfect, 0 is chance.
- **pp**: percentage points. Going from 60% to 50% is −10 pp.
- **MCP**: Model Context Protocol, a standard way for AI assistants to call outside tools.
