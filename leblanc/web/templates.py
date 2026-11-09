"""Page templates. Flat: black on white, square corners, one link colour, no shadows, no animation."""

CSS = """
:root { --fg:#111; --muted:#555; --line:#c8c8c8; --soft:#f3f3f3; --link:#0645ad; --bad:#9b1c1c; --good:#1d5e20; --mark:#fff3b0; }
* { box-sizing:border-box; border-radius:0; }
html { font-size:17px; }
body { margin:0; background:#fff; color:var(--fg); font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; line-height:1.55; }
a { color:var(--link); text-decoration:none; } a:hover { text-decoration:underline; }
header { border-bottom:2px solid var(--fg); }
header .in, main { max-width:1280px; margin:0 auto; padding:0 24px; }
header .in { display:flex; flex-wrap:wrap; align-items:baseline; gap:8px 28px; padding-top:14px; padding-bottom:12px; }
header .brand { font-weight:700; font-size:1.15rem; color:var(--fg); margin-right:12px; }
header nav a { margin-right:22px; font-size:1rem; }
header nav a.on { color:var(--fg); font-weight:700; border-bottom:2px solid var(--fg); }
main { padding-top:28px; padding-bottom:80px; }
h1 { font-size:1.6rem; margin:0 0 6px; } h2 { font-size:1.25rem; margin:44px 0 6px; padding-top:16px; border-top:1px solid var(--line); }
h3 { font-size:1.02rem; margin:26px 0 8px; }
p { margin:6px 0 12px; max-width:900px; } .muted { color:var(--muted); } .small { font-size:.88rem; }
table { border-collapse:collapse; width:100%; margin:8px 0 18px; font-size:.93rem; }
th, td { border:1px solid var(--line); padding:7px 10px; text-align:left; vertical-align:top; }
th { background:var(--soft); font-weight:600; }
td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
.scroll { overflow-x:auto; }
pre, code { font-family:Consolas,"SF Mono",Menlo,monospace; font-size:.86rem; }
pre { background:var(--soft); border:1px solid var(--line); padding:12px 14px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; }
.code td { border:none; padding:0 10px; font-family:Consolas,Menlo,monospace; font-size:.86rem; white-space:pre-wrap; }
.code { border:1px solid var(--line); background:#fafafa; }
.code td.ln { color:#888; text-align:right; width:44px; user-select:none; border-right:1px solid var(--line); }
.code tr.hit td { background:var(--mark); } .code tr.scaf td { background:#eee; color:#777; }
mark { background:var(--mark); }
.btn { display:inline-block; border:1px solid var(--fg); background:#fff; color:var(--fg); padding:8px 18px; font-size:1rem; cursor:pointer; margin:0 8px 8px 0; font-family:inherit; }
.btn:hover { background:var(--fg); color:#fff; text-decoration:none; } .btn.primary { background:var(--fg); color:#fff; }
input[type=text], textarea, select { border:1px solid var(--fg); padding:7px 9px; font-size:1rem; font-family:inherit; background:#fff; }
textarea { width:100%; min-height:110px; }
.kv { display:grid; grid-template-columns:max-content 1fr; gap:6px 22px; margin:10px 0 18px; }
.kv div:nth-child(odd) { color:var(--muted); }
.big { font-size:2rem; font-weight:700; line-height:1.1; }
.stats { display:flex; flex-wrap:wrap; gap:0; border:1px solid var(--line); margin:12px 0 20px; }
.stats > div { padding:14px 22px; border-right:1px solid var(--line); min-width:170px; }
.stats > div:last-child { border-right:none; }
.verdict { font-weight:700; } .v-yes { color:var(--good); } .v-no { color:var(--fg); } .v-unclear, .v-insufficient, .v-ceiling { color:var(--muted); }
.bad { color:var(--bad); } .good { color:var(--good); }
.state { font-weight:700; text-transform:uppercase; letter-spacing:.04em; }
.filters { display:flex; flex-wrap:wrap; gap:10px 14px; align-items:end; margin:8px 0 14px; }
.filters label { display:flex; flex-direction:column; font-size:.85rem; color:var(--muted); }
.sentence { font-size:1.05rem; border-left:3px solid var(--fg); padding:4px 0 4px 14px; }
svg text { font-family:inherit; }
@media (max-width:700px) { html { font-size:16px; } header .in, main { padding:0 16px; } .stats > div { min-width:50%; border-bottom:1px solid var(--line); } }
"""

BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - LeBlanc</title>{% if refresh %}<meta http-equiv="refresh" content="{{ refresh }}">{% endif %}
<style>{{ css|safe }}</style></head><body>
<header><div class="in"><a class="brand" href="/">LeBlanc v4</a><nav>
{% for href, label in nav %}<a href="{{ href }}" class="{{ 'on' if active == href else '' }}">{{ label }}</a>{% endfor %}
</nav></div></header><main>{{ body|safe }}</main></body></html>"""

RUN = """
<h1>Run</h1>
<p class="muted">State is read from the database every 10 seconds. The runner is a separate process: closing this page does not stop it.</p>
<div class="stats">
  <div><div class="muted small">state</div><div class="big state">{{ state }}</div>{% if pid %}<div class="small muted">pid {{ pid }}</div>{% endif %}</div>
  <div><div class="muted small">cells done</div><div class="big">{{ done }} / {{ total }}</div><div class="small muted">{{ pct }}</div></div>
  <div><div class="muted small">spend</div><div class="big">${{ '%.3f'|format(spend) }}</div><div class="small muted">cap ${{ cap }}</div></div>
  <div><div class="muted small">estimated finish</div><div class="big">{{ eta }}</div><div class="small muted">{{ rate }}</div></div>
  <div><div class="muted small">failed cells</div><div class="big {{ 'bad' if failed else '' }}">{{ failed }}</div></div>
</div>
<form method="post" action="/control">
  {% if not pid %}<button class="btn primary" name="action" value="start">{{ 'Resume' if done else 'Start run' }}</button>{% endif %}
  {% if pid %}<button class="btn" name="action" value="pause">Pause</button><button class="btn" name="action" value="stop">Stop</button>{% endif %}
</form>
{% if not total %}<p><b>No cells planned yet.</b> Start run plans every cell first (56 tasks x 3 models x 3 arms x 3 repetitions, plus repairs).</p>{% endif %}
<h2>Progress by model and arm</h2>
<div class="scroll"><table><tr><th>model</th>{% for a in arms %}<th class="num">{{ a }}</th>{% endfor %}<th class="num">total</th></tr>
{% for m in grid %}<tr><td>{{ m.label }}</td>{% for a in arms %}<td class="num">{{ m.cells[a] }}</td>{% endfor %}<td class="num">{{ m.total }}</td></tr>{% endfor %}
</table></div>
<p class="small muted">Each entry is done / planned. Repetitions run in order: repetition {{ cur_rep or '-' }} is in progress; finished repetitions: {{ reps_done or 'none' }}.</p>
<h2>Pipeline stages</h2>
<table><tr><th>stage</th><th class="num">waiting</th><th class="num">done</th></tr>
<tr><td>model call</td><td class="num">{{ stage.llm_wait }}</td><td class="num">{{ stage.llm_done }}</td></tr>
<tr><td>static analysis (Bandit + Semgrep)</td><td class="num">{{ stage.judge_wait }}</td><td class="num">{{ stage.judge_done }}</td></tr>
<tr><td>sandbox tests (functional + security)</td><td class="num">{{ stage.test_wait }}</td><td class="num">{{ stage.test_done }}</td></tr></table>
<h2>Models</h2>
<table><tr><th>model</th><th>pinned host</th><th class="num">calls</th><th class="num">ok</th><th class="num">tokens in</th><th class="num">tokens out</th><th class="num">spend</th><th>last error</th></tr>
{% for r in models %}<tr><td>{{ r.label }}</td><td>{{ r.host }}</td><td class="num">{{ r.n }}</td><td class="num">{{ r.ok }}</td><td class="num">{{ r.tin }}</td><td class="num">{{ r.tout }}</td><td class="num">${{ '%.4f'|format(r.cost) }}</td><td class="small">{{ r.err }}</td></tr>{% endfor %}
</table>
<h2>Last 50 events</h2>
<table><tr><th style="width:170px">time</th><th style="width:70px">level</th><th>message</th></tr>
{% for e in events %}<tr><td class="small">{{ e.t }}</td><td class="small {{ 'bad' if e.level in ('error','warn') else '' }}">{{ e.level }}</td><td class="small">{{ e.msg }}</td></tr>{% endfor %}
</table>
"""

RESULTS = """
<h1>Results</h1>
<p class="muted">Computed from the database at {{ meta.generated_at }}. {{ meta.cells_done }} of {{ meta.cells_total }} cells done; complete repetitions: {{ meta.reps_complete or 'none yet' }}.
Nothing on this page is typed by hand. Until all three repetitions are complete, treat every number as provisional.</p>
{% if chart %}<h2>Security against tokens</h2>
<p>Each point is one strategy on one model: how often the output is secure and works (up) against mean tokens spent per task attempt (right). Up and to the left is better.</p>
{{ chart|safe }}{% endif %}
{% for s in sections %}
<h2 id="{{ s.id }}">{{ s.id }}. {{ s.question }}</h2>
{% if s.sentence %}<p class="sentence">{{ s.sentence }}</p>{% endif %}
{% for t in s.tables %}
<h3>{{ t.title }}</h3>
{% if t.columns %}<div class="scroll"><table><tr>{% for c in t.columns %}<th>{{ c }}</th>{% endfor %}</tr>
{% for row in t.rows %}<tr>{% for v in row %}<td class="{{ 'verdict v-' ~ v if v in ('yes','no','unclear','insufficient','ceiling') else '' }}">{{ v }}</td>{% endfor %}</tr>{% endfor %}
{% if not t.rows %}<tr><td colspan="{{ t.columns|length }}" class="muted">no data yet</td></tr>{% endif %}
</table></div>{% endif %}
{% endfor %}{% endfor %}
<h2>Engine A retrieval (offline)</h2>
<p>How often the warnings retrieved from the prompt text alone include the task's own weakness. The study's targeted arm uses the correct warning directly; this measures what a real retriever would achieve.</p>
<table><tr><th>set</th><th class="num">tasks</th><th class="num">own CWE among warnings</th><th class="num">no warning</th><th class="num">mean warnings</th><th class="num">mean tokens</th><th class="num">max tokens</th></tr>
{% for k, v in engine_a.items() %}<tr><td>{{ k }}</td><td class="num">{{ v.tasks }}</td><td class="num">{{ '%.1f'|format(100*v.target_cwe_in_warnings) }}%</td><td class="num">{{ '%.1f'|format(100*v.no_warning) }}%</td><td class="num">{{ v.mean_warnings }}</td><td class="num">{{ v.mean_tokens }}</td><td class="num">{{ v.max_tokens }}</td></tr>{% endfor %}
</table>
"""

RUNS = """
<h1>Runs</h1>
<form class="filters" method="get">
{% for name, opts in filters %}<label>{{ name }}<select name="{{ name }}"><option value="">all</option>{% for o in opts %}<option {{ 'selected' if args.get(name) == o|string else '' }}>{{ o }}</option>{% endfor %}</select></label>{% endfor %}
<button class="btn">Filter</button></form>
<p class="muted small">{{ n }} matching cells{% if n > rows|length %}, showing the first {{ rows|length }}{% endif %}.</p>
<div class="scroll"><table><tr><th>cell</th><th>kind</th><th>status</th><th>extract</th><th class="num">scanner</th><th>functional</th><th>security</th><th>strict func.</th><th>strict sec.</th><th>repair</th><th class="num">tokens</th><th class="num">cost</th></tr>
{% for r in rows %}<tr><td><a href="/cell/{{ r.id }}">{{ r.id }}</a></td><td>{{ r.kind }}</td><td>{{ r.status }}</td><td>{{ r.extract or '' }}</td>
<td class="num {{ 'bad' if r.vuln_task else '' }}">{{ '' if r.vuln_task is none else (r.n_findings ~ ' finding' ~ ('s' if r.n_findings != 1 else '')) }}</td>
<td class="{{ 'good' if r.fpl_result == 'pass' else ('bad' if r.fpl_result == 'fail' else '') }}">{{ r.fpl_result or '' }}</td>
<td class="{{ 'good' if r.spl_result == 'pass' else ('bad' if r.spl_result == 'fail' else '') }}">{{ r.spl_result or '' }}</td>
<td class="small muted">{{ r.fp_result or '' }}</td><td class="small muted">{{ r.sp_result or '' }}</td>
<td>{{ r.repair_outcome or '' }}{% if r.rounds %} ({{ r.rounds }}){% endif %}</td><td class="num">{{ (r.tokens_in or 0) + (r.tokens_out or 0) }}</td><td class="num">{{ '%.5f'|format(r.cost_usd or 0) }}</td></tr>{% endfor %}
</table></div>
"""

CELL = """
<p><a href="/runs">Runs</a> / {{ c.id }}</p>
<h1>{{ c.id }}</h1>
<div class="kv">
<div>task</div><div><a href="/task/{{ c.task_id }}">{{ c.task_id }}</a> ({{ task.cwe }}, {{ task.source }} {{ task.source_id }})</div>
<div>model</div><div>{{ c.model }} via {{ c.provider or '-' }}</div>
<div>arm / kind / repetition</div><div>{{ c.arm }} / {{ c.kind }} / {{ c.rep }}</div>
<div>status</div><div>{{ c.status }}{% if c.last_error %} <span class="bad">({{ c.last_error }})</span>{% endif %}</div>
<div>extraction</div><div>{{ c.extract or '-' }} (finish reason: {{ c.finish_reason or '-' }})</div>
<div>scanner verdict</div><div>{% if c.vuln_task is none %}-{% elif c.vuln_task %}<span class="bad">flagged: {{ c.n_findings }} finding(s) in task code</span>{% else %}<span class="good">no finding in task code</span>{% endif %}{% if c.vuln_raw and not c.vuln_task %} (findings only on scaffolding){% endif %}</div>
<div>functional test (lenient, primary)</div><div>{{ c.fpl_result or '-' }} <span class="small muted">{{ c.fpl_detail or '' }}</span></div>
<div>security test (lenient, primary)</div><div>{{ c.spl_result or '-' }}{% if not sp_valid %} <span class="small muted">(lenient security test not valid for this task; not counted)</span>{% endif %} <span class="small muted">{{ c.spl_detail or '' }}</span></div>
<div>functional test (published, strict)</div><div>{{ c.fp_result or '-' }} <span class="small muted">{{ c.fp_detail or '' }}</span></div>
<div>security test (published, strict)</div><div>{{ c.sp_result or '-' }} <span class="small muted">{{ c.sp_detail or '' }}</span></div>
<div>repair</div><div>{{ c.repair_outcome or '-' }}{% if c.rounds is not none %}, {{ c.rounds }} round(s){% endif %}</div>
<div>tokens</div><div>{{ c.tokens_in }} in, {{ c.tokens_out }} out ({{ c.tokens_reasoning }} reasoning), {{ c.n_calls }} call(s), {{ '%.1f'|format(c.latency_s or 0) }} s, ${{ '%.6f'|format(c.cost_usd or 0) }}</div>
</div>
{% if c.prompt_sent %}<h2>Prompt as sent</h2>
{% if c.added_text %}<p>Added by the {{ c.arm }} arm ({{ c.added_chars }} characters, about {{ added_tokens }} tokens) is highlighted.</p>{% endif %}
<pre>{{ prompt_html|safe }}</pre>{% endif %}
{% if code_rows %}<h2>Final code</h2><p class="small muted">Highlighted lines carry a finding. Grey lines are scaffolding (excluded from the primary metric).</p>
<table class="code">{% for ln, text, cls in code_rows %}<tr class="{{ cls }}"><td class="ln">{{ ln }}</td><td>{{ text }}</td></tr>{% endfor %}</table>{% endif %}
{% if findings %}<h2>Findings</h2><table><tr><th>line</th><th>tool</th><th>rule</th><th>CWE</th><th>severity</th><th>on scaffolding</th><th>message</th></tr>
{% for f in findings %}<tr><td class="num">{{ f.line }}</td><td>{{ f.tool }}</td><td>{{ f.rule }}</td><td>{{ f.cwes }}</td><td>{{ f.severity }}</td><td>{{ 'yes' if f.on_scaffolding else 'no' }}</td><td class="small">{{ f.message }}</td></tr>{% endfor %}</table>{% endif %}
{% if rounds %}<h2>Repair rounds</h2>{% for r in rounds %}<h3>Round {{ r.round }}: {{ r.n_findings if r.n_findings is not none else 'no extractable code' }}{{ ' finding(s) after this round' if r.n_findings is not none else '' }}</h3><pre>{{ r.diff }}</pre>{% endfor %}{% endif %}
{% if calls %}<h2>Calls</h2><table><tr><th>round</th><th>ok</th><th>http</th><th>host</th><th class="num">in</th><th class="num">out</th><th class="num">reasoning</th><th class="num">seconds</th><th>finish</th><th class="num">cost</th><th>error</th></tr>
{% for k in calls %}<tr><td>{{ k.round }}</td><td>{{ 'yes' if k.ok else 'no' }}</td><td>{{ k.http_status or '' }}</td><td>{{ k.provider or '' }}</td><td class="num">{{ k.prompt_tokens or '' }}</td><td class="num">{{ k.completion_tokens or '' }}</td><td class="num">{{ k.reasoning_tokens or '' }}</td><td class="num">{{ k.latency_s }}</td><td>{{ k.finish_reason or '' }}</td><td class="num">{{ '%.6f'|format(k.cost_usd or 0) }}</td><td class="small">{{ k.error or '' }}</td></tr>{% endfor %}</table>{% endif %}
{% if c.response_text %}<h2>Raw response</h2><pre>{{ c.response_text }}</pre>{% endif %}
"""

AUDIT = """
<h1>Audit</h1>
<p>Each item is a scanner finding on generated code. Decide whether it is a real weakness in this code (true positive) or a false alarm (false positive).
Labels from other annotators are never shown. The sample is drawn once, at random, with the study seed, and then frozen.</p>
{% if not sample_n %}<form method="post" action="/audit/draw"><button class="btn primary">Draw the audit sample</button></form>
<p class="muted">Draw it after the run (or at least repetition 1) is complete, so that it covers all models and arms.</p>
{% else %}
<form method="get" class="filters"><label>annotator name<input type="text" name="who" value="{{ who }}"></label><button class="btn">Use this name</button></form>
{% if who %}<p>{{ who }}: {{ done }} of {{ sample_n }} labelled.</p>
{% if item %}
<h2>Finding {{ item.id }}: {{ item.tool }} {{ item.rule }} ({{ item.cwes }}), line {{ item.line }}</h2>
<p>{{ item.message }}</p>
<p class="small muted">Task {{ item.task_id }} ({{ item.cwe }}). Model and arm are hidden.</p>
<table class="code">{% for ln, text, cls in ctx %}<tr class="{{ cls }}"><td class="ln">{{ ln }}</td><td>{{ text }}</td></tr>{% endfor %}</table>
<form method="post" action="/audit/label"><input type="hidden" name="who" value="{{ who }}"><input type="hidden" name="fid" value="{{ item.id }}">
<p><input type="text" name="note" placeholder="optional note" style="width:100%"></p>
<button class="btn" name="label" value="tp">True positive</button><button class="btn" name="label" value="fp">False positive</button><button class="btn" name="label" value="unsure">Unsure</button></form>
{% else %}<p class="good">All items labelled.</p>{% endif %}{% endif %}
<h2>Summary</h2><table><tr><th>annotator</th><th class="num">labelled</th><th class="num">true positive</th><th class="num">false positive</th><th class="num">unsure</th></tr>
{% for r in summary.rows %}<tr>{% for v in r %}<td>{{ v }}</td>{% endfor %}</tr>{% endfor %}</table><p>{{ summary.kappa_text }}</p>
{% endif %}
"""

DATASET = """
<h1>Dataset and Engine A</h1>
<p>{{ tasks|length }} tasks from CodeSecEval (Wang et al., ISSTA 2026), selected by a seeded rule (scripts/select_tasks.py). Each task has a functional test and a security test written by the dataset authors.</p>
<h2>Try Engine A</h2>
<form method="post" action="/dataset"><textarea name="prompt" placeholder="Type any coding prompt">{{ prompt }}</textarea><p><button class="btn primary">Show what would be added</button></p></form>
{% if analysis %}<table><tr><th>CWE</th><th>name</th><th>matched words</th><th class="num">score</th></tr>
{% for w in analysis.warnings %}<tr><td>{{ w.cwe }}</td><td>{{ w.name }}</td><td>{{ (w.strong + w.weak)|join(', ') }}</td><td class="num">{{ w.score }}</td></tr>{% endfor %}
{% if not analysis.warnings %}<tr><td colspan="4">No warning: nothing in the prompt matched strongly enough. Nothing would be added.</td></tr>{% endif %}</table>
{% if analysis.text %}<p>Text added to the prompt (about {{ analysis.tokens }} tokens):</p><pre>{{ analysis.text }}</pre>{% endif %}{% endif %}
<h2>What each arm adds</h2>
<table><tr><th>arm</th><th>added text</th><th class="num">about tokens</th></tr>
<tr><td>plain</td><td class="muted">nothing</td><td class="num">0</td></tr>
<tr><td>generic</td><td>{{ generic }}</td><td class="num">{{ generic_tok }}</td></tr>
<tr><td>targeted</td><td>one line for the task's own CWE, for example: {{ example }}</td><td class="num">{{ example_tok }}</td></tr></table>
<h2>Tasks</h2>
<div class="scroll"><table><tr><th>id</th><th>CWE</th><th>source</th><th>entry point</th><th>prompt</th></tr>
{% for t in tasks %}<tr><td><a href="/task/{{ t.id }}">{{ t.id }}</a></td><td>{{ t.cwe }}</td><td class="small">{{ t.source }} {{ t.source_id }}</td><td><code>{{ t.entry_point }}</code></td><td class="small">{{ t.prompt[:160] }}{{ '...' if t.prompt|length > 160 else '' }}</td></tr>{% endfor %}
</table></div>
<h2>Excluded from the pool</h2><table><tr><th>task</th><th>reason</th></tr>{% for e in excluded %}<tr><td>{{ e.key }}</td><td class="small">{{ e.reason }}</td></tr>{% endfor %}</table>
"""

TASK = """
<p><a href="/dataset">Dataset</a> / {{ t.id }}</p><h1>{{ t.id }}: {{ t.cwe }}</h1>
<div class="kv"><div>source</div><div>{{ t.source }} {{ t.source_id }}</div><div>entry point</div><div><code>{{ t.entry_point }}</code></div>
<div>targeted warning</div><div>{{ warning }}</div></div>
<h2>Prompt</h2><pre>{{ t.prompt }}</pre>
<h2>Functional test (Test-FP)</h2><pre>{{ t.test_fp }}</pre>
<h2>Security test (Test-SP)</h2><pre>{{ t.test_sp }}</pre>
<h2>Secure reference</h2><pre>{{ t.secure_reference }}</pre>
<h2>Insecure reference</h2><pre>{{ t.insecure_reference }}</pre>
<h2>All cells for this task</h2><p><a href="/runs?task={{ t.id }}">Open in Runs</a></p>
"""

SETUP = """
<h1>Setup</h1>
<h2>Keys</h2><table><tr><th>key</th><th>present</th></tr>{% for k, v in keys %}<tr><td>{{ k }}</td><td class="{{ 'good' if v else 'bad' }}">{{ 'yes' if v else 'no: add it to .env' }}</td></tr>{% endfor %}</table>
<p class="small muted">Values are never shown. Keys are read from v4/.env or the parent folder's .env.</p>
<h2>Models</h2><table><tr><th>model</th><th>developer</th><th>tier</th><th>pinned host</th><th class="num">$ in / 1M</th><th class="num">$ out / 1M</th></tr>
{% for m in models %}<tr><td>{{ m.id }}</td><td>{{ m.developer }}</td><td class="small">{{ m.tier }}</td><td>{{ (m.provider_order or ['any'])|join(', ') }} {{ (m.quantizations or [])|join(', ') }}</td><td class="num">{{ prices.get(m.id, {}).get('input', '-') }}</td><td class="num">{{ prices.get(m.id, {}).get('output', '-') }}</td></tr>{% endfor %}</table>
<p class="small muted">{{ pin_note }}</p>
<h2>Study</h2><div class="kv"><div>study hash</div><div><code>{{ hash }}</code>{% if db_hash and db_hash != hash %} <span class="bad">differs from the database's planned hash {{ db_hash }}: the configuration changed after planning</span>{% endif %}</div>
<div>spend cap</div><div>${{ study.max_spend_usd }}</div><div>repetitions</div><div>{{ study.reps }}</div><div>arms</div><div>{{ study.arms|join(', ') }}; repairs: {{ study.repair_arms|join(', ') }} on the {{ study.repair_base_arm }} output</div>
<div>decoding</div><div>temperature {{ study.temperature }}, reasoning effort {{ study.reasoning_effort }}, output cap {{ study.max_tokens }} tokens</div></div>
<details><summary>study.json</summary><pre>{{ study_json }}</pre></details>
<h2>Checks</h2>
<form method="post" action="/setup/selfcheck" style="display:inline"><button class="btn">Run selfcheck (free, about 1 minute)</button></form>
<form method="post" action="/setup/preflight" style="display:inline"><button class="btn">Run preflight (one real call per model, under $0.01)</button></form>
{% if check %}<h3>{{ check.title }}</h3><pre>{{ check.text }}</pre>{% endif %}
"""

EXPORT = """
<h1>Export</h1>
<p>Writes every table as CSV, the computed results as JSON, the result tables as LaTeX, and a manifest with the configuration and analyser versions, into <code>run/export/</code>.</p>
<form method="post" action="/export"><button class="btn primary">Export now</button></form>
{% if files %}<h2>Files</h2><table><tr><th>file</th><th class="num">size</th></tr>{% for f, s in files %}<tr><td><a href="/export/{{ f }}">{{ f }}</a></td><td class="num">{{ s }}</td></tr>{% endfor %}</table>{% endif %}
"""
