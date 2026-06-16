# ANVIL Benchmark Harness

Measures ANVIL's **detection rate, false-positive rate, and speed** against a
labeled corpus, head-to-head with sqlmap (SQLi) and dalfox (XSS). Turns "is it
powerful?" into numbers you can stand behind.

## Run it

```bash
cargo build                 # build ./target/debug/anvil first
python3 benchmark/run_benchmark.py
# options: --only sqli,xss,ssrf  --tools anvil,sqlmap,dalfox  --port 8980
```

Self-contained (Python stdlib only). Spins up `targets/vulnapp.py` — a labeled
vulnerable app — runs each tool, scores verdicts against `manifest.json` ground
truth, and writes `results.md` + `results.csv`.

## Corpus

`vulnapp.py` is sqlite-backed but emits **MySQL-style errors** and supports
`SLEEP()`, so SQLi tools that target MySQL/PostgreSQL/MSSQL are exercised fairly
(real targets are MySQL and emit those errors). It includes **safe** endpoints
(parameterized SQL, HTML-escaped reflection, allowlisted fetch) so the harness
measures false positives, not just detection.

| Type | Vulnerable | Safe |
|------|-----------|------|
| SQLi | error/UNION, boolean-blind, string-context, time-based, POST-body | parameterized |
| XSS  | HTML body, attribute, JS-string | html.escape |
| SSRF | real server-side fetch | allowlist-only |

## Latest results (debug build)

| Tool | Scope (n) | Precision | Recall | F1 | Total time |
|------|-----------|-----------|--------|----|-----------|
| anvil  | 12 (all) | **1.00** | 0.67 | 0.80 | 96.5s |
| sqlmap | 6 (sqli) | 1.00 | 0.80 | 0.89 | 42.2s |
| dalfox | 4 (xss)  | 1.00 | 1.00 | 1.00 | 44.8s |

Read-out:
- **Zero false positives (precision 1.00)** — every safe endpoint was correctly
  left alone. ANVIL's evidence-driven / headless-execution-proof design holds up.
- **XSS: 3/3, and faster than dalfox** (~1–4s vs ~10–13s) thanks to headless
  verification rather than fuzzing.
- **SSRF: 1/1, no FP.**
- **SQLi recall is the weak spot (2/5).** The misses (boolean-blind, string
  context, time-based) are a *surfacing* gap, not a detection gap: the
  `check_boolean_blind` / `check_time_blind` functions exist and work, but
  `SqliEngine::detect()` only returns `true` for UNION-based. Wiring the other
  techniques into `detect()` is the highest-value next fix.

## Caveats / fairness notes

- The **time-based** SQLi target is somewhat synthetic (sqlite + a registered
  `SLEEP`); sqlmap also missed it because its DBMS-specific time payloads don't
  match a sqlite backend. For a fully realistic SQLi benchmark, point the
  manifest at a MySQL-backed app (e.g. sqli-labs via Docker) — the harness is
  manifest-driven, so only `manifest.json` needs new entries.
- Verdicts are parsed from each tool's output/JSON; markers may need updating if
  a tool changes its output format.
- Debug build; a `--release` build would lower ANVIL's wall-clock further.
