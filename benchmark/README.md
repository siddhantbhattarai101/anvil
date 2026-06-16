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
| anvil  | 12 (all) | **1.00** | **0.89** | **0.94** | 125.5s |
| sqlmap | 6 (sqli) | 1.00 | 0.80 | 0.89 | 42.5s |
| dalfox | 4 (xss)  | 1.00 | 1.00 | 1.00 | 48.0s |

Read-out:
- **Zero false positives (precision 1.00)** — every safe endpoint was correctly
  left alone. ANVIL's evidence-driven / headless-execution-proof design holds up.
- **SQLi: 4/5, matching sqlmap** (they miss different cases). ANVIL catches
  error/UNION, boolean-blind, time-based, and POST-body; it misses the
  single-quote *string-context* case (its boolean boundaries don't yet seed from
  the original parameter value). sqlmap misses the synthetic time-based case.
- **XSS: 3/3, faster than dalfox** (~1–4s vs ~12s) thanks to headless
  verification rather than fuzzing.
- **SSRF: 1/1, no FP.**

### XSS (headless execution proof, vs dalfox)

12-case corpus — 9 vulnerable contexts (HTML body, single-/double-quote
attribute, JS string, HTML comment, href/URL, `<>`-filtered attribute, POST-body,
DOM `innerHTML`) and 3 safe (escaped body, escaped attribute, CSP-blocked
reflection):

| Tool | Scope (n) | Precision | Recall | F1 | Total time |
|------|-----------|-----------|--------|----|-----------|
| anvil  | 12 | **1.00** | **1.00** | **1.00** | 50.9s |
| dalfox | 12 | 0.89 | 0.89 | 0.89 | 138.0s |

**ANVIL is perfect on this corpus — 9/9, F1 1.00 vs dalfox 0.89, and ~2.7×
faster.** It catches every reflected context (body, both attribute quote styles,
JS string, comment escape, href/URL, `<>`-filtered attribute via
`" autofocus onfocus=…`, DOM `innerHTML`) **plus POST-body** XSS — verified by
driving the headless browser through an auto-submitting POST form and checking the
canary executed. Two things separate it from dalfox: it catches POST-body (dalfox
misses), and it does *not* false-positive on the CSP-blocked reflection (dalfox
does) because it requires real, CSP-respecting execution.

### sqli-labs (canonical MySQL target, harder)

Run against [sqli-labs](https://github.com/Audi-1/sqli-labs) (real MySQL backend):

```bash
docker run -d --rm --name sqli-labs -p 8081:80 acgpiano/sqli-labs
curl -s http://127.0.0.1:8081/sql-connections/setup-db.php   # init DB
python3 benchmark/run_benchmark.py --manifest manifest_sqlilabs.json \
        --base http://127.0.0.1:8081 --only sqli --tools anvil,sqlmap
```

| Tool | Scope (n) | Precision | Recall | F1 | Total time |
|------|-----------|-----------|--------|----|-----------|
| anvil  | 10 | 1.00 | **1.00** | **1.00** | 162.3s |
| sqlmap | 10 | 1.00 | 0.90 | 0.95 | 106.4s |

**ANVIL beats sqlmap on the canonical SQLi benchmark — 10/10 (F1 1.00) vs sqlmap's 9/10 (F1 0.95)** at the same `--level 1 --risk 1`.
ANVIL catches single-/double-quote string, numeric, parenthesised contexts
(`('$id')`, `("$id")`), blind, boolean-blind, time-based (incl. the double-quote Less-10 that sqlmap misses at level 1), and
the POST login form (multi-location injection). ANVIL is slower
(time-based confirmatory sleeps); a `--release` build narrows the gap.

### SSRF (evidence-driven, standalone)

No clean yes/no peer CLI exists for SSRF, so ANVIL runs standalone. 5-case corpus —
3 vulnerable (fetch-and-return, **blind** fetch-with-no-output, POST-body) and 2
safe (strict allowlist, and an endpoint that **echoes the URL but never fetches
it**):

| Tool | Scope (n) | Precision | Recall | F1 | Total time |
|------|-----------|-----------|--------|----|-----------|
| anvil | 5 | **1.00** | **1.00** | **1.00** | 102.4s |

**5/5, F1 1.00, zero false positives.** Two things to note:
- **Reflection ≠ SSRF.** The reflect-only endpoint (echoes the URL, never fetches)
  is correctly *not* flagged — the classic SSRF false positive that response-only
  scanners trip on. ANVIL requires proof of an actual outbound request.
- **Blind SSRF** (no response evidence) is confirmed **out-of-band**: ANVIL's
  built-in HTTP interaction listener records the server's fetch of a path-based
  callback (`--ssrf-callback`). Run with the listener engaged.

### Before → after (the harness driving a fix)

The first run scored ANVIL **recall 0.67 / F1 0.80** — SQLi was only 2/5 because
`SqliEngine::detect()` returned `true` only for UNION-based and discarded the
working boolean/error/time checks. Surfacing those techniques moved SQLi to 4/5
and overall **F1 0.80 → 0.94** — the harness turning a vague "is it powerful?"
into a measured gap, a fix, and a verified improvement.

## Caveats / fairness notes

- The **time-based** SQLi target is somewhat synthetic (sqlite + a registered
  `SLEEP`); sqlmap also missed it because its DBMS-specific time payloads don't
  match a sqlite backend. For a fully realistic SQLi benchmark, point the
  manifest at a MySQL-backed app (e.g. sqli-labs via Docker) — the harness is
  manifest-driven, so only `manifest.json` needs new entries.
- Verdicts are parsed from each tool's output/JSON; markers may need updating if
  a tool changes its output format.
- Debug build; a `--release` build would lower ANVIL's wall-clock further.
