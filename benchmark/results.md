# ANVIL Benchmark Results

Corpus: local labeled vulnapp (SQLi/XSS/SSRF, vulnerable + safe).
`found` vs ground truth → precision/recall/F1. Lower time is better.

## Per-tool summary

| Tool | Scope (n) | TP | FP | FN | TN | Precision | Recall | F1 | Total time |
|------|-----------|----|----|----|----|-----------|--------|----|-----------|
| anvil | 12 | 6 | 0 | 3 | 3 | 1.00 | 0.67 | 0.80 | 96.5s |
| dalfox | 4 | 3 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 | 44.8s |
| sqlmap | 6 | 4 | 0 | 1 | 1 | 1.00 | 0.80 | 0.89 | 42.2s |

## Per-target detail

| Target | Type | Expected | anvil | dalfox | sqlmap |
|--------|------|----------|----|----|----|
| sqli-error-numeric | sqli | vulnerable | FOUND (1.85s) | — | FOUND (12.16s) |
| sqli-blind-numeric | sqli | vulnerable | miss (9.91s) | — | FOUND (3.42s) |
| sqli-string-quote | sqli | vulnerable | miss (9.92s) | — | FOUND (12.05s) |
| sqli-time-numeric | sqli | vulnerable | miss (9.91s) | — | miss (1.27s) |
| sqli-post-body | sqli | vulnerable | FOUND (1.84s) | — | FOUND (12.26s) |
| sqli-safe-param | sqli | safe | miss (9.93s) | — | miss (1.07s) |
| xss-body-html | xss | vulnerable | FOUND (1.14s) | FOUND (12.78s) | — |
| xss-attr | xss | vulnerable | FOUND (1.57s) | FOUND (11.59s) | — |
| xss-js-string | xss | vulnerable | FOUND (3.8s) | FOUND (9.75s) | — |
| xss-safe-escaped | xss | safe | miss (5.68s) | miss (10.71s) | — |
| ssrf-fetch | ssrf | vulnerable | FOUND (39.87s) | — | — |
| ssrf-safe-allowlist | ssrf | safe | miss (1.04s) | — | — |
