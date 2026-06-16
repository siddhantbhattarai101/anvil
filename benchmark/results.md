# ANVIL Benchmark Results

Corpus: local labeled vulnapp (SQLi/XSS/SSRF, vulnerable + safe).
`found` vs ground truth → precision/recall/F1. Lower time is better.

## Per-tool summary

| Tool | Scope (n) | TP | FP | FN | TN | Precision | Recall | F1 | Total time |
|------|-----------|----|----|----|----|-----------|--------|----|-----------|
| dalfox | 4 | 3 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 | 48.0s |
| anvil | 12 | 8 | 0 | 1 | 3 | 1.00 | 0.89 | 0.94 | 125.5s |
| sqlmap | 6 | 4 | 0 | 1 | 1 | 1.00 | 0.80 | 0.89 | 42.5s |

## Per-target detail

| Target | Type | Expected | anvil | dalfox | sqlmap |
|--------|------|----------|----|----|----|
| sqli-error-numeric | sqli | vulnerable | FOUND (1.85s) | — | FOUND (12.23s) |
| sqli-blind-numeric | sqli | vulnerable | FOUND (20.73s) | — | FOUND (3.62s) |
| sqli-string-quote | sqli | vulnerable | miss (12.14s) | — | FOUND (12.27s) |
| sqli-time-numeric | sqli | vulnerable | FOUND (20.71s) | — | miss (1.29s) |
| sqli-post-body | sqli | vulnerable | FOUND (1.86s) | — | FOUND (11.94s) |
| sqli-safe-param | sqli | safe | miss (12.12s) | — | miss (1.19s) |
| xss-body-html | xss | vulnerable | FOUND (1.21s) | FOUND (12.44s) | — |
| xss-attr | xss | vulnerable | FOUND (1.68s) | FOUND (12.34s) | — |
| xss-js-string | xss | vulnerable | FOUND (3.84s) | FOUND (12.18s) | — |
| xss-safe-escaped | xss | safe | miss (5.94s) | miss (10.99s) | — |
| ssrf-fetch | ssrf | vulnerable | FOUND (42.31s) | — | — |
| ssrf-safe-allowlist | ssrf | safe | miss (1.06s) | — | — |
