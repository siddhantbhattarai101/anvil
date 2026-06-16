# ANVIL Benchmark Results

Corpus: local labeled vulnapp (SQLi/XSS/SSRF, vulnerable + safe).
`found` vs ground truth → precision/recall/F1. Lower time is better.

## Per-tool summary

| Tool | Scope (n) | TP | FP | FN | TN | Precision | Recall | F1 | Total time |
|------|-----------|----|----|----|----|-----------|--------|----|-----------|
| anvil | 6 | 5 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 | 54.3s |

## Per-target detail

| Target | Type | Expected | anvil |
|--------|------|----------|----|
| sqli-error-numeric | sqli | vulnerable | FOUND (1.86s) |
| sqli-blind-numeric | sqli | vulnerable | FOUND (7.11s) |
| sqli-string-quote | sqli | vulnerable | FOUND (5.03s) |
| sqli-time-numeric | sqli | vulnerable | FOUND (21.91s) |
| sqli-post-body | sqli | vulnerable | FOUND (1.85s) |
| sqli-safe-param | sqli | safe | miss (16.56s) |
