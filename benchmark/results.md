# ANVIL Benchmark Results

Corpus: local labeled vulnapp (SQLi/XSS/SSRF, vulnerable + safe).
`found` vs ground truth → precision/recall/F1. Lower time is better.

## Per-tool summary

| Tool | Scope (n) | TP | FP | FN | TN | Precision | Recall | F1 | Total time |
|------|-----------|----|----|----|----|-----------|--------|----|-----------|
| anvil | 12 | 8 | 0 | 1 | 3 | 1.00 | 0.89 | 0.94 | 57.2s |
| dalfox | 12 | 8 | 1 | 1 | 2 | 0.89 | 0.89 | 0.89 | 131.0s |

## Per-target detail

| Target | Type | Expected | anvil | dalfox |
|--------|------|----------|----|----|
| xss-body-html | xss | vulnerable | FOUND (1.15s) | FOUND (14.38s) |
| xss-attr-dq | xss | vulnerable | FOUND (1.61s) | FOUND (11.41s) |
| xss-attr-sq | xss | vulnerable | FOUND (2.22s) | FOUND (12.85s) |
| xss-js-string | xss | vulnerable | FOUND (5.81s) | FOUND (14.85s) |
| xss-comment | xss | vulnerable | FOUND (6.35s) | FOUND (6.76s) |
| xss-href-url | xss | vulnerable | FOUND (1.6s) | FOUND (5.05s) |
| xss-filtered-attr | xss | vulnerable | FOUND (5.37s) | FOUND (12.19s) |
| xss-post-body | xss | vulnerable | miss (6.77s) | miss (4.42s) |
| xss-dom-innerhtml | xss | vulnerable | FOUND (2.5s) | FOUND (12.77s) |
| xss-safe-escaped | xss | safe | miss (7.81s) | miss (12.8s) |
| xss-safe-attr | xss | safe | miss (7.94s) | miss (10.17s) |
| xss-safe-csp | xss | safe | miss (8.08s) | FOUND (13.39s) |
