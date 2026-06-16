# ANVIL Benchmark Results

Corpus: local labeled vulnapp (SQLi/XSS/SSRF, vulnerable + safe).
`found` vs ground truth → precision/recall/F1. Lower time is better.

## Per-tool summary

| Tool | Scope (n) | TP | FP | FN | TN | Precision | Recall | F1 | Total time |
|------|-----------|----|----|----|----|-----------|--------|----|-----------|
| dalfox | 12 | 8 | 1 | 1 | 2 | 0.89 | 0.89 | 0.89 | 138.0s |
| anvil | 12 | 9 | 0 | 0 | 3 | 1.00 | 1.00 | 1.00 | 50.9s |

## Per-target detail

| Target | Type | Expected | anvil | dalfox |
|--------|------|----------|----|----|
| xss-body-html | xss | vulnerable | FOUND (1.24s) | FOUND (12.8s) |
| xss-attr-dq | xss | vulnerable | FOUND (1.6s) | FOUND (13.02s) |
| xss-attr-sq | xss | vulnerable | FOUND (2.22s) | FOUND (13.99s) |
| xss-js-string | xss | vulnerable | FOUND (5.73s) | FOUND (7.03s) |
| xss-comment | xss | vulnerable | FOUND (6.53s) | FOUND (12.18s) |
| xss-href-url | xss | vulnerable | FOUND (1.59s) | FOUND (14.79s) |
| xss-filtered-attr | xss | vulnerable | FOUND (5.42s) | FOUND (12.17s) |
| xss-post-body | xss | vulnerable | FOUND (1.5s) | miss (2.77s) |
| xss-dom-innerhtml | xss | vulnerable | FOUND (2.3s) | FOUND (12.8s) |
| xss-safe-escaped | xss | safe | miss (7.45s) | miss (13.95s) |
| xss-safe-attr | xss | safe | miss (7.64s) | miss (10.38s) |
| xss-safe-csp | xss | safe | miss (7.7s) | FOUND (12.17s) |
