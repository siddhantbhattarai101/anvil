# ANVIL Benchmark Results

Corpus: local labeled vulnapp (SQLi/XSS/SSRF, vulnerable + safe).
`found` vs ground truth → precision/recall/F1. Lower time is better.

## Per-tool summary

| Tool | Scope (n) | TP | FP | FN | TN | Precision | Recall | F1 | Total time |
|------|-----------|----|----|----|----|-----------|--------|----|-----------|
| sqlmap | 10 | 9 | 0 | 1 | 0 | 1.00 | 0.90 | 0.95 | 106.4s |
| anvil | 10 | 9 | 0 | 1 | 0 | 1.00 | 0.90 | 0.95 | 150.9s |

## Per-target detail

| Target | Type | Expected | anvil | sqlmap |
|--------|------|----------|----|----|
| labs-01-string | sqli | vulnerable | FOUND (9.07s) | FOUND (11.16s) |
| labs-02-numeric | sqli | vulnerable | FOUND (26.62s) | FOUND (11.1s) |
| labs-03-paren-quote | sqli | vulnerable | FOUND (9.06s) | FOUND (11.07s) |
| labs-04-paren-dquote | sqli | vulnerable | FOUND (9.09s) | FOUND (11.17s) |
| labs-05-blind | sqli | vulnerable | FOUND (9.07s) | FOUND (12.02s) |
| labs-06-blind-dquote | sqli | vulnerable | FOUND (9.11s) | FOUND (12.07s) |
| labs-08-boolean | sqli | vulnerable | FOUND (26.17s) | FOUND (12.35s) |
| labs-09-time | sqli | vulnerable | FOUND (26.16s) | FOUND (12.85s) |
| labs-10-time-dquote | sqli | vulnerable | miss (17.42s) | miss (1.42s) |
| labs-11-post-login | sqli | vulnerable | FOUND (9.09s) | FOUND (11.15s) |
