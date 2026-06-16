# ANVIL Benchmark Results

Corpus: local labeled vulnapp (SQLi/XSS/SSRF, vulnerable + safe).
`found` vs ground truth → precision/recall/F1. Lower time is better.

## Per-tool summary

| Tool | Scope (n) | TP | FP | FN | TN | Precision | Recall (TPR) | FPR | F1 | OWASP Score (TPR-FPR) | Total time |
|------|-----------|----|----|----|----|-----------|--------------|-----|----|----------------------|-----------|
| anvil | 40 | 20 | 0 | 0 | 20 | 1.00 | 1.00 | 0.00 | 1.00 | **1.00** | 82.1s |

## Per-target detail

| Target | Type | Expected | anvil |
|--------|------|----------|----|
| pt-000 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-001 | pathtrav | safe | miss (3.86s) |
| pt-002 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-003 | pathtrav | safe | miss (3.86s) |
| pt-004 | pathtrav | vulnerable | FOUND (0.23s) |
| pt-005 | pathtrav | safe | miss (3.86s) |
| pt-006 | pathtrav | vulnerable | FOUND (0.23s) |
| pt-007 | pathtrav | safe | miss (3.85s) |
| pt-008 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-009 | pathtrav | safe | miss (3.87s) |
| pt-010 | pathtrav | vulnerable | FOUND (0.22s) |
| pt-011 | pathtrav | safe | miss (3.86s) |
| pt-012 | pathtrav | vulnerable | FOUND (0.25s) |
| pt-013 | pathtrav | safe | miss (3.87s) |
| pt-014 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-015 | pathtrav | safe | miss (3.87s) |
| pt-016 | pathtrav | vulnerable | FOUND (0.23s) |
| pt-017 | pathtrav | safe | miss (3.86s) |
| pt-018 | pathtrav | vulnerable | FOUND (0.25s) |
| pt-019 | pathtrav | safe | miss (3.87s) |
| pt-020 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-021 | pathtrav | safe | miss (3.86s) |
| pt-022 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-023 | pathtrav | safe | miss (3.86s) |
| pt-024 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-025 | pathtrav | safe | miss (3.89s) |
| pt-026 | pathtrav | vulnerable | FOUND (0.23s) |
| pt-027 | pathtrav | safe | miss (3.87s) |
| pt-028 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-029 | pathtrav | safe | miss (3.87s) |
| pt-030 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-031 | pathtrav | safe | miss (3.86s) |
| pt-032 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-033 | pathtrav | safe | miss (3.87s) |
| pt-034 | pathtrav | vulnerable | FOUND (0.25s) |
| pt-035 | pathtrav | safe | miss (3.86s) |
| pt-036 | pathtrav | vulnerable | FOUND (0.24s) |
| pt-037 | pathtrav | safe | miss (3.87s) |
| pt-038 | pathtrav | vulnerable | FOUND (0.23s) |
| pt-039 | pathtrav | safe | miss (3.87s) |
