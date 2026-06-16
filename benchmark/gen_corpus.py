#!/usr/bin/env python3
"""Generate an OWASP-Benchmark-style corpus manifest at scale.

Each case maps to `/bench/{type}?case=N&q=...`. The vulnapp derives behaviour
from `case`: even = genuinely vulnerable (true positive), odd = safe-but-look-
alike using a real sanitizer (false-positive bait). 50/50 split mirrors OWASP
Benchmark, whose scoring metric is the Benchmark Accuracy Score = TPR - FPR.

Usage: python3 gen_corpus.py [N_per_type]   (default 250 -> 500 total cases)
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 250
    targets = []
    for typ, base, val in (("sqli", "/bench/sqli", "1"), ("xss", "/bench/xss", "test"),
                           ("cmdi", "/bench/cmdi", "x")):
        for case in range(n):
            real = case % 2 == 0
            targets.append({
                "id": f"{typ}-{case:05d}",
                "type": typ,
                "path": f"{base}/{case}",
                "param": "q",
                "method": "GET",
                "value": val,
                "expected": "vulnerable" if real else "safe",
                "note": f"{typ} case {case} ({'TP' if real else 'FP-bait'})",
            })
    manifest = {
        "description": f"OWASP-Benchmark-style scale corpus: {len(targets)} cases "
                       f"({n} sqli + {n} xss, 50% vulnerable / 50% safe).",
        "targets": targets,
    }
    out = HERE / "manifest_scale.json"
    out.write_text(json.dumps(manifest, indent=1))
    tp = sum(1 for t in targets if t["expected"] == "vulnerable")
    print(f"wrote {out} — {len(targets)} cases ({tp} vulnerable, {len(targets)-tp} safe)")


if __name__ == "__main__":
    main()
