#!/usr/bin/env python3
"""Benchmark harness: run ANVIL head-to-head with sqlmap/dalfox against the
labeled vulnapp corpus and score detection rate, false positives, and speed.

Verdict is compared to manifest.json ground truth → per-tool TP/FP/FN/TN,
precision, recall, F1, and wall-clock. Outputs results.md and results.csv.

Usage:
  python3 run_benchmark.py [--port 8980] [--tools anvil,sqlmap,dalfox]
                           [--anvil-bin PATH] [--only sqli,xss,ssrf]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEFAULT_ANVIL = REPO / "target" / "debug" / "anvil"

TIMEOUTS = {"anvil": 120, "sqlmap": 180, "dalfox": 90}


# ----------------------------- process helper -----------------------------
def run(cmd, timeout):
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        out = (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + "\n[timeout]"
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
    except FileNotFoundError as e:
        out = f"[not found] {e}"
    return out, round(time.time() - t0, 2)


def target_url(base, t):
    if t["method"] == "GET":
        return f"{base}{t['path']}?{t['param']}={t['value']}"
    return f"{base}{t['path']}"  # POST: param goes in body


def post_body(t):
    """Body for a POST target: an explicit `body` (full form) or param=value."""
    return t.get("body", f"{t['param']}={t['value']}")


# ----------------------------- ANVIL runner -----------------------------
def anvil_verdict(anvil_bin, base, t, out_json):
    url = target_url(base, t)
    flag = {"sqli": "--sqli", "xss": "--xss", "ssrf": "--ssrf"}[t["type"]]
    cmd = [str(anvil_bin), "-t", url, "-p", t["param"], flag,
           "--format", "json", "-o", out_json]
    if t["method"] == "POST":
        cmd += ["--method", "POST", "--data", post_body(t)]
    out, secs = run(cmd, TIMEOUTS["anvil"])

    found = False
    # JSON findings (reporter-backed: XSS/SSRF, and SQLi sitemap mode)
    kw = {"sqli": ["sql"], "xss": ["xss", "scripting"],
          "ssrf": ["ssrf", "request forgery"]}[t["type"]]
    try:
        data = json.loads(Path(out_json).read_text())
        for f in data.get("findings", []):
            vt = str(f.get("vuln_type", "")).lower()
            if any(k in vt for k in kw):
                found = True
                break
    except Exception:
        pass
    # stdout markers (SQLi enumeration mode prints, doesn't always write JSON)
    markers = {
        "sqli": ["SQL injection confirmed"],
        "xss": ["CONFIRMED - ACTIVE TEST"],
        "ssrf": ["[SSRF DETECTED]"],
    }[t["type"]]
    if any(m in out for m in markers):
        found = True
    return found, secs


# ----------------------------- sqlmap runner -----------------------------
def sqlmap_verdict(base, t):
    url = target_url(base, t)
    cmd = ["sqlmap", "-u", url, "-p", t["param"], "--batch",
           "--level=1", "--risk=1", "--technique=BEUST",
           "--flush-session", "--disable-coloring"]
    if t["method"] == "POST":
        cmd += ["--data", post_body(t)]
    out, secs = run(cmd, TIMEOUTS["sqlmap"])
    pos = ["is vulnerable", "appears to be injectable",
           "injection point(s) with a total", "the back-end DBMS is",
           "might be injectable"]
    found = any(m in out for m in pos)
    return found, secs


# ----------------------------- dalfox runner -----------------------------
def dalfox_verdict(base, t):
    url = target_url(base, t)
    cmd = ["dalfox", "url", url, "--no-color", "--silence"]
    out, secs = run(cmd, TIMEOUTS["dalfox"])
    found = ("[POC]" in out) or ("[V]" in out) or ("[VULN]" in out)
    return found, secs


# ----------------------------- scoring -----------------------------
def score(rows, tool):
    tp = fp = fn = tn = 0
    total_t = 0.0
    n = 0
    for r in rows:
        if tool not in r["tools"]:
            continue
        found, secs = r["tools"][tool]
        total_t += secs
        n += 1
        vuln = r["target"]["expected"] == "vulnerable"
        if vuln and found:
            tp += 1
        elif vuln and not found:
            fn += 1
        elif not vuln and found:
            fp += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    # OWASP Benchmark metrics: TPR (recall), FPR, and the Benchmark Accuracy
    # Score (Youden's J = TPR - FPR), the official tool-scoring metric.
    tpr = rec
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    bas = tpr - fpr
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec,
                f1=f1, tpr=tpr, fpr=fpr, bas=bas, total_t=round(total_t, 1), n=n)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8980)
    ap.add_argument("--tools", default="anvil,sqlmap,dalfox")
    ap.add_argument("--anvil-bin", default=str(DEFAULT_ANVIL))
    ap.add_argument("--only", default="sqli,xss,ssrf")
    ap.add_argument("--manifest", default="manifest.json",
                    help="ground-truth manifest file (in benchmark/)")
    ap.add_argument("--base", default=None,
                    help="external target base URL (e.g. sqli-labs). Skips the "
                         "built-in vulnapp.")
    args = ap.parse_args()

    tools = set(args.tools.split(","))
    types = set(args.only.split(","))
    manifest = json.loads((HERE / args.manifest).read_text())

    # External base (e.g. sqli-labs) → don't launch vulnapp.
    srv = None
    if args.base:
        base = args.base.rstrip("/")
    else:
        base = f"http://127.0.0.1:{args.port}"
        srv = subprocess.Popen(
            [sys.executable, str(HERE / "targets" / "vulnapp.py"), str(args.port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{base}/health", timeout=1).read()
                break
            except Exception:
                time.sleep(0.1)
        else:
            print("vulnapp failed to start", file=sys.stderr)
            return 1

    try:
        rows = []
        for t in manifest["targets"]:
            if t["type"] not in types:
                continue
            entry = {"target": t, "tools": {}}
            out_json = f"/tmp/anvil_bench_{t['id']}.json"
            # ANVIL on every type
            if "anvil" in tools:
                entry["tools"]["anvil"] = anvil_verdict(args.anvil_bin, base, t, out_json)
            # peer tools by type
            if t["type"] == "sqli" and "sqlmap" in tools and shutil.which("sqlmap"):
                entry["tools"]["sqlmap"] = sqlmap_verdict(base, t)
            if t["type"] == "xss" and "dalfox" in tools and shutil.which("dalfox"):
                entry["tools"]["dalfox"] = dalfox_verdict(base, t)
            rows.append(entry)
            mark = lambda x: "FOUND" if x else "miss"
            cells = "  ".join(
                f"{tn}={mark(v[0])}({v[1]}s)" for tn, v in entry["tools"].items()
            )
            print(f"[{t['type']:>4}] {t['id']:<22} exp={t['expected']:<10} {cells}", flush=True)
    finally:
        if srv is not None:
            srv.terminate()
            try:
                srv.wait(timeout=5)
            except Exception:
                srv.kill()

    # ---- reports ----
    summaries = {tool: score(rows, tool) for tool in tools}
    md = ["# ANVIL Benchmark Results", "",
          "Corpus: local labeled vulnapp (SQLi/XSS/SSRF, vulnerable + safe).",
          "`found` vs ground truth → precision/recall/F1. Lower time is better.", "",
          "## Per-tool summary", "",
          "| Tool | Scope (n) | TP | FP | FN | TN | Precision | Recall (TPR) | FPR | F1 | OWASP Score (TPR-FPR) | Total time |",
          "|------|-----------|----|----|----|----|-----------|--------------|-----|----|----------------------|-----------|"]
    for tool, s in summaries.items():
        if s["n"] == 0:
            continue
        md.append(
            f"| {tool} | {s['n']} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} | "
            f"{s['precision']:.2f} | {s['tpr']:.2f} | {s['fpr']:.2f} | {s['f1']:.2f} | "
            f"**{s['bas']:.2f}** | {s['total_t']}s |"
        )
    md += ["", "## Per-target detail", "",
           "| Target | Type | Expected | " +
           " | ".join(sorted(tools)) + " |",
           "|--------|------|----------|" + "|".join(["----"] * len(tools)) + "|"]
    for r in rows:
        t = r["target"]
        cells = []
        for tool in sorted(tools):
            if tool in r["tools"]:
                f, s = r["tools"][tool]
                cells.append(f"{'FOUND' if f else 'miss'} ({s}s)")
            else:
                cells.append("—")
        md.append(f"| {t['id']} | {t['type']} | {t['expected']} | " + " | ".join(cells) + " |")
    (HERE / "results.md").write_text("\n".join(md) + "\n")

    with open(HERE / "results.csv", "w") as fh:
        fh.write("target,type,expected," + ",".join(f"{x}_found,{x}_sec" for x in sorted(tools)) + "\n")
        for r in rows:
            t = r["target"]
            cells = [t["id"], t["type"], t["expected"]]
            for tool in sorted(tools):
                if tool in r["tools"]:
                    f, s = r["tools"][tool]
                    cells += [str(int(f)), str(s)]
                else:
                    cells += ["", ""]
            fh.write(",".join(cells) + "\n")

    print("\n" + "\n".join(md))
    print(f"\nWrote {HERE/'results.md'} and {HERE/'results.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
