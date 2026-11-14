#!/usr/bin/env python3
# ffp: FFP-AegisScan-SCORE io-edge python
"""AegisScan Score Calculator v2.0.0 — Unified 8-Domain Security Scoring Engine."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scanners"))

from config import (  # noqa: E402
    SCORING_LABELS,
    SCORING_WEIGHTS,
    calculate_weighted_score,
    get_timestamp,
    get_verdict,
    log_audit_event,
    setup_logging,
)
import ai_prompt_safety_scanner  # noqa: E402
import auth_acl_scanner  # noqa: E402
import cryptography_scanner  # noqa: E402
import dependency_scanner  # noqa: E402
import infrastructure_headers_scanner  # noqa: E402
import injection_scanner  # noqa: E402
import secrets_scanner  # noqa: E402
import supply_chain_cicd_scanner  # noqa: E402

logger = setup_logging("AegisScan-score-calculator")

DOMAIN_RUNNERS = [
    ("secrets", secrets_scanner),
    ("injection", injection_scanner),
    ("dependencies", dependency_scanner),
    ("auth_acl", auth_acl_scanner),
    ("cryptography", cryptography_scanner),
    ("ai_prompt_safety", ai_prompt_safety_scanner),
    ("supply_chain_cicd", supply_chain_cicd_scanner),
    ("infrastructure_headers", infrastructure_headers_scanner),
]

DEDUCTIONS = {"CRITICAL": 18, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def _compute_scanner_score(report: dict) -> float:
    if "score" in report and isinstance(report["score"], (int, float)) and report["score"] > 0:
        return float(max(0.0, min(100.0, report["score"])))
    findings = report.get("findings", [])
    if not findings:
        return 100.0
    penalty = sum(DEDUCTIONS.get(f.get("severity", "INFO"), 0) for f in findings)
    return float(max(0, 100 - penalty))


def _deduplicate(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        k = (f.get("file", ""), f.get("line", 0), f.get("pattern", ""))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _redact_findings(findings: list[dict]) -> list[dict]:
    sensitive = {"secret", "token", "password", "raw", "value", "match"}
    out: list[dict] = []
    for f in findings:
        clean = {}
        for k, v in f.items():
            if k.lower() in sensitive:
                clean[k] = "[redacted]"
            elif k == "snippet" and f.get("type") == "secret":
                clean[k] = "[redacted]"
            else:
                clean[k] = v
        out.append(clean)
    return out


def _bar(score: float, width: int = 20) -> str:
    filled = int(round(score / 100.0 * width))
    filled = max(0, min(width, filled))
    return "[" + ("#" * filled) + ("." * (width - filled)) + "]"


def run_score(target_path: str, output_format: str = "text", verbose: bool = False) -> dict:
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")

    t0 = time.time()
    target_str = str(target)
    domain_scores: dict[str, float] = {}
    scanner_summaries: dict[str, dict] = {}
    all_findings: list[dict] = []

    for domain_key, mod in DOMAIN_RUNNERS:
        rep = mod.run_scan(target_path=target_str, output_format="quiet", verbose=verbose)
        findings = rep.get("findings", [])
        for f in findings:
            f.setdefault("domain", domain_key)
        score = _compute_scanner_score(rep)
        domain_scores[domain_key] = round(score, 2)
        scanner_summaries[domain_key] = {
            "scanner": mod.__name__,
            "findings": len(findings),
            "score": round(score, 2),
        }
        all_findings.extend(findings)

    deduped = _deduplicate(all_findings)
    final_score = calculate_weighted_score(domain_scores)
    verdict = get_verdict(final_score)
    elapsed = round(time.time() - t0, 3)

    log_audit_event("score_v2", target_str, verdict["label"], {"final_score": final_score})

    report = {
        "report": "aegis-scan",
        "version": "2.0.0",
        "target": target_str,
        "timestamp": get_timestamp(),
        "duration_seconds": elapsed,
        "total_findings": len(deduped),
        "domain_scores": domain_scores,
        "final_score": final_score,
        "verdict": verdict,
        "scanner_summaries": scanner_summaries,
        "findings": _redact_findings(deduped),
    }

    if output_format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif output_format == "text":
        print("=" * 76)
        print("  AegisScan-SCANNER v2.0.0 — 8-DOMAIN SECURITY AUDIT REPORT")
        print("=" * 76)
        print(f"  Target         : {target_str}")
        print(f"  Duration       : {elapsed:.3f}s")
        print(f"  Total Findings : {len(deduped)}")
        print("-" * 76)
        print(f"  {'Domain':<34} {'Weight':>6}  {'Score':>6}  {'Posture'}")
        print(f"  {'-'*34} {'-'*6}  {'-'*6}  {'-'*22}")
        for dom, weight in SCORING_WEIGHTS.items():
            sc = domain_scores.get(dom, 0.0)
            lbl = SCORING_LABELS.get(dom, dom)
            print(f"  {lbl:<34} {int(weight*100):>5}%  {sc:>6.1f}  {_bar(sc)}")
        print("=" * 76)
        print(f"  FINAL SCORE    : {final_score:.2f} / 100.00")
        print(f"  VERDICT        : {verdict['emoji']} {verdict['label']} — {verdict['description']}")
        print("=" * 76)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="AegisScan v2.0.0 — 8-Domain Security Auditor")
    ap.add_argument("positional_target", nargs="?", help="Path to target directory")
    ap.add_argument("--target", help="Path to target directory")
    ap.add_argument("--output", choices=["text", "json", "quiet"], default="text")
    ap.add_argument("--fail-under", type=float, default=0.0, help="Exit 1 if score < threshold")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    target = args.target or args.positional_target or "."
    rep = run_score(target, output_format=args.output, verbose=args.verbose)
    if args.fail_under > 0 and rep["final_score"] < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
