#!/usr/bin/env python3
# ffp: FFP-AegisScan-FULL-AUDIT io-edge python
"""AegisScan Full Audit v2.0.0 — 8-Domain Security Orchestrator & Markdown/JSON Report Generator."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import config  # noqa: E402
import score_calculator  # noqa: E402


def render_markdown(rep: dict) -> str:
    lines = [
        f"# AegisScan v{rep['version']} — 8-Domain Security Audit Report",
        "",
        f"- **Target**: `{rep['target']}`",
        f"- **Timestamp**: `{rep['timestamp']}`",
        f"- **Final Score**: **{rep['final_score']:.2f} / 100.00**",
        f"- **Verdict**: `{rep['verdict']['emoji']} {rep['verdict']['label']}` — {rep['verdict']['description']}",
        f"- **Total Findings**: `{rep['total_findings']}`",
        "",
        "## Per-Domain Security Matrix",
        "",
        "| Domain | Weight | Score | Findings |",
        "| :--- | ---: | ---: | ---: |",
    ]
    for dom, weight in config.SCORING_WEIGHTS.items():
        lbl = config.SCORING_LABELS.get(dom, dom)
        sc = rep["domain_scores"].get(dom, 0.0)
        fc = rep["scanner_summaries"].get(dom, {}).get("findings", 0)
        lines.append(f"| {lbl} (`{dom}`) | {int(weight*100)}% | {sc:.1f}/100 | {fc} |")

    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not rep["findings"]:
        lines.append("No security findings detected across all 8 domains.")
    else:
        for f in rep["findings"][:100]:
            lines.append(
                f"- **[{f.get('severity')}]** `{f.get('domain', f.get('type'))}` / `{f.get('pattern')}` "
                f"— `{f.get('file')}:{f.get('line', 0)}`"
            )
            if f.get("remediation"):
                lines.append(f"  - *Remediation*: {f['remediation']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="AegisScan v2.0.0 Full 8-Domain Security Audit")
    ap.add_argument("positional_target", nargs="?", help="Directory to audit")
    ap.add_argument("--target", help="Directory to audit")
    ap.add_argument("--output", choices=["text", "json", "markdown"], default="text")
    ap.add_argument("--report-file", type=Path, default=None, help="Optional file path to save Markdown/JSON report")
    ap.add_argument("--fail-under", type=float, default=0.0)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    target = args.target or args.positional_target or "."
    fmt = "quiet" if args.output in ("json", "markdown") else "text"
    rep = score_calculator.run_score(target, output_format=fmt, verbose=args.verbose)

    if args.output == "json":
        rendered = json.dumps(rep, indent=2, ensure_ascii=False)
        print(rendered)
    elif args.output == "markdown":
        rendered = render_markdown(rep)
        print(rendered)
    else:
        rendered = render_markdown(rep)

    if args.report_file:
        args.report_file.parent.mkdir(parents=True, exist_ok=True)
        args.report_file.write_text(rendered + "\n", encoding="utf-8")

    if args.fail_under > 0 and rep["final_score"] < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
