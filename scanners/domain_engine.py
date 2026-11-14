# ffp: FFP-AegisScan-DOMAIN-ENGINE io-edge python
"""Shared context-aware regex & heuristic scanning engine for AegisScan Security Domains."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*|<!--)")
TEST_PATH_RE = re.compile(
    r"(?i)(?:^test_|_test\.(?:py|go|rs)$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|(?:^|[/\\])tests?(?:[/\\]|$))"
)
DEDUCTIONS = {"CRITICAL": 18, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def collect_files(target: Path, extra_names: set[str] | None = None) -> list[Path]:
    files: list[Path] = []
    max_files = config.LIMITS["max_files_per_scan"]
    extra = {n.lower() for n in (extra_names or set())}
    if target.is_file():
        return [target]
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in sorted(dirs) if d not in config.SKIP_DIRECTORIES]
        for fn in sorted(filenames):
            if len(files) >= max_files:
                return files
            fp = Path(root) / fn
            if fp.is_symlink():
                continue
            low = fn.lower()
            if fp.suffix.lower() in {".md", ".rst", ".txt"} and low not in extra:
                continue
            if low.endswith("_scanner.py") or low == "domain_engine.py":
                continue
            if low in extra or fp.suffix.lower() in config.SCANNABLE_EXTENSIONS or any(
                low.endswith(ext) for ext in config.SCANNABLE_EXTENSIONS
            ):
                files.append(fp)
    return files


def run_rule_domain(
    *,
    domain_key: str,
    scanner_name: str,
    target: Path,
    rules: list[tuple[str, re.Pattern[str], str, str]],
    positive_patterns: list[re.Pattern[str]] | None = None,
    file_filter: Callable[[Path], bool] | None = None,
    extra_names: set[str] | None = None,
    include_low: bool = False,
) -> dict:
    """Execute a domain rule set and compute a 0..100 domain score."""
    all_files = collect_files(target, extra_names=extra_names)
    if file_filter is not None:
        all_files = [f for f in all_files if file_filter(f)]

    findings: list[dict] = []
    severity_counts = {sev: 0 for sev in config.SEVERITY}
    positive_hits = 0

    for fp in all_files:
        try:
            if fp.stat().st_size > config.LIMITS["max_file_size_bytes"]:
                continue
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_str = str(fp)
        is_test = bool(TEST_PATH_RE.search(str(fp.relative_to(target)) if fp.is_relative_to(target) else fp.name))
        if is_test and not include_low:
            continue

        if positive_patterns:
            if any(p.search(text) for p in positive_patterns):
                positive_hits += 1

        lines = text.splitlines()
        file_findings = 0
        for line_no, line in enumerate(lines, start=1):
            if file_findings >= config.LIMITS["max_findings_per_file"]:
                break
            if COMMENT_RE.match(line) or "re.compile(" in line or "regexp.MustCompile(" in line or "AegisScan-ignore" in line:
                continue
            for pattern_id, regex, base_sev, remediation in rules:
                m = regex.search(line)
                if not m:
                    continue
                sev = base_sev
                if is_test and sev in ("CRITICAL", "HIGH"):
                    sev = "LOW"
                if sev == "LOW" and not include_low:
                    continue
                snippet = line.strip()
                if len(snippet) > 96:
                    snippet = snippet[:93] + "..."
                findings.append(
                    {
                        "domain": domain_key,
                        "type": domain_key,
                        "pattern": pattern_id,
                        "severity": sev,
                        "file": rel_str,
                        "line": line_no,
                        "snippet": snippet,
                        "remediation": remediation,
                    }
                )
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                file_findings += 1
                if len(findings) >= config.LIMITS["max_report_findings"]:
                    break
            if len(findings) >= config.LIMITS["max_report_findings"]:
                break

    penalty = sum(severity_counts.get(s, 0) * w for s, w in DEDUCTIONS.items())
    raw_score = max(0, 100 - penalty)
    if positive_patterns and raw_score < 100 and positive_hits > 0:
        bonus = min(8, positive_hits * 2)
        raw_score = min(100, raw_score + bonus)

    return {
        "scan": scanner_name,
        "domain": domain_key,
        "target": str(target),
        "timestamp": config.get_timestamp(),
        "total_files_scanned": len(all_files),
        "positive_signal_files": positive_hits,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "score": raw_score,
        "verdict": config.get_verdict(raw_score),
        "findings": findings,
    }


def cli_main(scanner_title: str, scan_fn: Callable[[Path, bool, bool], dict]) -> None:
    ap = argparse.ArgumentParser(description=scanner_title)
    ap.add_argument("--target", required=True, help="Target directory or file to scan")
    ap.add_argument("--output", choices=["json", "text"], default="text")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--include-low", action="store_true")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Target does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    t0 = time.time()
    res = scan_fn(target, args.include_low, args.verbose)
    res["duration_seconds"] = round(time.time() - t0, 3)

    if args.output == "json":
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(f"=== {scanner_title} ===")
        print(f"Target: {res['target']} | Files: {res['total_files_scanned']} | Score: {res['score']}/100")
        for f in res["findings"][:15]:
            print(f"  [{f['severity']}] {f['pattern']} @ {f['file']}:{f['line']}")
