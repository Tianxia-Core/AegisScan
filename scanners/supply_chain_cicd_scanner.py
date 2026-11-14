# ffp: FFP-AegisScan-CICD io-edge python
"""AegisScan Supply Chain & CI/CD Scanner — Domain 7: GitHub Actions, Docker & Build Pipeline Hardening."""
from __future__ import annotations

import re
import time
from pathlib import Path

from domain_engine import cli_main, run_rule_domain

RULES = [
    (
        "gha_pull_request_target_trigger",
        re.compile(r"""^\s*pull_request_target\s*:"""),
        "HIGH",
        "Audit `pull_request_target` workflows carefully; never check out or execute untrusted PR `head.sha` with write permissions or secrets.",
    ),
    (
        "gha_untrusted_expression_injection",
        re.compile(r"""\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|head_commit\.message)"""),
        "CRITICAL",
        "Pass untrusted GitHub event fields via `env:` variables rather than inline `${{ ... }}` shell interpolation.",
    ),
    (
        "gha_unpinned_branch_action",
        re.compile(r"""^\s*-?\s*uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?:main|master|HEAD)\b"""),
        "HIGH",
        "Pin GitHub Actions to an immutable 40-char commit SHA or explicit release tag instead of `@main`/`@master`.",
    ),
    (
        "curl_wget_pipe_to_shell",
        re.compile(r"""(?i)(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b"""),
        "HIGH",
        "Download artifacts to disk, verify SHA-256 checksums / Ed25519 signatures, and only then execute.",
    ),
    (
        "dockerfile_floating_latest_tag",
        re.compile(r"""^\s*FROM\s+[A-Za-z0-9_./-]+:latest\b""", re.IGNORECASE),
        "MEDIUM",
        "Pin container base images by version and `@sha256:...` digest instead of `:latest`.",
    ),
]

POSITIVE = [
    re.compile(r"(?i)(?:permissions:\s*\n\s*contents:\s*read|SHA256SUMS|SBOM|dependabot|CycloneDX)"),
]


def scan(target: Path, include_low: bool = False, verbose: bool = False) -> dict:
    _ = verbose
    return run_rule_domain(
        domain_key="supply_chain_cicd",
        scanner_name="supply_chain_cicd_scanner",
        target=target,
        rules=RULES,
        positive_patterns=POSITIVE,
        extra_names={"dockerfile", "makefile", "justfile"},
        include_low=include_low,
    )


def run_scan(target_path: str, output_format: str = "json", verbose: bool = False) -> dict:
    _ = output_format
    t0 = time.time()
    res = scan(Path(target_path).resolve(), include_low=verbose, verbose=verbose)
    res["duration_seconds"] = round(time.time() - t0, 3)
    return res


if __name__ == "__main__":
    cli_main("AegisScan Supply Chain & CI/CD Scanner", scan)
