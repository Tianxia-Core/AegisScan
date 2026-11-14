#!/usr/bin/env python3
# ffp: FFP-AegisScan-SECRETS glue python
"""AegisScan Secrets Scanner -- Deep scanner for secrets and credentials.

Goes deeper than quick_scan by performing entropy analysis, base64 detection,
context-aware false positive reduction, and targeted scanning of sensitive
file types (.env, config files, shell scripts, Docker, CI/CD).

Usage:
    python secrets_scanner.py --target /path/to/project
    python secrets_scanner.py --target /path/to/project --output json --verbose
    python secrets_scanner.py --target /path/to/project --include-low
"""

import argparse
import base64
import json
import math
import os
import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Import from the AegisScan config hub (parent directory)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
logger = config.setup_logging("AegisScan-secrets-scanner")

# ---------------------------------------------------------------------------
# Additional patterns beyond config.SECRET_PATTERNS
# ---------------------------------------------------------------------------
# Each entry: (pattern_name, compiled_regex, severity)

_EXTRA_PATTERN_DEFS = [
    # URLs with embedded credentials  (http://user:pass@host)
    (
        "url_embedded_credentials",
        r"""https?://[^:\s]+:[^@\s]+@[^\s/]+""",
        "HIGH",
    ),
    # Stripe keys
    (
        "stripe_key",
        r"""(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}""",
        "CRITICAL",
    ),
    # Google API key
    (
        "google_api_key",
        r"""AIza[0-9A-Za-z\-_]{35}""",
        "HIGH",
    ),
    # Twilio Account SID / Auth Token
    (
        "twilio_key",
        r"""(?:AC[a-f0-9]{32}|SK[a-f0-9]{32})""",
        "HIGH",
    ),
    # Heroku API key
    (
        "heroku_api_key",
        r"""(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['\"]\S{8,}['\"]""",
        "HIGH",
    ),
    # SendGrid API key
    (
        "sendgrid_key",
        r"""SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}""",
        "CRITICAL",
    ),
    # npm token
    (
        "npm_token",
        r"""(?:npm_)[A-Za-z0-9]{36}""",
        "CRITICAL",
    ),
    # Generic connection string (ODBC / ADO style)
    (
        "connection_string",
        r"""(?i)(?:connectionstring|conn_str)\s*[:=]\s*['\"][^'\"]{10,}['\"]""",
        "HIGH",
    ),
    # JWT tokens (three base64 segments separated by dots)
    (
        "jwt_token",
        r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}""",
        "MEDIUM",
    ),
    # Azure storage key
    (
        "azure_storage_key",
        r"""(?i)(?:accountkey|storage[_-]?key)\s*[:=]\s*['\"]\S{44,}['\"]""",
        "CRITICAL",
    ),

    # Slack tokens
    (
        "slack_token",
        r"""xox[bpors]-[0-9]{10,}-[A-Za-z0-9-]+""",
        "CRITICAL",
    ),

    # GitHub tokens
    (
        "github_token",
        r"""(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}""",
        "CRITICAL",
    ),

    # AWS keys
    (
        "aws_access_key",
        r"""(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}""",
        "CRITICAL",
    ),
    (
        "aws_secret_key",
        r"""(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]\S{40}['\"]""",
        "CRITICAL",
    ),
]

_EXTRA_PATTERNS = [
    (name, re.compile(pattern), severity)
    for name, pattern, severity in _EXTRA_PATTERN_DEFS
]

# ---------------------------------------------------------------------------
# Compile all patterns from config + extras
# ---------------------------------------------------------------------------
ALL_SECRET_PATTERNS = config.SECRET_PATTERNS + _EXTRA_PATTERNS

# ---------------------------------------------------------------------------
# Private key file extensions
# ---------------------------------------------------------------------------
PRIVATE_KEY_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".cer", ".crt", ".der",
    ".p7b", ".p7c", ".jks", ".ks",
}

# ---------------------------------------------------------------------------
# File patterns
# ---------------------------------------------------------------------------
# Files that are test fixtures -- lower severity or skip
_TEST_FILE_PATTERNS = re.compile(
    r"""(?i)(?:^test_|_test\.py$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|__tests__|fixtures?[/\\])"""
)

# Placeholder / example value patterns -- these are NOT real secrets
_PLACEHOLDER_PATTERN = re.compile(
    r"""(?i)(?:example|placeholder|changeme|xxx+|your[_-]?key[_-]?here|"""
    r"""insert[_-]?here|replace[_-]?me|todo|fixme|dummy|fake|sample|test123|"""
    r"""sk_test_|pk_test_|loading\.\.\.|"""
    r"""\$\{[A-Z_][A-Z0-9_]*[:-]|\$\{[A-Z_][A-Z0-9_]*\})"""
)

# File categories
ENV_FILE_PATTERNS = {".env", ".env.local", ".env.production", ".env.staging", ".env.development"}
CONFIG_EXTENSIONS = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".json", ".properties"}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".fish", ".ps1"}
DOCKER_PREFIXES = ("Dockerfile", "docker-compose", "dockerfile")
CICD_PATTERNS = (".github/", ".gitlab/", ".circleci/", "azure-pipelines/", "jenkins/", ".travis.yml")

# ---------------------------------------------------------------------------
# Context helpers
# ---------------------------------------------------------------------------
_MARKDOWN_CODE_FENCE = re.compile(r"^```")

def _is_comment_line(line: str) -> bool:
    """Return True if the line is a comment (shell, python, js, sql, etc.)."""
    stripped = line.lstrip()
    return (
        stripped.startswith("#")
        or stripped.startswith("//")
        or stripped.startswith("--")
        or stripped.startswith("/*")
        or stripped.startswith("*")
    )

def _is_test_file(filepath: Path) -> bool:
    """Return True if the file appears to be a test file."""
    return bool(_TEST_FILE_PATTERNS.search(filepath.name)) or bool(
        _TEST_FILE_PATTERNS.search(str(filepath))
    )

def _is_placeholder_value(line: str) -> bool:
    """Return True if the matched line contains placeholder/example values."""
    return bool(_PLACEHOLDER_PATTERN.search(line))

def _is_env_example(filepath: Path) -> bool:
    """Return True if the file is a .env.example or similar template."""
    name = filepath.name.lower()
    return name in (".env.example", ".env.sample", ".env.template", ".env.defaults")

def _classify_file(filepath: Path) -> str:
    """Classify a file into a category for reporting.

    Returns one of: 'env', 'config', 'shell', 'docker', 'cicd',
                     'private_key', 'source', 'other'.
    """
    name = filepath.name.lower()
    suffix = filepath.suffix.lower()

    # .env variants
    if name.startswith(".env") or name in {".env", ".env.local", ".env.production", ".env.staging", ".env.development"}:
        return "env"

    # Private key files
    if suffix in PRIVATE_KEY_EXTENSIONS:
        return "private_key"

    # Config files
    if suffix in CONFIG_EXTENSIONS:
        return "config"

    # Shell scripts
    if suffix in SHELL_EXTENSIONS:
        return "shell"

    # Docker files
    if any(name.startswith(prefix) for prefix in DOCKER_PREFIXES):
        return "docker"

    # CI/CD files
    filepath_str = str(filepath).replace("\\", "/")
    for cicd_pattern in CICD_PATTERNS:
        if cicd_pattern in filepath_str:
            return "cicd"

    # Source code
    if suffix in {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go", ".rs", ".cpp", ".c", ".h"}:
        return "source"

    return "other"

def _redact(s: str) -> str:
    """Redact sensitive portions of a snippet for safe logging."""
    for pattern_name, regex, _ in config.SECRET_PATTERNS:
        s = regex.sub("[REDACTED]", s)
    for pattern_name, regex, _ in _EXTRA_PATTERNS:
        s = regex.sub("[REDACTED]", s)
    return s

def _context_snippet(line: str, match_start: int, match_end: int, context: int = 40) -> str:
    """Extract a context snippet around a match."""
    start = max(0, match_start - context)
    end = min(len(line), match_end + context)
    raw = line[start:end].strip()
    return _redact(raw)

def scan_file(filepath: Path, verbose: bool = False) -> list[dict]:
    """Perform deep secret scanning on a single file.

    Applies pattern matching, entropy analysis, base64 detection,
    URL credential detection, IP detection, and context-aware filtering.

    Returns a list of finding dicts.
    """
    findings: list[dict] = []
    max_findings = config.LIMITS["max_findings_per_file"]
    file_str = str(filepath)
    file_category = _classify_file(filepath)
    is_test = _is_test_file(filepath)
    is_env_ex = _is_env_example(filepath)

    # --- Private key file detection (by extension, not content) ---
    if filepath.suffix.lower() in PRIVATE_KEY_EXTENSIONS:
        sev = "MEDIUM" if is_test else "CRITICAL"
        findings.append({
            "type": "secret",
            "pattern": "private_key_file",
            "severity": sev,
            "file": file_str,
            "line": 0,
            "snippet": f"Private key file detected: {filepath.name}",
            "category": file_category,
        })
        # Still scan content if readable
        # (fall through)

    # --- File size check ---
    try:
        size = filepath.stat().st_size
    except OSError:
        return findings

    if size > config.LIMITS["max_file_size_bytes"]:
        if verbose:
            logger.debug("Skipping oversized file: %s (%d bytes)", filepath, size)
        return findings

    # --- Read content ---
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        if verbose:
            logger.debug("Cannot read %s: %s", filepath, exc)
        return findings

    lines = text.splitlines()
    in_markdown_code_block = False

    for line_num, line in enumerate(lines, start=1):
        if len(findings) >= max_findings:
            break

        stripped = line.strip()
        if not stripped:
            continue

        # Track markdown code fences for context-aware filtering
        if _MARKDOWN_CODE_FENCE.match(stripped):
            in_markdown_code_block = not in_markdown_code_block
            continue

        # Context-aware filters
        if "re.compile(" in stripped or "regexp.MustCompile(" in stripped or "AegisScan-ignore" in stripped:
            continue
        if is_test and not verbose:
            continue
        is_comment = _is_comment_line(stripped)
        is_placeholder = _is_placeholder_value(stripped)

        # --- Pattern matching (config + extra patterns) ---
        for pattern_name, regex, severity in ALL_SECRET_PATTERNS:
            m = regex.search(line)
            if not m:
                continue

            # Apply false positive reduction
            skip = False
            adjusted_severity = severity

            if is_comment and not file_category == "env":
                # Comments in source code are usually not real secrets
                # But comments in .env files might still be sensitive
                skip = True

            if in_markdown_code_block:
                skip = True

            if is_placeholder:
                skip = True

            if is_test:
                # Lower severity for test files
                sev_weight = config.SEVERITY.get(severity, 1)
                if sev_weight >= config.SEVERITY["HIGH"]:
                    adjusted_severity = "MEDIUM"

            if skip:
                continue

            findings.append({
                "type": "secret",
                "pattern": pattern_name,
                "severity": adjusted_severity,
                "file": file_str,
                "line": line_num,
                "snippet": _context_snippet(line, m.start(), m.end()),
                "category": file_category,
            })

        # --- Entropy analysis ---
        if not is_env_ex and not is_test and not is_comment and not in_markdown_code_block:
            entropy = config.shannon_entropy(line)
            if entropy > 4.5 and len(line.strip()) > 20:
                # Check if it looks like base64 or hex
                if re.match(r'^[A-Za-z0-9+/=]{20,}$', line.strip()) or re.match(r'^[0-9a-fA-F]{32,}$', line.strip()):
                    if not _is_placeholder_value(line):
                        findings.append({
                            "type": "secret",
                            "pattern": "high_entropy_string",
                            "severity": "HIGH" if entropy > 5.0 else "MEDIUM",
                            "file": file_str,
                            "line": line_num,
                            "snippet": _context_snippet(line, 0, len(line)),
                            "category": file_category,
                        })

    return findings

# ---------------------------------------------------------------------------
# High-level scan function
# ---------------------------------------------------------------------------

def scan(target: Path, include_low: bool = False, verbose: bool = False) -> dict:
    """Scan a directory or file for secrets.

    Returns a summary dict with findings and statistics.
    """
    all_findings: list[dict] = []
    files_scanned = 0

    if target.is_file():
        files = [target]
    else:
        files = []
        for ext in config.SCANNABLE_EXTENSIONS:
            files.extend(target.rglob(f"*{ext}"))
        # Filter out skip directories
        files = [f for f in files if not any(skip in f.parts for skip in config.SKIP_DIRECTORIES)]

    for f in files:
        if len(all_findings) >= config.LIMITS["max_report_findings"]:
            break
        findings = scan_file(f, verbose)
        all_findings.extend(findings)
        files_scanned += 1

    # Severity counts
    severity_counts = {sev: 0 for sev in config.SEVERITY}
    for f in all_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    return {
        "scan": "secrets_scanner",
        "target": str(target),
        "timestamp": config.get_timestamp(),
        "duration_seconds": 0,  # filled by caller
        "total_files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "pattern_counts": {},  # filled by caller if needed
        "category_counts": {},  # filled by caller if needed
        "score": 0,
        "verdict": config.get_verdict(0),
        "findings": all_findings,
    }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="AegisScan Secrets Scanner")
    parser.add_argument("--target", required=True, help="Path to scan")
    parser.add_argument("--output", choices=["json", "text"], default="text")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--include-low", action="store_true")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        logger.error("Target does not exist: %s", target)
        sys.exit(1)

    start = time.time()
    result = scan(target, include_low=args.include_low, verbose=args.verbose)
    result["duration_seconds"] = round(time.time() - start, 3)

    # Calculate score
    severity_counts = result["severity_counts"]
    total = sum(severity_counts.values())
    if total == 0:
        score = 100
    else:
        score = max(0, 100 - (severity_counts.get("CRITICAL", 0) * 20 + severity_counts.get("HIGH", 0) * 10 + severity_counts.get("MEDIUM", 0) * 5 + severity_counts.get("LOW", 0) * 2))
    result["score"] = score
    result["verdict"] = config.get_verdict(score)

    # Get findings for output
    all_findings = result.get("findings", [])

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        # Text output
        print(f"\n{'='*70}")
        print(f"  AegisScan SECRETS SCANNER REPORT")
        print(f"{'='*70}")
        print(f"  Target:       {result['target']}")
        print(f"  Timestamp:    {result['timestamp']}")
        print(f"  Duration:     {result['duration_seconds']}s")
        print(f"  Files scanned: {result['total_files_scanned']}")
        print(f"  Total findings: {result['total_findings']}")
        print()
        print("  FINDINGS BY SEVERITY")
        print("  " + "-" * 68)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count:
                print(f"     {sev:<10} {count}  {'#' * (count // 10 + 1)}")
        print()
        print("  TOP FINDINGS (most critical first)")
        print("  " + "-" * 68)
        # Sort by severity weight
        sorted_findings = sorted(
            all_findings,
            key=lambda f: config.SEVERITY.get(f["severity"], 0),
            reverse=True
        )
        for f in sorted_findings[:10]:
            print(f"     {f['severity']:<10} {f['type']} | {f['pattern']}")
            print(f"              {f['file']}:{f['line']} | {f['snippet'][:80]}")
        print()
        print(f"  QUICK SCORE:  {result['score']} / 100")
        print(f"  VERDICT:      {result['verdict']['emoji']} {result['verdict']['label']}")
        print(f"                {result['verdict']['description']}")

# ---------------------------------------------------------------------------
# run_scan - compatibility wrapper for full_audit.py
# ---------------------------------------------------------------------------
def run_scan(target_path: str, output_format: str = "json", verbose: bool = False) -> dict:
    """Run secrets scan on a target path.

    Compatibility wrapper for full_audit.py integration.

    Args:
        target_path: Path to scan.
        output_format: 'json' or 'text'.
        verbose: Enable verbose output.

    Returns:
        Scan result dict.
    """
    target = Path(target_path).resolve()
    if not target.exists():
        return {
            "scan": "secrets_scanner",
            "target": str(target),
            "timestamp": config.get_timestamp(),
            "total_files_scanned": 0,
            "total_findings": 0,
            "severity_counts": {sev: 0 for sev in config.SEVERITY},
            "findings": [],
            "score": 100,
            "verdict": config.get_verdict(100),
        }

    start = time.time()
    result = scan(target, include_low=verbose, verbose=verbose)
    result["duration_seconds"] = round(time.time() - start, 3)
    severity_counts = result["severity_counts"]
    total = sum(severity_counts.values())
    if total == 0:
        score = 100
    else:
        score = max(
            0,
            100
            - (
                severity_counts.get("CRITICAL", 0) * 20
                + severity_counts.get("HIGH", 0) * 10
                + severity_counts.get("MEDIUM", 0) * 5
                + severity_counts.get("LOW", 0) * 2
            ),
        )
    result["score"] = score
    result["verdict"] = config.get_verdict(score)
    return result


if __name__ == "__main__":
    main()