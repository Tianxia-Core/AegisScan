# ffp: FFP-AegisScan-CONFIG io-edge python
"""
AegisScan v2.0.0 — Central Configuration Hub (Standalone MIT Edition).
Covers all 8 security domains with stdlib-only Python portability.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(os.environ.get("SCANNER_007_HOME", str(Path(__file__).resolve().parent)))
SCRIPTS_DIR = BASE_DIR
SCANNERS_DIR = BASE_DIR / "scanners"
DATA_DIR = Path(os.environ.get("SCANNER_007_DATA_DIR", str(BASE_DIR / ".aegis_data")))
REPORTS_DIR = DATA_DIR / "reports"
PLAYBOOKS_DIR = DATA_DIR / "playbooks"
AUDIT_LOG_PATH = DATA_DIR / "audit_log.jsonl"
SCORE_HISTORY_PATH = DATA_DIR / "score_history.json"


def ensure_directories() -> None:
    for directory in (DATA_DIR, REPORTS_DIR, PLAYBOOKS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


SEVERITY = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}
SEVERITY_LABEL = {v: k for k, v in SEVERITY.items()}

# Canonical 8 Security Domains (sum = 1.00)
SCORING_WEIGHTS = {
    "secrets": 0.20,
    "injection": 0.15,
    "dependencies": 0.10,
    "auth_acl": 0.15,
    "cryptography": 0.15,
    "ai_prompt_safety": 0.10,
    "supply_chain_cicd": 0.10,
    "infrastructure_headers": 0.05,
}

SCORING_LABELS = {
    "secrets": "Secrets & Credentials",
    "injection": "Code, SQL & Command Injection",
    "dependencies": "Dependencies & Lockfile Pinning",
    "auth_acl": "Authentication & Access Control",
    "cryptography": "Cryptography & TLS Posture",
    "ai_prompt_safety": "AI & Prompt Safety",
    "supply_chain_cicd": "Supply Chain & CI/CD Pipelines",
    "infrastructure_headers": "Infrastructure & Security Headers",
}

VERDICT_THRESHOLDS = {
    "approved": {
        "min": 90,
        "max": 100,
        "label": "APPROVED",
        "description": "Production-ready security posture across all 8 domains",
        "emoji": "[PASS]",
    },
    "approved_with_caveats": {
        "min": 70,
        "max": 89,
        "label": "APPROVED WITH CAVEATS",
        "description": "Acceptable with documented mitigations for medium/low findings",
        "emoji": "[WARN]",
    },
    "partial_block": {
        "min": 50,
        "max": 69,
        "label": "PARTIAL BLOCK",
        "description": "Remediation required prior to production deployment",
        "emoji": "[BLOCK]",
    },
    "total_block": {
        "min": 0,
        "max": 49,
        "label": "TOTAL BLOCK",
        "description": "Critical security exposure detected; block release",
        "emoji": "[CRITICAL]",
    },
}


def get_verdict(score: float) -> dict:
    score = max(0.0, min(100.0, score))
    best = None
    for verdict in VERDICT_THRESHOLDS.values():
        if score >= verdict["min"]:
            if best is None or verdict["min"] > best["min"]:
                best = verdict
    return best if best is not None else VERDICT_THRESHOLDS["total_block"]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


_SECRET_PATTERN_DEFS = [
    ("generic_api_key", r"""(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['\"]\S{8,}['\"]""", "HIGH"),
    ("aws_access_key", r"""(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}""", "CRITICAL"),
    ("aws_secret_key", r"""(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]\S{40}['\"]""", "CRITICAL"),
    ("password_assignment", r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]""", "HIGH"),
    ("token_assignment", r"""(?i)(?:token|bearer|auth[_-]?token|access[_-]?token|refresh[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]""", "HIGH"),
    ("private_key", r"""-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----""", "CRITICAL"),
    ("github_token", r"""(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}""", "CRITICAL"),
    ("slack_token", r"""xox[bpors]-[0-9]{10,}-[A-Za-z0-9-]+""", "CRITICAL"),
    ("generic_secret", r"""(?i)(?:secret|client[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]""", "MEDIUM"),
    ("db_connection_string", r"""(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp):\/\/[^:]+:[^@]+@""", "HIGH"),
    ("env_inline_secret", r"""(?i)^(?:DATABASE_URL|SECRET_KEY|JWT_SECRET|ENCRYPTION_KEY)\s*=\s*\S+""", "HIGH"),
]

SECRET_PATTERNS = [(name, re.compile(pattern), sev) for name, pattern, sev in _SECRET_PATTERN_DEFS]

_DANGEROUS_PATTERN_DEFS = [
    ("eval_usage", r"""\beval\s*\(""", "CRITICAL"),
    ("exec_usage", r"""\bexec\s*\(""", "CRITICAL"),
    ("subprocess_shell_true", r"""subprocess\.\w+\(.*shell\s*=\s*True""", "CRITICAL"),
    ("os_system", r"""\bos\.system\s*\(""", "HIGH"),
    ("os_popen", r"""\bos\.popen\s*\(""", "HIGH"),
    ("pickle_loads", r"""\bpickle\.loads?\s*\(""", "HIGH"),
    ("yaml_unsafe_load", r"""\byaml\.load\s*\((?!.*Loader\s*=)""", "HIGH"),
    ("marshal_loads", r"""\bmarshal\.loads?\s*\(""", "MEDIUM"),
    ("requests_no_verify", r"""verify\s*=\s*False""", "HIGH"),
    ("ssl_no_verify", r"""(?i)ssl[_.]?verify\s*=\s*(?:False|0|None)""", "HIGH"),
    ("sql_string_format", r"""(?i)(?:execute|cursor\.execute)\s*\(\s*[f'\"]+.*\{""", "CRITICAL"),
    ("child_process_exec", r"""\bchild_process\.\s*exec\s*\(""", "CRITICAL"),
    ("innerHTML_assignment", r"""\.innerHTML\s*=""", "HIGH"),
]

DANGEROUS_PATTERNS = [(name, re.compile(pattern), sev) for name, pattern, sev in _DANGEROUS_PATTERN_DEFS]

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".scala", ".go", ".rs", ".rb", ".php", ".zig", ".c", ".h",
    ".sh", ".bash", ".zsh", ".ps1",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".tf",
    ".json", ".env", ".env.example", ".sql",
    ".html", ".htm", ".xml", ".md", ".txt",
    ".dockerfile", ".docker-compose.yml",
}

SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn", ".aegis_data",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "node_modules", "bower_components",
    "venv", ".venv", "env",
    ".tox", ".nox",
    "dist", "build", "target", "egg-info",
    ".next", ".nuxt", "vendor", "coverage", ".coverage", ".terraform",
}

TIMEOUTS = {
    "file_read_seconds": 10,
    "scan_total_seconds": 300,
    "network_seconds": 30,
}

LIMITS = {
    "max_file_size_bytes": 5 * 1024 * 1024,
    "max_files_per_scan": 10_000,
    "max_findings_per_file": 200,
    "max_report_findings": 1_000,
}

LOG_FORMAT = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


def setup_logging(name: str = "AegisScan", level: int = logging.WARNING) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def get_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_audit_event(action: str, target: str, result: str, details: dict | None = None) -> None:
    if os.environ.get("SCANNER_007_DISABLE_AUDIT_LOG") == "1":
        return
    try:
        ensure_directories()
        event = {
            "timestamp": get_timestamp(),
            "action": action,
            "target": str(target),
            "result": result,
        }
        if details:
            event["details"] = details
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        pass


def calculate_weighted_score(domain_scores: dict[str, float]) -> float:
    total = 0.0
    for domain, weight in SCORING_WEIGHTS.items():
        total += float(domain_scores.get(domain, 0.0)) * weight
    return round(total, 2)
