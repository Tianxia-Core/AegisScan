# ffp: FFP-AegisScan-AUTH-ACL io-edge python
"""AegisScan Auth & ACL Scanner — Domain 4: Authentication, Session & Access Control."""
from __future__ import annotations

import re
import time
from pathlib import Path

from domain_engine import cli_main, run_rule_domain

RULES = [
    (
        "jwt_alg_none_or_unverified",
        re.compile(r"""(?i)(?:verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[[^\]]*['\"]none['\"]|jwt\.decode\([^)]*verify\s*=\s*False)"""),
        "CRITICAL",
        "Always enforce cryptographic signature verification and explicit Asymmetric/HMAC algorithm allowlists on JWTs.",
    ),
    (
        "hardcoded_admin_bypass",
        re.compile(r"""(?i)\bif\s+(?:user|username|role|email)\s*==\s*['\"](?:admin|root|superuser|backdoor)['\"]\s*:"""),
        "HIGH",
        "Replace hardcoded identity string comparisons with centralized RBAC/ABAC policy checks.",
    ),
    (
        "cors_wildcard_with_credentials",
        re.compile(r"""(?i)(?:allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\].*allow_credentials\s*=\s*True|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"])"""),
        "MEDIUM",
        "Restrict CORS origins to explicit trusted domains instead of wildcard '*'.",
    ),
    (
        "world_writable_chmod",
        re.compile(r"""(?i)(?:chmod\s*\([^)]*0o?777|\bchmod\s+777\b)"""),
        "HIGH",
        "Apply least-privilege permissions (0o600 for files, 0o700 for private directories).",
    ),
    (
        "csrf_protection_disabled",
        re.compile(r"""(?i)(?:@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*:\s*false)"""),
        "MEDIUM",
        "Keep CSRF tokens enabled on state-mutating cookie-authenticated endpoints.",
    ),
]

POSITIVE = [
    re.compile(r"(?i)(?:@login_required|@require_auth|@permission_required|Depends\(get_current_user\)|requireAuth|RBAC)"),
    re.compile(r"(?i)(?:argon2|bcrypt|scrypt|pbkdf2_hmac)"),
]


def scan(target: Path, include_low: bool = False, verbose: bool = False) -> dict:
    _ = verbose
    return run_rule_domain(
        domain_key="auth_acl",
        scanner_name="auth_acl_scanner",
        target=target,
        rules=RULES,
        positive_patterns=POSITIVE,
        include_low=include_low,
    )


def run_scan(target_path: str, output_format: str = "json", verbose: bool = False) -> dict:
    _ = output_format
    t0 = time.time()
    res = scan(Path(target_path).resolve(), include_low=verbose, verbose=verbose)
    res["duration_seconds"] = round(time.time() - t0, 3)
    return res


if __name__ == "__main__":
    cli_main("AegisScan Auth & ACL Scanner", scan)
