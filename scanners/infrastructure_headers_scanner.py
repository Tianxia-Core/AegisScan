# ffp: FFP-AegisScan-INFRA-HEADERS io-edge python
"""AegisScan Infrastructure & Security Headers Scanner — Domain 8: HTTP Headers, Debug Flags, Cookies & IaC."""
from __future__ import annotations

import re
import time
from pathlib import Path

from domain_engine import cli_main, run_rule_domain

RULES = [
    (
        "production_debug_mode_enabled",
        re.compile(r"""(?i)(?:\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b)"""),
        "HIGH",
        "Disable `DEBUG = True` / `debug=True` in production configurations to prevent interactive debugger & stack trace exposure.",
    ),
    (
        "k8s_or_docker_privileged_container",
        re.compile(r"""(?i)^\s*privileged\s*:\s*true\b"""),
        "CRITICAL",
        "Avoid `privileged: true` containers; drop `ALL` Linux capabilities and grant only minimal required capabilities.",
    ),
    (
        "cookie_httponly_or_secure_disabled",
        re.compile(r"""(?i)(?:httponly\s*[:=]\s*(?:False|false)|SESSION_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False)"""),
        "MEDIUM",
        "Set `Secure`, `HttpOnly`, and `SameSite=Lax` (or `Strict`) on session and authentication cookies.",
    ),
    (
        "iac_unrestricted_ssh_rdp_ingress",
        re.compile(r"""(?i)(?:cidr_blocks\s*=\s*\[\s*['\"]0\.0\.0\.0/0['\"]\s*\].*(?:22|3389)|from_port\s*=\s*(?:22|3389).*0\.0\.0\.0/0)"""),
        "HIGH",
        "Restrict administrative SSH (22) and RDP (3389) ingress to WireGuard/VPN or bastion CIDRs instead of 0.0.0.0/0.",
    ),
]

POSITIVE = [
    re.compile(r"(?i)(?:Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options|NoNewPrivileges)"),
]


def scan(target: Path, include_low: bool = False, verbose: bool = False) -> dict:
    _ = verbose
    return run_rule_domain(
        domain_key="infrastructure_headers",
        scanner_name="infrastructure_headers_scanner",
        target=target,
        rules=RULES,
        positive_patterns=POSITIVE,
        extra_names={"dockerfile", "nginx.conf", "caddyfile"},
        include_low=include_low,
    )


def run_scan(target_path: str, output_format: str = "json", verbose: bool = False) -> dict:
    _ = output_format
    t0 = time.time()
    res = scan(Path(target_path).resolve(), include_low=verbose, verbose=verbose)
    res["duration_seconds"] = round(time.time() - t0, 3)
    return res


if __name__ == "__main__":
    cli_main("AegisScan Infrastructure & Headers Scanner", scan)
