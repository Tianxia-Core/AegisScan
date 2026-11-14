# ffp: FFP-AegisScan-CRYPTO io-edge python
"""AegisScan Cryptography Scanner — Domain 5: Ciphers, Hashes, KDFs, CSPRNG & TLS."""
from __future__ import annotations

import re
import time
from pathlib import Path

from domain_engine import cli_main, run_rule_domain

RULES = [
    (
        "broken_hash_md5_sha1",
        re.compile(r"""(?i)(?:\bhashlib\.(?:md5|sha1)\s*\(|\bcrypto\.createHash\(\s*['\"](?:md5|sha1)['\"]|\bmd5\.New\(\)|\bsha1\.New\(\))"""),
        "HIGH",
        "Use SHA-256/SHA-512/BLAKE3 for integrity and Argon2id/scrypt/PBKDF2-HMAC-SHA256 for passwords.",
    ),
    (
        "insecure_ecb_cipher_mode",
        re.compile(r"""(?i)(?:MODE_ECB|AES-128-ECB|AES-256-ECB|NewECBEncrypter)"""),
        "CRITICAL",
        "Replace unauthenticated ECB mode with AES-256-GCM or ChaCha20-Poly1305 AEAD.",
    ),
    (
        "tls_verification_disabled",
        re.compile(r"""(?i)(?:InsecureSkipVerify\s*:\s*true|CERT_NONE|_create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)"""),
        "CRITICAL",
        "Enforce X.509 certificate chain & hostname validation with TLS 1.2/1.3.",
    ),
    (
        "legacy_tls_protocol_version",
        re.compile(r"""(?i)(?:PROTOCOL_TLSv1(?:_1)?\b|VersionTLS10|VersionTLS11|SSLv3)"""),
        "HIGH",
        "Enforce TLS 1.2 minimum (prefer TLS 1.3).",
    ),
    (
        "weak_prng_for_secret_token",
        re.compile(r"""(?i)\brandom\.(?:choice|randint|random|randrange)\s*\(.*(?:token|secret|key|nonce|salt|otp|password)"""),
        "HIGH",
        "Use OS CSPRNG (`secrets` in Python, `crypto/rand` in Go, `OsRng` in Rust) for security tokens.",
    ),
]

POSITIVE = [
    re.compile(r"(?i)(?:AESGCM|cipher\.NewGCM|ChaCha20Poly1305|ed25519|blake3|PBKDF2|HKDF|Scrypt)"),
    re.compile(r"(?i)(?:VersionTLS13|TLSVersion\.TLSv1_3|secrets\.token_bytes|crypto/rand)"),
]


def scan(target: Path, include_low: bool = False, verbose: bool = False) -> dict:
    _ = verbose
    return run_rule_domain(
        domain_key="cryptography",
        scanner_name="cryptography_scanner",
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
    cli_main("AegisScan Cryptography Scanner", scan)
