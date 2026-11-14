# ffp: FFP-AegisScan-AI-PROMPT io-edge python
"""AegisScan AI & Prompt Safety Scanner — Domain 6: LLM Prompt Injection, Unbounded Tool Execution & Output Sinks."""
from __future__ import annotations

import re
import time
from pathlib import Path

from domain_engine import cli_main, run_rule_domain

RULES = [
    (
        "system_prompt_raw_user_interpolation",
        re.compile(r"""(?i)['\"]role['\"]\s*:\s*['\"]system['\"].*f['\"].*\{(?:user_input|prompt|query|req\.|request\.)"""),
        "HIGH",
        "Separate untrusted user input into isolated `user` role messages with delimiter framing; never interpolate raw user input into `system` instructions.",
    ),
    (
        "llm_output_to_code_exec_sink",
        re.compile(r"""(?i)\b(?:eval|exec|os\.system|subprocess\.\w+)\s*\(\s*(?:llm_output|completion|response\.text|choice\.message\.content|model_output)"""),
        "CRITICAL",
        "Never pass raw LLM output directly to code/shell execution sinks; enforce strict JSON schema validation and sandboxed allowlists.",
    ),
    (
        "agent_dangerous_auto_approve_flag",
        re.compile(r"""(?i)(?:allow_dangerous_code\s*=\s*True|dangerouslyAllowBrowser\s*:\s*true|trust_remote_code\s*=\s*True)"""),
        "HIGH",
        "Disable `trust_remote_code=True` and dangerous code execution flags in production inference pipelines.",
    ),
    (
        "unbounded_llm_completion_call",
        re.compile(r"""(?i)chat\.completions\.create\((?![^)]*max_tokens)(?![^)]*max_completion_tokens)[^)]*\)"""),
        "MEDIUM",
        "Specify explicit `max_tokens` / `timeout` budgets on LLM API calls to prevent token-exhaustion DoS.",
    ),
]

POSITIVE = [
    re.compile(r"(?i)(?:max_tokens|max_completion_tokens|response_format|json_schema|pydantic|guardrail|allowlist)"),
]


def scan(target: Path, include_low: bool = False, verbose: bool = False) -> dict:
    _ = verbose
    return run_rule_domain(
        domain_key="ai_prompt_safety",
        scanner_name="ai_prompt_safety_scanner",
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
    cli_main("AegisScan AI & Prompt Safety Scanner", scan)
