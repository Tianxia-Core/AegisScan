# ARCHITECTURE

```
quick_scan.py ──→ scanners/*.py ──→ findings[] ──→ score_calculator.py ──→ 0–100
full_audit.py ──→ scanners/*.py ──→ findings[] ──→ score_calculator.py ──→ report
```

- **Scanners** are independent modules, one per domain. Each exposes
  `scan(path) -> [Finding{rule, severity, file, line, fix}]`. Add a domain by
  dropping in a new file — no registry edits (convention over configuration).
- **Findings** carry severity weights consumed blindly by the scorer; scanners
  never touch scoring. This separation is what keeps a new regex from silently
  rebalancing the whole scale.
- **Config** (`config.py`) owns thresholds, weights, and ignore-paths. The
  only file an operator should need to touch.
- **Outputs** are JSON-serializable dicts, so the JSONL audit trail
  (`logs/audit.jsonl` convention) and any CI gate consume the same shape.
