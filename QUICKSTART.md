# QUICKSTART (5 minutes)

```bash
pip install -r requirements.txt
# Pre-commit gate (fast, blocking):
python quick_scan.py /path/to/your/repo
# Deep audit (8 domains, 100-point scale):
python full_audit.py /path/to/your/repo
```

Exit code is nonzero when findings exceed the failure threshold in
`config.py`, so both entry points drop straight into CI:

```yaml
# .github/workflows/AegisScan.yml
- run: python quick_scan.py .
```

## What "100/100" means

The score is `100 - penalties` across 8 domains (secrets, auth, injection,
dependencies, crypto, access control, observability, compliance). A perfect
score means *this scanner found nothing above threshold* — not that the code
is invulnerable. New threat classes need new scanner rules; see
`scanners/` for the per-domain pattern sets and `config.py` for weights.
