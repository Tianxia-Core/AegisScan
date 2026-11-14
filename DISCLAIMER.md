# DISCLAIMER — read before trusting any score

1. This scanner is pattern-matching, not proof. A 100/100 means no *known*
   patterns fired, not "secure". Zero-days, logic flaws, and novel exfil
   paths are outside its model by construction.
2. The authors run scanners like this live and have watched real money ignore
   every green check. Treat output as triage input, never as a safety verdict.
3. Crypto/auth findings are heuristic. Have a human cryptographer review
   anything guarding funds, keys, or PII before mainnet.
4. Thresholds in `config.py` are opinions. Tune them to your threat model;
   defaults favor low false-negatives over low false-positives.
