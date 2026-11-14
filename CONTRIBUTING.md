# Contributing to AegisScan

1. Keep both the **Go static CLI** (`cmd/aegis-scan`) and **Python stdlib suite** (`scanners/`) free of mandatory third-party runtime dependencies.
2. Construct synthetic credentials dynamically in unit tests (e.g., `"ghp_" + "X"*38`) so test fixtures never trigger secret scanners.
3. Run both test suites before opening a PR:
   ```bash
   python3 -m unittest discover -s tests -v
   go test -v ./...
   ```
