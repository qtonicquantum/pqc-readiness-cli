# Contributing

Thanks for your interest in `pqc-readiness-cli`.

## Ground rules

- The CLI is a **self-scan** tool. Pull requests that weaken the consent gate, add third-party scanning without authorization checks, or shell out to external crypto binaries (e.g. `openssl`) will be declined.
- All cryptographic parsing must use the `cryptography` Python library.
- CBOM output must remain CycloneDX 1.7. Other versions can be added behind a flag, but 1.7 is the default and must always validate.
- No marketing copy in source code or output. The tool emits findings; the README handles framing.

## Development setup

```bash
git clone https://github.com/qtonicquantum/pqc-readiness-cli.git
cd pqc-readiness-cli
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Running checks

```bash
just lint     # ruff + mypy
just test     # pytest with coverage
just scan     # smoke-test against a fixture cert
```

Or invoke directly:

```bash
ruff check src tests
mypy src
pytest -q
```

Coverage threshold is 85%. The CI matrix runs Python 3.10 / 3.11 / 3.12 / 3.13 on Ubuntu, macOS, and Windows.

## Pull requests

1. Open an issue first for non-trivial work so we can confirm scope.
2. Branch from `main`. Use `feat/`, `fix/`, `docs/`, `refactor/`, `test/`, or `chore/` prefixes.
3. One logical change per PR. Add or update tests. Update `CHANGELOG.md` under `## [Unreleased]`.
4. CI must be green before review.

## Code of Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
