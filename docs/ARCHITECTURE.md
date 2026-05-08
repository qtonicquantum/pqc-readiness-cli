# Architecture

## Module map

```
src/pqc_readiness/
  __init__.py             # version
  __main__.py             # python -m pqc_readiness
  cli.py                  # Click CLI: inventory / algorithms / version
  analysis/
    algorithms.py         # identify_certificate via cryptography lib
    pqc_oids.py           # NIST CSOR OID registry
    strength.py           # SP 800-57 / CNSA 2.0 categories
    findings.py           # Pydantic Finding model
  scanners/
    files.py              # walk_directory, read_certificate
  cbom/
    builder.py            # Finding[] -> CycloneDX Bom
    emit.py               # Bom -> CycloneDX 1.7 JSON
```

## Data flow

```
PEM/DER files ──▶ scanners.files.walk_directory
              └─▶ analysis.algorithms.identify_certificate
                  └─▶ analysis.strength + analysis.pqc_oids
                      └─▶ analysis.findings.Finding
                          └─▶ cbom.builder.build_bom
                              └─▶ cbom.emit.emit_json (CycloneDX 1.7)
```

## Design principles

- **No subprocess to openssl.** All parsing uses the `cryptography` library.
- **Local-only.** No network calls in v0.1.0.
- **Pydantic models** for typed findings.
- **Logging, not print**, throughout the library code.
