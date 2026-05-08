# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public release of `pqc-readiness-cli`.
- Local file inventory (PEM/DER/CRT/CER) using the `cryptography` library.
- CycloneDX 1.7 CBOM emission via `cyclonedx-python-lib`.
- NIST SP 800-57 Rev 5 strength assessment for RSA and EC keys.
- ML-KEM, ML-DSA, SLH-DSA OID detection per the NIST CSOR registry.
- Click-based CLI with `inventory`, `algorithms`, and `version` subcommands.

### Notes
- Coverage threshold tuned for the v0.1.0 surface; will tighten as additional
  scanners (SSH known_hosts, JKS/PKCS#12) are added.
