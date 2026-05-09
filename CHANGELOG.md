# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-05-09
### Added
- PyPI Trusted Publisher integration via pypa/gh-action-pypi-publish@release/v1 (OIDC, no API tokens). Each release now produces a PyPI artifact + PEP 740 attestation alongside the existing Sigstore-signed GitHub release.

### Fixed
- Markdownlint regression (MD024/no-duplicate-heading) introduced by 0.1.0 commit 7484a97. Adopted canonical Qtonic Quantum bundle markdownlint config: MD024.siblings_only=true; MD007/MD060 disabled to match repo conventions.

### Notes
- Mutation testing (mutmut) is available via manual workflow_dispatch only. Hosted-runner stability issues with mutmut 3.x prevent reliable scheduled execution; opt-in for now.


## [0.1.0] - 2026-05-08

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
