# Methodology

`pqc-readiness-cli` performs a local-only inventory of cryptographic assets
in the form of X.509 certificates (PEM/DER). For each asset it identifies the
public-key algorithm, classifies it under a strength category, and emits a
CycloneDX 1.7 Cryptography Bill of Materials (CBOM).

## Detection

- **Public-key algorithm** — RSA, ECDSA (secp256r1/secp384r1/secp521r1),
  Ed25519, Ed448 are detected via the `cryptography` library.
- **PQC OIDs** — ML-KEM, ML-DSA, and SLH-DSA OIDs from the NIST CSOR registry
  are recognized when present in a certificate.
- **Signature algorithm OID** — recorded for downstream chain analysis.

## Classification

Strength categories follow NIST SP 800-57 Part 1 Rev. 5 and the CNSA 2.0
transition guidance:

- `pqc-ready` — algorithm is a NIST PQC primitive (FIPS 203, 204, 205).
- `cnsa-2030` — meets CNSA 2.0 classical floor.
- `nist-2030` — accepted through 2030.
- `legacy` — accepted today, deprecated for new deployments.
- `weak` — broken or below the 112-bit floor.

## References

- NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management
- FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
- FIPS 204 — Module-Lattice-Based Digital Signature Standard
- FIPS 205 — Stateless Hash-Based Digital Signature Standard
- CNSA 2.0 — Commercial National Security Algorithm Suite 2.0
- NIST CSOR — https://csrc.nist.gov/Projects/Computer-Security-Objects-Register
