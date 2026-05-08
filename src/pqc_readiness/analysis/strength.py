"""Classical key-strength assessment.

Thresholds derived from NIST SP 800-57 Part 1 Rev. 5 (Recommendation for Key
Management) and CNSA 2.0 transition guidance. Categories:

    pqc-ready   — algorithm is a NIST-standardized PQC primitive.
    cnsa-2030   — meets CNSA 2.0 classical floor (RSA-3072+ for transitional
                  hybrid use, ECDSA P-384, etc.).
    nist-2030   — accepted through 2030 per SP 800-57 (RSA-3072, ECDSA P-256).
    legacy      — accepted today but deprecated for new deployments
                  (RSA-2048, 1024-bit DSA-equivalent).
    weak        — broken or below the 112-bit security floor.
"""

from __future__ import annotations


def assess_rsa(bits: int) -> str:
    """Return a strength category for an RSA modulus of the given bit length."""
    if bits < 2048:
        return "weak"
    if bits < 3072:
        return "legacy"
    if bits < 7680:
        return "nist-2030"
    return "cnsa-2030"


def assess_ec(curve_name: str) -> str:
    """Return a strength category for an elliptic-curve name."""
    name = curve_name.lower()
    if name in {"secp256r1", "prime256v1", "p-256"}:
        return "nist-2030"
    if name in {"secp384r1", "p-384"}:
        return "cnsa-2030"
    if name in {"secp521r1", "p-521"}:
        return "cnsa-2030"
    if name in {"secp224r1", "p-224"}:
        return "legacy"
    if name in {"secp192r1", "prime192v1", "p-192"}:
        return "weak"
    if name in {"ed25519"}:
        return "nist-2030"
    if name in {"ed448"}:
        # Ed448 is approved in NIST FIPS 186-5 but is NOT in the CNSA 2.0 suite.
        # CNSA 2.0 requires ML-DSA / LMS / XMSS for signatures; Ed448 is not listed.
        return "nist-2030"
    return "legacy"
