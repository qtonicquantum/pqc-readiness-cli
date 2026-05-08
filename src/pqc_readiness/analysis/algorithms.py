"""Certificate algorithm identification using the cryptography library."""

from __future__ import annotations

import logging
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID  # noqa: F401

logger = logging.getLogger(__name__)


def _load_cert(data: bytes) -> x509.Certificate:
    """Load an X.509 certificate from PEM or DER bytes."""
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def identify_certificate(cert_bytes: bytes) -> dict[str, Any]:
    """Identify a certificate's public-key algorithm and metadata.

    Returns a dict with: algorithm, key_bits, oid, signature_algorithm,
    not_valid_before, not_valid_after, subject.
    """
    cert = _load_cert(cert_bytes)
    pub = cert.public_key()

    algorithm: str
    key_bits: int | None
    oid: str

    if isinstance(pub, rsa.RSAPublicKey):
        algorithm = "RSA"
        key_bits = pub.key_size
        oid = "1.2.840.113549.1.1.1"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        algorithm = "ECDSA"
        key_bits = pub.curve.key_size
        oid = "1.2.840.10045.2.1"
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        algorithm = "Ed25519"
        key_bits = 256
        oid = "1.3.101.112"
    elif isinstance(pub, ed448.Ed448PublicKey):
        algorithm = "Ed448"
        key_bits = 456
        oid = "1.3.101.113"
    else:
        algorithm = type(pub).__name__
        key_bits = None
        oid = "unknown"

    sig_oid = cert.signature_algorithm_oid.dotted_string

    try:
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        # cryptography < 42 fallback
        not_before = cert.not_valid_before.isoformat()
        not_after = cert.not_valid_after.isoformat()

    curve_name: str | None = None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve_name = pub.curve.name

    return {
        "algorithm": algorithm,
        "key_bits": key_bits,
        "oid": oid,
        "curve": curve_name,
        "signature_algorithm": sig_oid,
        "not_valid_before": not_before,
        "not_valid_after": not_after,
        "subject": cert.subject.rfc4514_string(),
    }
