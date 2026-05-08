"""Shared pytest fixtures: generate test certificates with the cryptography library."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID


def _self_signed(key, subject_name: str, sig_hash=None) -> x509.Certificate:
    if sig_hash is None:
        sig_hash = hashes.SHA256()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
    )
    if isinstance(key, (ed25519.Ed25519PrivateKey,)):
        return builder.sign(private_key=key, algorithm=None)
    return builder.sign(private_key=key, algorithm=sig_hash)


def _write_pem(cert: x509.Certificate, path: Path) -> Path:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


@pytest.fixture(scope="session")
def cert_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate a directory of test certificates and return its path."""
    base = tmp_path_factory.mktemp("certs")

    rsa2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write_pem(_self_signed(rsa2048, "rsa-2048.test"), base / "rsa2048.pem")

    rsa3072 = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _write_pem(_self_signed(rsa3072, "rsa-3072.test"), base / "rsa3072.pem")

    p256 = ec.generate_private_key(ec.SECP256R1())
    _write_pem(_self_signed(p256, "ec-p256.test"), base / "ecdsa_p256.pem")

    p384 = ec.generate_private_key(ec.SECP384R1())
    _write_pem(_self_signed(p384, "ec-p384.test", sig_hash=hashes.SHA384()), base / "ecdsa_p384.pem")

    ed = ed25519.Ed25519PrivateKey.generate()
    _write_pem(_self_signed(ed, "ed25519.test"), base / "ed25519.pem")

    return base


@pytest.fixture(scope="session")
def rsa2048_cert(cert_dir: Path) -> Path:
    return cert_dir / "rsa2048.pem"


@pytest.fixture(scope="session")
def rsa3072_cert(cert_dir: Path) -> Path:
    return cert_dir / "rsa3072.pem"


@pytest.fixture(scope="session")
def ecdsa_p256_cert(cert_dir: Path) -> Path:
    return cert_dir / "ecdsa_p256.pem"


@pytest.fixture(scope="session")
def ecdsa_p384_cert(cert_dir: Path) -> Path:
    return cert_dir / "ecdsa_p384.pem"


@pytest.fixture(scope="session")
def ed25519_cert(cert_dir: Path) -> Path:
    return cert_dir / "ed25519.pem"
