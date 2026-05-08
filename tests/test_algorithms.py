from pathlib import Path

from pqc_readiness.analysis.algorithms import identify_certificate


def test_rsa_2048(rsa2048_cert: Path) -> None:
    info = identify_certificate(rsa2048_cert.read_bytes())
    assert info["algorithm"] == "RSA"
    assert info["key_bits"] == 2048


def test_rsa_3072(rsa3072_cert: Path) -> None:
    info = identify_certificate(rsa3072_cert.read_bytes())
    assert info["algorithm"] == "RSA"
    assert info["key_bits"] == 3072


def test_ec_p256(ecdsa_p256_cert: Path) -> None:
    info = identify_certificate(ecdsa_p256_cert.read_bytes())
    assert info["algorithm"] == "ECDSA"
    assert info["curve"] == "secp256r1"


def test_ec_p384(ecdsa_p384_cert: Path) -> None:
    info = identify_certificate(ecdsa_p384_cert.read_bytes())
    assert info["algorithm"] == "ECDSA"
    assert info["curve"] == "secp384r1"


def test_ed25519(ed25519_cert: Path) -> None:
    info = identify_certificate(ed25519_cert.read_bytes())
    assert info["algorithm"] == "Ed25519"
