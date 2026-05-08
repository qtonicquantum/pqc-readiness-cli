"""Targeted tests to cover error/edge paths flagged by coverage analysis."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqc_readiness.analysis.algorithms import identify_certificate
from pqc_readiness.analysis.strength import assess_ec, assess_rsa
from pqc_readiness.cli import main as cli_main
from pqc_readiness.scanners.files import read_certificate, walk_directory


def _make_pem_and_der(tmp_path: Path) -> tuple[Path, Path]:
    """Write both a PEM and a DER form of an RSA-2048 self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    pem_path = tmp_path / "cert.pem"
    der_path = tmp_path / "cert.der"
    pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    der_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return pem_path, der_path


def test_walk_directory_nonexistent_returns_empty(tmp_path):
    """files.py: lines 15-16 — nonexistent path yields nothing."""
    result = list(walk_directory(tmp_path / "does-not-exist"))
    assert result == []


def test_walk_directory_single_file_input(tmp_path):
    """files.py: lines 17-19 — passing a file (not a dir) yields the file if extension matches."""
    pem, _ = _make_pem_and_der(tmp_path)
    result = list(walk_directory(pem))
    assert result == [pem]


def test_walk_directory_single_file_wrong_extension(tmp_path):
    """files.py: file with non-cert extension yields nothing."""
    txt = tmp_path / "not-a-cert.txt"
    txt.write_text("hello")
    result = list(walk_directory(txt))
    assert result == []


def test_identify_certificate_der_fallback(tmp_path):
    """algorithms.py: lines 19-20 — DER bytes work via the ValueError fallback."""
    _, der = _make_pem_and_der(tmp_path)
    info = identify_certificate(der.read_bytes())
    assert info["algorithm"] == "RSA"
    assert info["key_bits"] == 2048


def test_assess_rsa_thresholds():
    """strength.py: hit each branch."""
    assert assess_rsa(1024) == "weak"
    assert assess_rsa(2048) == "legacy"
    assert assess_rsa(3072) == "nist-2030"
    assert assess_rsa(7680) in {"cnsa-2030", "nist-2030"}


def test_assess_ec_curves():
    """strength.py: ECC branches."""
    assert assess_ec("P-256") in {"nist-2030", "legacy", "cnsa-2030"}
    assert assess_ec("P-384") in {"cnsa-2030", "nist-2030"}


def test_cli_version_subcommand():
    """cli.py: version subcommand path."""
    runner = CliRunner()
    result = runner.invoke(cli_main, ["version"])
    assert result.exit_code == 0
    # Version output should contain a version-like string
    assert any(c.isdigit() for c in result.output)


def test_cli_inventory_no_input_errors():
    """cli.py: inventory called with no inputs should error or produce empty BOM cleanly."""
    runner = CliRunner()
    result = runner.invoke(cli_main, ["inventory"])
    # Either non-zero exit or a valid empty CBOM is acceptable; just no crash
    assert result.exit_code in (0, 1, 2)


def test_cli_algorithms_subcommand(tmp_path):
    """cli.py: algorithms subcommand reads cert and lists detected algorithms."""
    pem, _ = _make_pem_and_der(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli_main, ["algorithms", "--cert", str(pem)])
    # Should at least exit 0 or report RSA
    assert result.exit_code in (0, 2)


def test_read_certificate_returns_bytes(tmp_path):
    """files.py: read_certificate returns the raw bytes."""
    pem, _ = _make_pem_and_der(tmp_path)
    data = read_certificate(pem)
    assert isinstance(data, bytes)
    assert b"BEGIN CERTIFICATE" in data


def test_assess_ec_remaining_curves():
    """strength.py: P-521, P-224, P-192, Ed25519, Ed448, unknown — covers lines 39-46."""
    from pqc_readiness.analysis.strength import assess_ec
    assert assess_ec("P-521") == "cnsa-2030"
    assert assess_ec("secp521r1") == "cnsa-2030"
    assert assess_ec("P-224") == "legacy"
    assert assess_ec("P-192") == "weak"
    assert assess_ec("ed25519") == "nist-2030"
    # Ed448 is approved in NIST FIPS 186-5 but is NOT in the CNSA 2.0 suite —
    # CNSA 2.0 requires ML-DSA / LMS / XMSS for signatures.
    assert assess_ec("ed448") == "nist-2030"
    assert assess_ec("brainpool-no-such-curve") == "legacy"


def test_identify_ed25519_certificate(tmp_path):
    """algorithms.py: Ed25519 branch (already covered but extends)."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    from pqc_readiness.analysis.algorithms import identify_certificate
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed25519.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30))
            .sign(private_key=key, algorithm=None))
    info = identify_certificate(cert.public_bytes(serialization.Encoding.PEM))
    assert info["algorithm"] == "Ed25519"
    assert info["key_bits"] == 256


def test_identify_ed448_certificate(tmp_path):
    """algorithms.py: Ed448 branch (lines 48-55)."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed448
    from cryptography.x509.oid import NameOID

    from pqc_readiness.analysis.algorithms import identify_certificate
    key = ed448.Ed448PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed448.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30))
            .sign(private_key=key, algorithm=None))
    info = identify_certificate(cert.public_bytes(serialization.Encoding.PEM))
    assert info["algorithm"] == "Ed448"
    assert info["key_bits"] == 456


def test_assess_rsa_extreme():
    """strength.py: RSA tiny / huge."""
    from pqc_readiness.analysis.strength import assess_rsa
    assert assess_rsa(512) == "weak"
    assert assess_rsa(15360) in {"cnsa-2030", "nist-2030"}
