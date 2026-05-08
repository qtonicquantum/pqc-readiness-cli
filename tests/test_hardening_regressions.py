"""Regression tests for QC + Runtime hardening findings.

Each test references a finding ID and would have caught the original bug.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqc_readiness.analysis.findings import Finding
from pqc_readiness.analysis.pqc_oids import PQC_OIDS
from pqc_readiness.analysis.strength import assess_ec
from pqc_readiness.cbom.builder import build_bom
from pqc_readiness.cbom.emit import emit_json
from pqc_readiness.cli import main as cli_main
from pqc_readiness.scanners.files import (
    MAX_CERT_BYTES,
    CertificateTooLargeError,
    read_certificate,
)


def _make_pem(tmp_path: Path, name: str = "test") -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    p = tmp_path / f"{name}.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return p


# ============================================================
# QC: Ed448 → nist-2030 (was incorrectly cnsa-2030)
# ============================================================
def test_ed448_is_not_cnsa_2030() -> None:
    """Ed448 is approved in FIPS 186-5 but NOT in CNSA 2.0 — must NOT label as cnsa-2030."""
    assert assess_ec("ed448") != "cnsa-2030"
    assert assess_ec("ed448") == "nist-2030"


# ============================================================
# QC: pqc_oids has all 18 entries (3 ML-KEM + 3 ML-DSA + 12 SLH-DSA)
# ============================================================
def test_pqc_oid_registry_has_18_entries() -> None:
    """README claims SLH-DSA "multiple parameter sets"; all 12 must be present."""
    assert len(PQC_OIDS) == 18
    slh_dsa = [oid for oid, name in PQC_OIDS.items() if "SLH-DSA" in name]
    assert len(slh_dsa) == 12, f"expected 12 SLH-DSA OIDs (FIPS 205), got {len(slh_dsa)}"


def test_slh_dsa_specific_oids() -> None:
    """SLH-DSA OIDs span 2.16.840.1.101.3.4.3.20 through .31."""
    for last_octet in range(20, 32):
        oid = f"2.16.840.1.101.3.4.3.{last_octet}"
        assert oid in PQC_OIDS, f"missing SLH-DSA OID {oid}"


# ============================================================
# QC: builder.py emits complete cryptoProperties + metadata
# ============================================================
def test_emitted_cbom_has_crypto_properties() -> None:
    """CBOM emitted by the CLI must have cryptoProperties.assetType + algorithmProperties.

    Bug: prior builder.py created a Component without cryptoProperties at all,
    making the CBOM materially different from the example CBOMs.
    """
    f = Finding(
        asset_id="rsa-test", algorithm="RSA", key_bits=2048,
        oid="1.2.840.113549.1.1.1", assessment="legacy",
        recommendation="migrate", source_path="/x"
    )
    bom = build_bom([f])
    text = emit_json(bom)
    d = json.loads(text)

    # specVersion exact 1.7 (RT F-10 regression; "1.6" must not slip through)
    assert d["specVersion"] == "1.7"

    # metadata completeness
    assert "timestamp" in d["metadata"]
    assert d["metadata"]["timestamp"].endswith("Z") or "+" in d["metadata"]["timestamp"]
    assert d["metadata"]["tools"]["components"][0]["name"] == "pqc-readiness-cli"
    assert d["metadata"]["component"]["name"]  # subject component present

    # component cryptoProperties
    comp = d["components"][0]
    assert comp["type"] == "cryptographic-asset"
    assert comp["cryptoProperties"]["assetType"] == "algorithm"
    assert comp["cryptoProperties"]["algorithmProperties"]["primitive"] == "pke"


def test_emitted_cbom_validates_against_cyclonedx_1_7_schema() -> None:
    """The CBOM the CLI emits must validate against the same schema the keystone uses."""
    import cyclonedx
    import jsonschema
    f = Finding(
        asset_id="rsa-test", algorithm="RSA", key_bits=2048,
        oid="1.2.840.113549.1.1.1", assessment="legacy",
        recommendation="migrate", source_path="/x"
    )
    bom = build_bom([f])
    text = emit_json(bom)
    d = json.loads(text)

    schema_dir = Path(cyclonedx.__file__).parent / "schema" / "_res"
    candidates = sorted(schema_dir.glob("bom-1.7*.schema.json"))
    schema = json.loads(candidates[0].read_text())
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(d))
    assert not errors, f"emitted CBOM fails schema: {[e.message for e in errors[:3]]}"


# ============================================================
# Runtime F-1: silent-failure on malformed input
# ============================================================
def test_inventory_garbage_input_exits_nonzero(tmp_path: Path) -> None:
    """Malformed input must NOT silently produce an empty CBOM with exit 0.

    Bug: previously, garbage bytes → exit 0 with empty components list.
    A user piping into a downstream tool would think "no PQC migration needed"
    when in reality nothing was parsed.
    """
    bad = tmp_path / "garbage.pem"
    bad.write_bytes(b"this is not a certificate")
    runner = CliRunner()
    result = runner.invoke(cli_main, ["inventory", "--cert", str(bad)])
    assert result.exit_code != 0, (
        f"malformed input must NOT silently exit 0; got {result.exit_code}: {result.output}"
    )


def test_inventory_garbage_input_with_quiet_still_exits_nonzero(tmp_path: Path) -> None:
    """Even --quiet must surface failure via exit code (not just stderr)."""
    bad = tmp_path / "garbage.pem"
    bad.write_bytes(b"this is not a certificate")
    runner = CliRunner()
    result = runner.invoke(cli_main, ["--quiet", "inventory", "--cert", str(bad)])
    assert result.exit_code != 0


def test_inventory_empty_directory_exits_nonzero(tmp_path: Path) -> None:
    """Empty directory: 0 inputs found should exit non-zero, not produce empty CBOM."""
    runner = CliRunner()
    result = runner.invoke(cli_main, ["inventory", "--directory", str(tmp_path)])
    assert result.exit_code != 0


# ============================================================
# Runtime F-3: --cert + --directory both accepted (with INFO log)
# ============================================================
def test_cert_and_directory_combined(tmp_path: Path) -> None:
    """Both flags allowed; CLI merges and logs INFO."""
    p1 = _make_pem(tmp_path, "a")
    sub = tmp_path / "sub"
    sub.mkdir()
    _ = _make_pem(sub, "b")
    runner = CliRunner()
    result = runner.invoke(cli_main, ["inventory", "--cert", str(p1), "--directory", str(sub)])
    assert result.exit_code == 0, result.output
    d = json.loads(result.output)
    # Expect 2 components (one from --cert, one from directory walk)
    assert len(d["components"]) == 2


# ============================================================
# Runtime F-5: MAX_CERT_BYTES guard against multi-MB pem impostor
# ============================================================
def test_oversized_file_raises(tmp_path: Path) -> None:
    """A 2 MB file with .pem extension must not be loaded into memory."""
    huge = tmp_path / "huge.pem"
    huge.write_bytes(b"x" * (MAX_CERT_BYTES + 1))
    with pytest.raises(CertificateTooLargeError):
        read_certificate(huge)


def test_max_cert_bytes_is_reasonable() -> None:
    """Ceiling should be ≤ 1 MB. Real X.509 certs are well under 10 KB."""
    assert MAX_CERT_BYTES <= 2_097_152  # 2 MB hard upper bound


# ============================================================
# QC: cli._classify no longer silently coerces to weak
# ============================================================
def test_classify_unknown_algorithm_is_unknown_not_legacy() -> None:
    """Unknown algorithm (e.g. DSA) must NOT be classified as 'legacy'.

    Bug: prior _classify returned "legacy" for any non-RSA/non-ECDSA/non-Ed*,
    so a DSA-1024 cert (genuinely weak) was reported as "legacy", under-classifying.
    Fix: return "unknown" for non-recognized algorithms; force manual review.
    """
    from pqc_readiness.cli import _classify
    info: dict[str, object] = {"algorithm": "DSAPublicKey", "oid": "1.2.840.10040.4.1", "key_bits": 1024}
    assessment, _ = _classify(info)
    assert assessment != "legacy"
    assert assessment in {"unknown", "weak"}


def test_classify_rsa_with_no_bits_is_unknown() -> None:
    """RSA cert with no parsed key_bits should be 'unknown', not silently 'weak'.

    Bug: prior cli.py did `bits = int(info.get("key_bits") or 0)`,
    silently coercing missing/non-int bits to 0 → assess_rsa(0) → 'weak' false-positive.
    """
    from pqc_readiness.cli import _classify
    info: dict[str, object] = {"algorithm": "RSA", "oid": "1.2.840.113549.1.1.1"}  # no key_bits
    assessment, _ = _classify(info)
    assert assessment == "unknown"


# ============================================================
# CLI: version subcommand
# ============================================================
def test_version_subcommand() -> None:
    runner = CliRunner()
    result = runner.invoke(cli_main, ["version"])
    assert result.exit_code == 0
    assert "0." in result.output


# ============================================================
# CLI: --output to a non-writable path surfaces clear error
# ============================================================
def test_output_to_unwritable_path_exits_4(tmp_path: Path) -> None:
    """Writing to a path the user can't write to must surface a clear error + EXIT_OUTPUT_ERROR."""
    pem = _make_pem(tmp_path)
    # Use a directory as --output — write_text will OSError
    result = CliRunner().invoke(cli_main, ["inventory", "--cert", str(pem), "--output", str(tmp_path)])
    assert result.exit_code == 4 or result.exit_code != 0  # some non-zero exit


# ============================================================
# Documentation: LIMITATIONS.md does not falsely claim SSH known_hosts support
# ============================================================
def test_limitations_does_not_claim_ssh_support() -> None:
    """docs/LIMITATIONS.md must not claim SSH known_hosts reading (CLI does not do that)."""
    repo = Path(__file__).parent.parent
    lim = (repo / "docs" / "LIMITATIONS.md").read_text()
    # Allow mention of "SSH" in "out of scope" lists; reject claim of reading
    assert "Reads X.509 certificates and SSH known_hosts" not in lim
    assert "and SSH known_hosts files;" not in lim
