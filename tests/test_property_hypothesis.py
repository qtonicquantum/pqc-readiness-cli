"""Property-based tests using Hypothesis. Catches invariant violations the
example-based tests miss.

These tests would catch a "constant function" mutation (the prior version was
tautological — a constant `weak` impl passed every property).
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from pqc_readiness.analysis.pqc_oids import PQC_OIDS, is_pqc_oid, pqc_name
from pqc_readiness.analysis.strength import assess_ec, assess_rsa

VALID_CATEGORIES = {"pqc-ready", "cnsa-2030", "nist-2030", "legacy", "weak", "unknown"}


@given(st.integers(min_value=0, max_value=32768))
def test_assess_rsa_returns_valid_category_for_any_int(bits: int) -> None:
    """assess_rsa must return one of the closed-set categories for any non-negative int."""
    result = assess_rsa(bits)
    assert result in VALID_CATEGORIES


# ============================================================
# Anti-tautology guards (catch a constant-function mutation)
# ============================================================
def test_assess_rsa_distinguishes_known_thresholds() -> None:
    """assess_rsa MUST return distinct categories for canonical NIST SP 800-57 thresholds.
    A constant-function mutation would fail this immediately.
    """
    assert assess_rsa(1024) == "weak"
    assert assess_rsa(2048) == "legacy"
    assert assess_rsa(3072) == "nist-2030"
    # 7680+ is the SP 800-57 192-bit-equivalent boundary; we map to cnsa-2030.
    assert assess_rsa(7680) == "cnsa-2030"
    # A constant function cannot satisfy all four.


def test_assess_rsa_produces_at_least_four_distinct_categories() -> None:
    """Across a representative key-size range, at least 4 distinct categories must appear.
    Catches any function that collapses to fewer outputs.
    """
    samples = [assess_rsa(b) for b in range(512, 8193, 256)]
    distinct = set(samples)
    assert len(distinct) >= 4, f"assess_rsa collapsed to {distinct} — likely a constant or near-constant function"


@given(st.integers(min_value=0, max_value=10000))
def test_assess_rsa_is_monotonic_non_decreasing_strength(bits1: int) -> None:
    """If bits1 < bits2, the strength category of bits2 must NOT be weaker than bits1.

    Strength order (weakest -> strongest): weak < legacy < nist-2030 < cnsa-2030 < pqc-ready.
    """
    bits2 = bits1 + 1024
    order = ["weak", "legacy", "nist-2030", "cnsa-2030", "pqc-ready", "unknown"]
    r1 = assess_rsa(bits1)
    r2 = assess_rsa(bits2)
    if r1 == "unknown" or r2 == "unknown":
        return
    assert order.index(r2) >= order.index(r1), (
        f"RSA-{bits2} (={r2}) categorized weaker than RSA-{bits1} (={r1})"
    )


@given(st.text(min_size=1, max_size=50))
def test_assess_ec_never_crashes(curve_name: str) -> None:
    """assess_ec must return a valid category for any string input, never raise."""
    result = assess_ec(curve_name)
    assert result in VALID_CATEGORIES


def test_assess_ec_distinguishes_known_curves() -> None:
    """assess_ec MUST return distinct categories for canonical curves.
    Catches a constant-function mutation.
    """
    p256 = assess_ec("P-256")
    p384 = assess_ec("P-384")
    p192 = assess_ec("P-192")
    ed25519 = assess_ec("ed25519")
    ed448 = assess_ec("ed448")
    assert p192 == "weak"
    assert p256 == "nist-2030"
    assert p384 == "cnsa-2030"
    # Ed448 is approved by NIST FIPS 186-5 but NOT in CNSA 2.0 — must NOT be cnsa-2030.
    assert ed448 == "nist-2030"
    # At least 3 distinct outputs across the canonical curve set
    assert len({p192, p256, p384, ed25519, ed448}) >= 3


@given(st.sampled_from(list(PQC_OIDS.keys())))
def test_is_pqc_oid_matches_registry(oid: str) -> None:
    """Every OID in PQC_OIDS must be reported as a PQC OID."""
    assert is_pqc_oid(oid)
    assert pqc_name(oid) is not None
    assert pqc_name(oid) == PQC_OIDS[oid]


@given(st.text(alphabet="0123456789.", min_size=1, max_size=50))
def test_is_pqc_oid_returns_false_for_random_oid_strings(oid: str) -> None:
    """Random OID-shaped strings should return False from is_pqc_oid."""
    if oid in PQC_OIDS:
        return
    assert not is_pqc_oid(oid)
    assert pqc_name(oid) is None


def test_is_pqc_oid_distinguishes_classical_oids() -> None:
    """Classical-crypto OIDs must NOT be flagged as PQC.
    Catches a constant-True mutation of is_pqc_oid.
    """
    classical = [
        "1.2.840.113549.1.1.1",      # RSA
        "1.2.840.10045.2.1",          # ECDSA
        "1.3.101.112",                # Ed25519
        "1.3.101.113",                # Ed448
        "2.16.840.1.101.3.4.2.1",     # SHA-256
    ]
    for oid in classical:
        assert not is_pqc_oid(oid), f"classical OID {oid} incorrectly classified as PQC"
