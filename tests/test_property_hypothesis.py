"""Property-based tests using Hypothesis. Catches invariant violations the
example-based tests miss.
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


@given(st.integers(min_value=0, max_value=10000))
def test_assess_rsa_is_monotonic_non_decreasing_strength(bits1: int) -> None:
    """If bits1 >= bits2, the strength category of bits1 must NOT be weaker than bits2.

    Strength order (weakest -> strongest): weak < legacy < nist-2030 < cnsa-2030 < pqc-ready.
    """
    bits2 = bits1 + 1024  # always larger
    order = ["weak", "legacy", "nist-2030", "cnsa-2030", "pqc-ready", "unknown"]
    r1 = assess_rsa(bits1)
    r2 = assess_rsa(bits2)
    if r1 == "unknown" or r2 == "unknown":
        return  # unknown not comparable
    assert order.index(r2) >= order.index(r1), (
        f"RSA-{bits2} (={r2}) categorized weaker than RSA-{bits1} (={r1})"
    )


@given(st.text(min_size=1, max_size=50))
def test_assess_ec_never_crashes(curve_name: str) -> None:
    """assess_ec must return a valid category for any string input, never raise."""
    result = assess_ec(curve_name)
    assert result in VALID_CATEGORIES


@given(st.sampled_from(list(PQC_OIDS.keys())))
def test_is_pqc_oid_matches_registry(oid: str) -> None:
    """Every OID in PQC_OIDS must be reported as a PQC OID."""
    assert is_pqc_oid(oid)
    assert pqc_name(oid) is not None
    assert pqc_name(oid) == PQC_OIDS[oid]


@given(st.text(alphabet="0123456789.", min_size=1, max_size=50))
def test_is_pqc_oid_returns_false_for_random_oid_strings(oid: str) -> None:
    """Random OID-shaped strings should return False from is_pqc_oid (with probability 1)."""
    if oid in PQC_OIDS:
        return  # collision; skip
    assert not is_pqc_oid(oid)
    assert pqc_name(oid) is None


@given(st.sampled_from(["P-256", "P-384", "P-521", "ed25519", "ed448", "secp256r1", "prime256v1"]))
def test_assess_ec_known_curves_not_unknown(curve_name: str) -> None:
    """All canonical NIST/Ed curves should classify (never return unknown)."""
    result = assess_ec(curve_name)
    assert result != "unknown"
