from pqc_readiness.analysis.pqc_oids import PQC_OIDS, is_pqc_oid, pqc_name


def test_all_pqc_oids_present() -> None:
    """NIST CSOR registers 3 ML-KEM + 3 ML-DSA + 12 SLH-DSA = 18 OIDs total."""
    assert len(PQC_OIDS) == 18, f"expected 18 PQC OIDs, got {len(PQC_OIDS)}"


def test_ml_kem() -> None:
    assert pqc_name("2.16.840.1.101.3.4.4.1") == "ML-KEM-512"
    assert pqc_name("2.16.840.1.101.3.4.4.2") == "ML-KEM-768"
    assert pqc_name("2.16.840.1.101.3.4.4.3") == "ML-KEM-1024"


def test_ml_dsa() -> None:
    assert pqc_name("2.16.840.1.101.3.4.3.17") == "ML-DSA-44"
    assert pqc_name("2.16.840.1.101.3.4.3.18") == "ML-DSA-65"
    assert pqc_name("2.16.840.1.101.3.4.3.19") == "ML-DSA-87"


def test_slh_dsa() -> None:
    assert pqc_name("2.16.840.1.101.3.4.3.20") == "SLH-DSA-SHA2-128s"
    assert pqc_name("2.16.840.1.101.3.4.3.21") == "SLH-DSA-SHA2-128f"


def test_is_pqc_oid() -> None:
    assert is_pqc_oid("2.16.840.1.101.3.4.4.1") is True
    assert is_pqc_oid("1.2.840.113549.1.1.1") is False
    assert pqc_name("unknown") is None
