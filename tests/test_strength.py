from pqc_readiness.analysis.strength import assess_ec, assess_rsa


def test_rsa_2048_legacy() -> None:
    assert assess_rsa(2048) == "legacy"


def test_rsa_3072_nist_2030() -> None:
    assert assess_rsa(3072) == "nist-2030"


def test_rsa_1024_weak() -> None:
    assert assess_rsa(1024) == "weak"


def test_rsa_8192_cnsa() -> None:
    assert assess_rsa(8192) == "cnsa-2030"


def test_ec_p256_nist_2030() -> None:
    assert assess_ec("secp256r1") == "nist-2030"
    assert assess_ec("prime256v1") == "nist-2030"


def test_ec_p384_cnsa() -> None:
    assert assess_ec("secp384r1") == "cnsa-2030"


def test_ec_p521_cnsa() -> None:
    assert assess_ec("secp521r1") == "cnsa-2030"


def test_ec_p192_weak() -> None:
    assert assess_ec("secp192r1") == "weak"


def test_ec_ed25519() -> None:
    assert assess_ec("ed25519") == "nist-2030"
