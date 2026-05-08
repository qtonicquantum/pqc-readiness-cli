"""NIST PQC OID registry.

Source: NIST CSOR — https://csrc.nist.gov/Projects/Computer-Security-Objects-Register
ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).

SLH-DSA has 12 parameter sets at OIDs 2.16.840.1.101.3.4.3.20 through .31:
  .20 sha2-128s   .21 sha2-128f   .22 sha2-192s   .23 sha2-192f
  .24 sha2-256s   .25 sha2-256f   .26 shake-128s  .27 shake-128f
  .28 shake-192s  .29 shake-192f  .30 shake-256s  .31 shake-256f
"""

from __future__ import annotations

# Source: NIST CSOR; verified against FIPS 203/204/205 (Aug 2024).
PQC_OIDS: dict[str, str] = {
    # ML-KEM (FIPS 203)
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    # ML-DSA (FIPS 204)
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    # SLH-DSA (FIPS 205) — all 12 parameter sets
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
}


def is_pqc_oid(oid: str) -> bool:
    """Return True if the given OID matches a registered NIST PQC primitive."""
    return oid in PQC_OIDS


def pqc_name(oid: str) -> str | None:
    """Return the canonical name for a PQC OID, or None if not registered."""
    return PQC_OIDS.get(oid)
