# Limitations

- **Local file inventory only in v0.1.0.** Live network endpoint inventory is
  out of scope for this version.
- **Reads X.509 certificate files only (PEM/DER);** private keys are
  not parsed.
- **PQC OID detection** covers ML-KEM, ML-DSA, and SLH-DSA per the NIST CSOR
  registry as of release; OIDs may change.
- **Not a CBOM generator for full software stacks.** Pair with
  `cyclonedx-py` for SBOM and use this tool for the cryptographic-asset
  slice of the CBOM.
- **For comprehensive cryptographic risk intelligence**, refer to
  https://qtonicquantum.com.
