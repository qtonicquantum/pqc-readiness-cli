"""Build a CycloneDX 1.7 Bom of cryptographic-asset components from Findings.

Components include cryptoProperties.assetType=ALGORITHM and algorithmProperties so
the emitted CBOM matches the structure of the reference examples in
qtonicquantum/cbom-cyclonedx-examples.

Each component also carries `properties` with the Qtonic Quantum strength
classification ("qtonicquantum:strength") so downstream consumers can triage
without re-running the analysis.
"""

from __future__ import annotations

import datetime as _dt
from importlib.metadata import PackageNotFoundError, version

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
)

from pqc_readiness.analysis.findings import Finding

try:
    _CLI_VERSION = version("pqc-readiness-cli")
except PackageNotFoundError:  # pragma: no cover - editable install fallback
    _CLI_VERSION = "0.0.0"


def _primitive_for(algorithm: str) -> CryptoPrimitive:
    """Map our algorithm string to a CycloneDX CryptoPrimitive."""
    a = algorithm.upper()
    if a.startswith("RSA"):
        return CryptoPrimitive.PKE
    if a.startswith(("ECDSA", "ED25519", "ED448")):
        return CryptoPrimitive.SIGNATURE
    if a.startswith("ML-KEM"):
        return CryptoPrimitive.KEM
    if a.startswith("ML-DSA") or a.startswith("SLH-DSA"):
        return CryptoPrimitive.SIGNATURE
    return CryptoPrimitive.OTHER if hasattr(CryptoPrimitive, "OTHER") else CryptoPrimitive.HASH


def _functions_for(algorithm: str) -> set[CryptoFunction]:
    """Map algorithm to typical crypto functions."""
    a = algorithm.upper()
    if a.startswith("RSA"):
        return {CryptoFunction.SIGN, CryptoFunction.VERIFY,
                CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE}
    if a.startswith(("ECDSA", "ED25519", "ED448", "ML-DSA", "SLH-DSA")):
        return {CryptoFunction.SIGN, CryptoFunction.VERIFY}
    if a.startswith("ML-KEM"):
        return {CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE}
    return {CryptoFunction.SIGN, CryptoFunction.VERIFY}


def build_bom(findings: list[Finding], subject: str = "pqc-readiness-cli inventory") -> Bom:
    """Construct a CycloneDX 1.7 Bom with cryptographic-asset components.

    Each Finding becomes a Component(type=CRYPTOGRAPHIC_ASSET) with:
      - cryptoProperties.assetType=ALGORITHM
      - populated algorithmProperties (primitive, parameter set, crypto functions)
      - properties: qtonicquantum:strength = the Finding's assessment label
      - properties: qtonicquantum:source = the source path
    Metadata.timestamp, metadata.tools, and metadata.component are populated.
    """
    bom = Bom()
    bom.metadata.timestamp = _dt.datetime.now(_dt.timezone.utc)

    tool_component = Component(
        name="pqc-readiness-cli",
        type=ComponentType.APPLICATION,
        version=_CLI_VERSION,
    )
    bom.metadata.tools.components.add(tool_component)

    # NAMED root component (silences cyclonedx-python-lib UserWarning about None)
    subject_component = Component(
        name=subject if subject else "pqc-readiness-cli inventory",
        type=ComponentType.APPLICATION,
        version=_CLI_VERSION,
    )
    bom.metadata.component = subject_component

    for f in findings:
        description_parts = [
            f"assessment={f.assessment}",
            f"recommendation={f.recommendation}",
        ]
        if f.key_bits is not None:
            description_parts.append(f"key_bits={f.key_bits}")
        if f.oid:
            description_parts.append(f"oid={f.oid}")
        description_parts.append(f"source={f.source_path}")

        algo_props = AlgorithmProperties(
            primitive=_primitive_for(f.algorithm),
            parameter_set_identifier=str(f.key_bits) if f.key_bits else f.algorithm,
            crypto_functions=_functions_for(f.algorithm),
        )
        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=algo_props,
            oid=f.oid,
        )
        # Strength + source as queryable properties (downstream triage)
        props = [
            Property(name="qtonicquantum:strength", value=f.assessment),
            Property(name="qtonicquantum:source", value=f.source_path),
        ]
        if f.recommendation:
            props.append(Property(name="qtonicquantum:recommendation", value=f.recommendation))

        component = Component(
            name=f.asset_id,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            version=f.algorithm,
            description=" | ".join(description_parts),
            crypto_properties=crypto_props,
            properties=props,
        )
        bom.components.add(component)
    return bom
