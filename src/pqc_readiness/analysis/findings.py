"""Pydantic finding model."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A single cryptographic-asset finding."""

    asset_id: str = Field(..., description="Stable identifier for the asset")
    algorithm: str = Field(..., description="Algorithm name, e.g. RSA, ECDSA, ML-DSA-65")
    key_bits: int | None = Field(default=None, description="Key size in bits (None for PQC)")
    oid: str | None = Field(default=None, description="Algorithm OID")
    assessment: str = Field(..., description="Strength category")
    recommendation: str = Field(..., description="Recommended action")
    source_path: str = Field(..., description="Filesystem path the asset was read from")
