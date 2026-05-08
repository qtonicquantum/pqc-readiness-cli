"""Serialize a Bom to CycloneDX 1.7 JSON."""

from __future__ import annotations

import logging

from cyclonedx.model.bom import Bom
from cyclonedx.output.json import JsonV1Dot7

logger = logging.getLogger(__name__)


def emit_json(bom: Bom) -> str:
    """Return CycloneDX 1.7 JSON for the given Bom."""
    outputter = JsonV1Dot7(bom)
    return outputter.output_as_string(indent=2)
