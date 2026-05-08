import json

from pqc_readiness.analysis.findings import Finding
from pqc_readiness.cbom.builder import build_bom
from pqc_readiness.cbom.emit import emit_json


def test_build_and_emit() -> None:
    f = Finding(
        asset_id="test-asset",
        algorithm="RSA",
        key_bits=2048,
        oid="1.2.840.113549.1.1.1",
        assessment="legacy",
        recommendation="migrate",
        source_path="/dev/null",
    )
    bom = build_bom([f])
    payload = emit_json(bom)
    data = json.loads(payload)
    assert data["specVersion"] == "1.7"
    assert "components" in data
    assert len(data["components"]) == 1
    assert data["components"][0]["type"] == "cryptographic-asset"
