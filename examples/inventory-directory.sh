#!/usr/bin/env bash
# Generate a small directory of sample certs and inventory the directory.
set -euo pipefail
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

python3 - "$TMP" <<'PYEOF'
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import datetime as dt
out = sys.argv[1]
def mk(key, name):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365)))
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return b.sign(private_key=key, algorithm=None)
    return b.sign(private_key=key, algorithm=hashes.SHA256())
for k, n in [(rsa.generate_private_key(65537,2048),"rsa.example"),
             (ec.generate_private_key(ec.SECP256R1()),"ecdsa.example"),
             (ed25519.Ed25519PrivateKey.generate(),"ed25519.example")]:
    cert = mk(k, n)
    open(f"{out}/{n}.pem","wb").write(cert.public_bytes(serialization.Encoding.PEM))
PYEOF

pqc-readiness inventory --directory "$TMP" --output "$TMP/cbom.json"
echo "---"
echo "CBOM written to $TMP/cbom.json"
head -20 "$TMP/cbom.json"
