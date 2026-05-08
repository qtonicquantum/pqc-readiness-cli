#!/usr/bin/env bash
# Generate a sample RSA-2048 cert and inventory it.
set -euo pipefail
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

python3 - "$TMP" <<'PYEOF'
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime as dt
out = sys.argv[1]
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
cert = (x509.CertificateBuilder()
    .subject_name(subject).issuer_name(issuer)
    .public_key(key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(dt.datetime.now(dt.timezone.utc))
    .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
    .sign(private_key=key, algorithm=hashes.SHA256()))
open(f"{out}/sample.pem","wb").write(cert.public_bytes(serialization.Encoding.PEM))
PYEOF

pqc-readiness inventory --cert "$TMP/sample.pem"
