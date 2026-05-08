"""Local filesystem scanners for certificate files."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der"}

# Hard cap to prevent DoS from a huge file with .pem extension that isn\'t a cert.
# Real X.509 certs are well under 10 KB; allow up to 1 MB for chains.
MAX_CERT_BYTES = 1_048_576


class CertificateTooLargeError(ValueError):
    """Raised when a candidate cert file exceeds MAX_CERT_BYTES."""


def walk_directory(path: str | Path) -> Iterator[Path]:
    """Yield certificate files (by extension) found under path, recursively."""
    root = Path(path)
    if not root.exists():
        return
    if root.is_file():
        if root.suffix.lower() in CERT_EXTENSIONS:
            yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in CERT_EXTENSIONS:
            yield p


def read_certificate(path: str | Path) -> bytes:
    """Read a certificate file, refusing files larger than MAX_CERT_BYTES."""
    p = Path(path)
    size = p.stat().st_size
    if size > MAX_CERT_BYTES:
        raise CertificateTooLargeError(
            f"{p}: {size} bytes exceeds MAX_CERT_BYTES={MAX_CERT_BYTES}"
        )
    return p.read_bytes()
