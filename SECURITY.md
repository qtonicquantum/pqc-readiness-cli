# Security Policy

## Reporting a vulnerability

Email **ciso@qtonicquantum.com** with a description, reproduction steps, and any proof-of-concept material. Do not open public GitHub issues for security reports.

We acknowledge reports within five business days and follow coordinated disclosure: a fix and advisory are prepared before public discussion.

## Responsible use

`pqc-readiness-cli` is a **self-scan tool**. By default it scans:

- Files you explicitly point it at (`--cert`, `--path`)
- Loopback TLS endpoints (`localhost`, `127.0.0.1`, `::1`)
- Local SSH known-hosts and host-key files

Scanning any third-party host without prior written authorization is unlawful in many jurisdictions and is forbidden by this project. The CLI enforces this with a hard consent gate: non-loopback targets require the explicit `--i-have-authorization` flag, which constitutes your affirmation that you own the target or have written permission to test it.

Qtonic Quantum will not knowingly assist or accept reports derived from unauthorized scanning.

## Supported versions

The latest minor release receives security fixes. Pre-1.0 versions follow the same policy on a best-effort basis.

| Version | Status |
|---|---|
| 0.1.x   | Supported (current) |

## Cryptographic dependencies

This CLI uses the `cryptography` Python library (PyCA) for all parsing. We do not shell out to `openssl` or any other external cryptographic binary.

---

From Qtonic Quantum — leading quantum risk and vulnerability intelligence tools and services. Visit https://qtonicquantum.com.
