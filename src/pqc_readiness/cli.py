"""Click-based command-line interface for pqc-readiness-cli."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from pqc_readiness import __version__
from pqc_readiness.analysis.algorithms import identify_certificate
from pqc_readiness.analysis.findings import Finding
from pqc_readiness.analysis.pqc_oids import is_pqc_oid, pqc_name
from pqc_readiness.analysis.strength import assess_ec, assess_rsa
from pqc_readiness.cbom.builder import build_bom
from pqc_readiness.cbom.emit import emit_json
from pqc_readiness.scanners.files import read_certificate, walk_directory

logger = logging.getLogger("pqc_readiness")

# Exit codes
EXIT_OK = 0
EXIT_USAGE = 2          # Click default
EXIT_NO_FINDINGS = 3    # N inputs supplied, 0 findings produced
EXIT_OUTPUT_ERROR = 4   # Output write failed (permission, etc.)


def _configure_logging(quiet: bool) -> None:
    level = logging.ERROR if quiet else logging.INFO
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(handler)
    root.setLevel(level)


def _classify(info: dict[str, object]) -> tuple[str, str]:
    """Classify a parsed certificate. Returns (category, recommendation)."""
    algorithm = str(info.get("algorithm", "unknown"))
    oid = str(info.get("oid", ""))

    if oid and is_pqc_oid(oid):
        return "pqc-ready", f"Algorithm {pqc_name(oid)} is a NIST PQC primitive; retain."

    bits_val = info.get("key_bits")
    bits = bits_val if isinstance(bits_val, int) else None

    if algorithm == "RSA":
        if bits is None:
            return "unknown", "RSA key without parsed bit length; manual review required."
        category = assess_rsa(bits)
        return category, "Migrate to ML-KEM / ML-DSA hybrid by CNSA 2.0 deadline."

    if algorithm == "ECDSA":
        curve = str(info.get("curve") or "")
        category = assess_ec(curve) if curve else "unknown"
        return category, "Plan migration to ML-DSA per CNSA 2.0."

    if algorithm in {"Ed25519", "Ed448"}:
        category = assess_ec(algorithm.lower())
        return category, "Plan migration to ML-DSA for long-lived signing roles."

    # DSA-* and other unrecognized algorithms: be conservative, mark unknown
    # (NOT "legacy" — DSA-1024 is weak, not legacy).
    return "unknown", "Algorithm not classified; manual review required."


def _findings_from_paths(paths: list[Path]) -> tuple[list[Finding], int]:
    """Build Findings; return (findings, error_count). Narrow exception list."""
    findings: list[Finding] = []
    errors = 0
    for p in paths:
        try:
            data = read_certificate(p)
            info = identify_certificate(data)
        except (ValueError, OSError) as exc:
            logger.error("not a valid X.509 certificate (PEM/DER parse failed): %s: %s", p, exc)
            errors += 1
            continue
        assessment, recommendation = _classify(info)
        bits_val = info.get("key_bits")
        findings.append(
            Finding(
                asset_id=str(p),
                algorithm=str(info.get("algorithm", "unknown")),
                key_bits=bits_val if isinstance(bits_val, int) else None,
                oid=str(info.get("oid")) if info.get("oid") else None,
                assessment=assessment,
                recommendation=recommendation,
                source_path=str(p),
            )
        )
    return findings, errors


@click.group(help="pqc-readiness-cli — local cryptographic asset inventory.")
@click.option("--quiet", is_flag=True, help="Suppress non-error logging.")
@click.version_option(version=__version__, prog_name="pqc-readiness")
@click.pass_context
def main(ctx: click.Context, quiet: bool) -> None:
    """Top-level CLI group."""
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet
    _configure_logging(quiet)


def _resolve_inputs(certs: tuple[Path, ...], directory: Path | None) -> list[Path]:
    """Resolve --cert + --directory into a list of input paths.

    Allows both flags simultaneously (merges results); logs INFO on merge.
    """
    paths: list[Path] = list(certs)
    if directory is not None:
        if certs:
            logger.info("merging --cert inputs with --directory walk")
        paths.extend(walk_directory(directory))
    return paths


@main.command(help="Inventory PEM/DER certificate files and emit CycloneDX 1.7 CBOM.")
@click.option("--cert", "certs", multiple=True, type=click.Path(exists=True, path_type=Path),
              help="Path to a certificate file (repeatable).")
@click.option("--directory", "directory", type=click.Path(exists=True, path_type=Path),
              help="Directory to recursively walk for PEM/DER files.")
@click.option("--output", "output", type=click.Path(path_type=Path), default=None,
              help="Output CBOM path. Defaults to stdout.")
@click.option("--format", "fmt", type=click.Choice(["json"]), default="json",
              help="Output format (CycloneDX 1.7 JSON).")
def inventory(
    certs: tuple[Path, ...],
    directory: Path | None,
    output: Path | None,
    fmt: str,
) -> None:
    """Inventory action: parse files locally and emit CBOM."""
    if not certs and not directory:
        click.echo("no certificate files provided", err=True)
        sys.exit(EXIT_USAGE)

    paths = _resolve_inputs(certs, directory)
    if not paths:
        click.echo("no certificate files found in the given inputs", err=True)
        sys.exit(EXIT_NO_FINDINGS)

    findings, errors = _findings_from_paths(paths)
    if errors and not findings:
        click.echo(f"all {errors} input(s) failed to parse; no findings produced", err=True)
        sys.exit(EXIT_NO_FINDINGS)

    bom = build_bom(findings)
    payload = emit_json(bom)

    if output:
        try:
            output.write_text(payload, encoding="utf-8")
            logger.info("wrote CBOM to %s (%d finding(s), %d error(s))", output, len(findings), errors)
        except OSError as exc:
            click.echo(f"failed to write CBOM to {output}: {exc}", err=True)
            sys.exit(EXIT_OUTPUT_ERROR)
    else:
        click.echo(payload)

    # Non-zero exit if some inputs failed but others produced findings — surface it
    if errors:
        sys.exit(EXIT_NO_FINDINGS)


@main.command(help="List algorithms detected across input files.")
@click.option("--cert", "certs", multiple=True, type=click.Path(exists=True, path_type=Path))
@click.option("--directory", "directory", type=click.Path(exists=True, path_type=Path))
def algorithms(certs: tuple[Path, ...], directory: Path | None) -> None:
    """Print one algorithm summary per detected certificate."""
    if not certs and not directory:
        click.echo("no certificate files provided", err=True)
        sys.exit(EXIT_USAGE)

    paths = _resolve_inputs(certs, directory)
    if not paths:
        click.echo("no certificate files found in the given inputs", err=True)
        sys.exit(EXIT_NO_FINDINGS)

    findings, errors = _findings_from_paths(paths)
    for f in findings:
        click.echo("\t".join([
            f.algorithm,
            str(f.key_bits or "-"),
            f.oid or "-",
            f.assessment,
            f.source_path,
        ]))

    if errors and not findings:
        sys.exit(EXIT_NO_FINDINGS)


@main.command(help="Print the version and exit.")
def version() -> None:
    """Print the package version."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
