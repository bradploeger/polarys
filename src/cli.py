"""logverify: independent verification of POLARYS receipts, blocks and chains."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from . import __version__
from .blocks import verify_chain
from .keys import KeyRing, LocalKeyProvider
from .merkle import MerkleTree
from .receipts import verify_receipt
from .tsa import DEFAULT_TSAS, AllTSAsFailed, TimestampError, TSAClient, load_certificates, now_utc, verify_token

OK, FAIL, WARN = "PASS", "FAIL", "WARN"


def _roots(paths: tuple[str, ...]):
    certs = []
    for p in paths:
        certs += load_certificates(Path(p).read_bytes())
    return certs or None


def _keyring(path: str | None) -> KeyRing | None:
    return KeyRing.load(path) if path else None


def _color(ok: bool) -> str:
    return click.style(OK if ok else FAIL, fg="green" if ok else "red", bold=True)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="logverify")
def main() -> None:
    """Verify POLARYS receipts, timestamp tokens and block chains offline."""


@main.command()
@click.argument("receipt_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--keys", "keys", type=click.Path(exists=True), help="Published log-keys.json to pin the server keys.")
@click.option("--tsa-ca", multiple=True, type=click.Path(exists=True), help="Trusted TSA root certificate(s), PEM or DER.")
@click.option("--document", "documents", multiple=True, type=click.Path(exists=True), help="Original file(s) to check against the record.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def receipt(receipt_file, keys, tsa_ca, documents, as_json):
    """Verify a submitter receipt end to end."""
    data = json.loads(Path(receipt_file).read_text())
    docs = [(Path(d).name, Path(d).read_bytes()) for d in documents]
    rep = verify_receipt(data, _keyring(keys), _roots(tsa_ca), docs)
    if as_json:
        click.echo(json.dumps(rep.to_dict(), indent=2))
    else:
        env = data.get("signed_record", {}).get("envelope", {})
        click.echo(f"Record   {data.get('record_id')}")
        click.echo(f"Class    {env.get('record_class')}   submitter {env.get('submitter', {}).get('id')}")
        click.echo(f"Block    {data.get('block_header', {}).get('block_id')}\n")
        for s in rep.steps:
            click.echo(f"  {_color(s.ok)}  {s.name:<36} {s.detail}")
        for w in rep.warnings:
            click.echo(f"  {click.style(WARN, fg='yellow', bold=True)}  {w}")
        click.echo()
        if rep.ok:
            click.echo(click.style(f"VALID: record existed unaltered no later than {rep.gen_time}", fg="green", bold=True))
        else:
            click.echo(click.style("INVALID: see failed steps above", fg="red", bold=True))
    sys.exit(0 if rep.ok else 1)


@main.command()
@click.argument("store_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--keys", "keys", type=click.Path(exists=True), required=True, help="Published log-keys.json.")
@click.option("--tsa-ca", multiple=True, type=click.Path(exists=True), help="Trusted TSA root certificate(s).")
@click.option("--from", "from_id", type=int, default=None, help="First block id (default: genesis).")
@click.option("--to", "to_id", type=int, default=None, help="Last block id (default: newest).")
@click.option("--check-trees/--no-check-trees", default=True, help="Re-derive each Merkle root from trees/<id>.bin.")
@click.option("--json", "as_json", is_flag=True)
def chain(store_dir, keys, tsa_ca, from_id, to_id, check_trees, as_json):
    """Verify the hash chain, sealer signatures and timestamps of a stored ledger."""
    root = Path(store_dir)
    ids = sorted(int(p.stem) for p in (root / "blocks").glob("*.json"))
    if from_id is not None:
        ids = [i for i in ids if i >= from_id]
    if to_id is not None:
        ids = [i for i in ids if i <= to_id]
    blocks, leaves = [], {}
    for i in ids:
        header = json.loads((root / "blocks" / f"{i}.json").read_text())
        tok_path = root / "tokens" / f"{i}.tsr"
        blocks.append((header, tok_path.read_bytes() if tok_path.exists() else None))
        tree_path = root / "trees" / f"{i}.bin"
        if check_trees and tree_path.exists():
            try:
                leaves[i] = MerkleTree.from_bytes(tree_path.read_bytes()).levels[0]
            except ValueError as e:
                leaves[i] = []
                click.echo(f"block {i}: {e}", err=True)
    report = verify_chain(blocks, KeyRing.load(keys), _roots(tsa_ca), leaves, expect_genesis=from_id in (None, 0))
    if as_json:
        click.echo(json.dumps({"ok": report.ok, "errors": report.errors, "blocks": [
            {"block_id": b.block_id, "ok": not b.errors, "errors": b.errors, "warnings": b.warnings,
             "gen_time": b.gen_time.isoformat() if b.gen_time else None, "tsa": b.tsa} for b in report.blocks]}, indent=2))
    else:
        for e in report.errors:
            click.echo(f"  {_color(False)}  {e}")
        for b in report.blocks:
            when = b.gen_time.strftime("%Y-%m-%d %H:%M:%SZ") if b.gen_time else "-"
            click.echo(f"  {_color(not b.errors)}  block {b.block_id:<6} {when}  {b.tsa or ''}")
            for e in b.errors:
                click.echo(f"          {click.style('error', fg='red')}: {e}")
        warns = sorted({w for b in report.blocks for w in b.warnings})
        for w in warns:
            click.echo(f"  {click.style(WARN, fg='yellow', bold=True)}  {w}")
        n = len(report.blocks)
        click.echo()
        click.echo(click.style(f"{'VALID' if report.ok else 'INVALID'}: {n} block(s) checked", fg="green" if report.ok else "red", bold=True))
    sys.exit(0 if report.ok else 1)


@main.command()
@click.argument("token_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--digest", help="Expected SHA-256 (hex) the token should cover.")
@click.option("--tsa-ca", multiple=True, type=click.Path(exists=True))
def token(token_file, digest, tsa_ca):
    """Inspect and verify an RFC 3161 token (.tsr, DER)."""
    try:
        info = verify_token(Path(token_file).read_bytes(), bytes.fromhex(digest) if digest else None, trust_roots=_roots(tsa_ca))
    except TimestampError as e:
        click.echo(f"{_color(False)}  {e}")
        sys.exit(1)
    click.echo(json.dumps(info.summary(), indent=2))


@main.command("tsa-check")
@click.option("--timeout", default=10.0, show_default=True)
def tsa_check(timeout):
    """Request a test timestamp from each configured public TSA."""
    import hashlib

    digest = hashlib.sha256(b"POLARYS TSA connectivity check").digest()
    failures = 0
    for tsa in DEFAULT_TSAS:
        client = TSAClient([tsa], attempts_per_tsa=1, timeout=timeout, retry_delay=0)
        try:
            r = client.timestamp(digest, now_utc())
            click.echo(f"  {_color(True)}  {tsa.name:<14} {r.info.gen_time.isoformat()}  {r.info.tsa_name}")
        except AllTSAsFailed as e:
            failures += 1
            click.echo(f"  {_color(False)}  {tsa.name:<14} {e.attempts[-1].split(': ', 1)[-1]}")
        finally:
            client.close()
    sys.exit(0 if failures < len(DEFAULT_TSAS) else 1)


@main.command()
@click.argument("directory", type=click.Path(file_okay=False))
@click.option("--passphrase", envvar="POLARYS_KEY_PASSPHRASE", prompt=True, hide_input=True, confirmation_prompt=True)
def keygen(directory, passphrase):
    """Create a local keystore and print its public key document."""
    provider = LocalKeyProvider.create(directory, passphrase)
    doc = provider.keyring().to_document()
    Path(directory, "log-keys.json").write_text(json.dumps(doc, indent=2))
    click.echo(json.dumps(doc, indent=2))


@main.command()
@click.argument("directory", type=click.Path(file_okay=False))
def demo(directory):
    """Write a sample ledger (development TSA) to try the verifier on."""
    from .demo import build_demo

    summary = build_demo(directory)
    click.echo(f"Sample ledger with {len(summary['blocks'])} blocks and {len(summary['receipts'])} receipts written to {directory}")
    click.echo(Path(directory, "README.txt").read_text())


if __name__ == "__main__":
    main()
