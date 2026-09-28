"""``polarys``: administration commands for the ingest service.

Configuration comes from ``POLARYS_*`` environment variables (see ``polarys.config``).
"""

from __future__ import annotations

import json
import sys

import click

from . import __version__
from .config import Settings
from .db import Database
from .ledger import ApiClient, Ledger
from .records import IdentityError, Submitter
from .util import utcnow


def _settings() -> Settings:
    try:
        return Settings()
    except Exception as e:
        raise click.ClickException(f"configuration error: {e}") from None


def _ledger(s: Settings) -> Ledger:
    return Ledger(Database.open(s.database_url, 2))


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="polarys")
def main() -> None:
    """Run and administer the POLARYS ingest service."""


@main.command("init-db")
def init_db():
    """Create the ledger schema (safe to re-run) and open the first interval."""
    s = _settings()
    iv = _ledger(s).init_schema(utcnow())
    click.echo(f"ledger ready ({s.database_url.split('@')[-1]}); open interval {iv.interval_id}")


@main.group()
def keys():
    """Manage the local keystore."""


@keys.command("init")
def keys_init():
    """Create the keystore (record key, block key, KEK) in POLARYS_KEYSTORE_DIR."""
    from .keys import LocalKeyProvider

    s = _settings()
    try:
        pw = s.passphrase()
    except ValueError:
        pw = click.prompt("Keystore passphrase", hide_input=True, confirmation_prompt=True)
    p = LocalKeyProvider.create(s.keystore_dir, pw)
    click.echo(json.dumps(p.keyring().to_document(), indent=2))


@main.group()
def client():
    """Manage API keys. Each key belongs to one user (UPN) or device (FQDN)."""


@client.command("add")
@click.option("--user", "upn", help="User principal name, e.g. jane.doe@contoso.com")
@click.option("--device", "fqdn", help="Device FQDN, e.g. dc01.corp.contoso.com")
@click.option("--name", "display_name", help="Display name for the submitter.")
@click.option("--source", "sources", multiple=True, type=click.Choice(["api", "windows_event"]), help="Allowed source types (default: api).")
@click.option("--class", "classes", multiple=True, help="Restrict to these record classes (default: any).")
@click.option("--role", "roles", multiple=True, type=click.Choice(["submitter", "auditor", "records_manager"]), help="Roles (default: submitter).")
@click.option("--webhook", help="HTTPS URL that receives receipts as soon as they are issued.")
def client_add(upn, fqdn, display_name, sources, classes, roles, webhook):
    """Create an API key (and webhook secret) and print them once."""
    import secrets

    from .api import new_api_key
    from .delivery import check_webhook_url

    if bool(upn) == bool(fqdn):
        raise click.UsageError("give exactly one of --user or --device")
    try:
        sub = Submitter("user" if upn else "device", upn or fqdn, "api-key", display_name)
    except IdentityError as e:
        raise click.UsageError(str(e)) from None
    s = _settings()
    webhook_secret = None
    if webhook:
        try:
            check_webhook_url(webhook, s.allow_http_webhooks)
        except ValueError as e:
            raise click.UsageError(str(e)) from None
        webhook_secret = "whsec_" + secrets.token_urlsafe(32)
    if classes:
        from .classes import ClassRegistry

        reg = ClassRegistry()
        for c in classes:
            try:
                reg.get(c)
            except KeyError as e:
                raise click.UsageError(str(e)) from None
    key_id, token, secret_hash = new_api_key()
    _ledger(s).add_client(
        ApiClient(key_id, secret_hash, sub.type, sub.id, display_name, "api-key",
                  tuple(sources) or ("api",), tuple(classes) or None, tuple(roles) or ("submitter",), webhook, True,
                  webhook_secret),
        utcnow(),
    )
    click.echo(f"API key for {sub.type} {sub.id} (key id {key_id}). Store it now; it is not shown again:\n\n  {token}\n")
    if webhook_secret:
        click.echo(f"Webhook signing secret for {webhook}:\n\n  {webhook_secret}\n")


@client.command("list")
def client_list():
    for c in _ledger(_settings()).list_clients():
        state = "active" if c.active else "revoked"
        classes = ",".join(c.allowed_classes) if c.allowed_classes else "any"
        click.echo(f"{c.key_id}  {state:<7}  {c.submitter_type:<6} {c.submitter_id:<40} sources={','.join(c.allowed_sources)} "
                   f"classes={classes} roles={','.join(c.roles)}")


@client.command("revoke")
@click.argument("key_id")
def client_revoke(key_id):
    """Revoke an API key (takes effect within POLARYS_CLIENT_CACHE_SECONDS)."""
    if not _ledger(_settings()).revoke_client(key_id, utcnow()):
        raise click.ClickException(f"no active key {key_id}")
    click.echo(f"revoked {key_id}")


@main.command()
@click.option("--host", default=None)
@click.option("--port", type=int, default=None)
@click.option("--workers", type=int, default=1, show_default=True)
def serve(host, port, workers):
    """Run the REST API with uvicorn."""
    import uvicorn

    s = _settings()
    if s.database_url.startswith("sqlite") and workers > 1:
        raise click.UsageError("SQLite mode supports a single worker; use PostgreSQL for more")
    uvicorn.run("polarys.api:app_from_env", factory=True, host=host or s.host, port=port or s.port, workers=workers,
                proxy_headers=False, log_level="info")


@main.command()
def status():
    """Show ledger, spool and index-queue status."""
    from .store import open_store
    from .store.spool import SpoolingStore

    s = _settings()
    led = _ledger(s)
    iv = led.ensure_open_interval(utcnow())
    store = open_store(s)
    out = {
        "records": led.count_records(),
        "open_interval": iv.interval_id,
        "index_queue": led.index_queue_size(),
        "latest_block": (led.latest_block() or {}).get("block_id"),
        "store": store.name,
    }
    if isinstance(store, SpoolingStore):
        out["spool_pending_objects"] = len(store.pending())
    click.echo(json.dumps(out, indent=2))


@main.group()
def sealer():
    """The 5-minute sealer (run exactly one leader; extra instances wait as standbys)."""


def _logging(level: str) -> None:
    import logging

    logging.basicConfig(level=getattr(logging, level.upper()), format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@sealer.command("run")
@click.option("--log-level", default="info", show_default=True)
def sealer_run(log_level):
    """Seal at every boundary and deliver webhooks until stopped (SIGTERM / Ctrl-C)."""
    import signal

    from .service import build_sealer_service

    _logging(log_level)
    service, _ = build_sealer_service(_settings())
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: service.stop.set())
    service.run()


@sealer.command("once")
@click.option("--no-close", is_flag=True, help="Only finish pending work; do not close the open interval.")
@click.option("--log-level", default="warning", show_default=True)
def sealer_once(no_close, log_level):
    """Run one sealing cycle now (refuses if another sealer holds the lock)."""
    from .service import build_sealer_service

    _logging(log_level)
    service, _ = build_sealer_service(_settings())
    if not service.lock.acquire():
        raise click.ClickException("another sealer holds the leader lock")
    try:
        rep = service.sealer.run_cycle(freeze=not no_close)
        deliveries = service.deliverer.run_once()
    finally:
        service.lock.release()
    click.echo(json.dumps({**rep.to_dict(), "webhooks": deliveries.__dict__}, indent=2))
    sys.exit(1 if rep.errors else 0)


@main.command()
def deliver():
    """Deliver due receipt webhooks once."""
    from datetime import timedelta

    from .delivery import Deliverer

    s = _settings()
    rep = Deliverer(_ledger(s), timeout=s.webhook_timeout_seconds, retry_window=timedelta(hours=s.webhook_retry_hours),
                    allow_http=s.allow_http_webhooks).run_once()
    click.echo(json.dumps(rep.__dict__))


@main.group()
def chain():
    """Chain audit."""


@chain.command("verify")
@click.option("--from", "first", type=int, default=None)
@click.option("--to", "last", type=int, default=None)
@click.option("--no-leaves", is_flag=True, help="Skip recomputing Merkle roots from the ledger's leaf hashes.")
@click.option("--json", "as_json", is_flag=True)
def chain_verify(first, last, no_leaves, as_json):
    """Verify signatures, hash links, timestamp tokens and Merkle roots of the stored chain."""
    from .keys import LocalKeyProvider
    from .service import trust_roots, verify_ledger_chain

    s = _settings()
    ring = LocalKeyProvider(s.keystore_dir, s.passphrase()).keyring()
    roots = trust_roots(s)
    if roots is None and s.tsa_mode == "dev":
        from .devtsa import DevTSA

        roots = [DevTSA.load_or_create(s.dev_tsa_dir).ca_cert]
    res = verify_ledger_chain(_ledger(s), ring, roots, first, last, check_leaves=not no_leaves)
    if as_json:
        click.echo(json.dumps(res.to_dict(), indent=2))
    else:
        for b in res.report.blocks:
            mark = click.style("PASS" if not b.errors else "FAIL", fg="green" if not b.errors else "red", bold=True)
            click.echo(f"  {mark}  block {b.block_id:<7} {b.gen_time:%Y-%m-%d %H:%M:%SZ}  {b.tsa or ''}" if b.gen_time
                       else f"  {mark}  block {b.block_id}")
            for e in b.errors:
                click.echo(f"          error: {e}")
        for e in res.report.errors:
            click.echo(f"  error: {e}")
        if res.unanchored:
            click.echo(f"  waiting for a timestamp: blocks {res.unanchored}")
        for w in sorted({w for b in res.report.blocks for w in b.warnings}):
            click.echo(f"  WARN  {w}")
        click.echo(("VALID" if res.ok else "INVALID") + f": {res.checked} anchored block(s) checked")
    sys.exit(0 if res.ok else 1)


@main.group()
def spool():
    """Object-store spool."""


@spool.command("drain")
def spool_drain():
    """Upload spooled objects to the primary store."""
    from .ingest import drain_spool
    from .store import open_store

    s = _settings()
    result = drain_spool(_ledger(s), open_store(s))
    click.echo(json.dumps(result))
    sys.exit(0 if result["pending"] == 0 else 1)


if __name__ == "__main__":
    main()
