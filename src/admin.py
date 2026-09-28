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
@click.option("--webhook", help="Receipt webhook URL (used from Phase 3).")
def client_add(upn, fqdn, display_name, sources, classes, roles, webhook):
    """Create an API key and print it once."""
    from .api import new_api_key

    if bool(upn) == bool(fqdn):
        raise click.UsageError("give exactly one of --user or --device")
    try:
        sub = Submitter("user" if upn else "device", upn or fqdn, "api-key", display_name)
    except IdentityError as e:
        raise click.UsageError(str(e)) from None
    s = _settings()
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
                  tuple(sources) or ("api",), tuple(classes) or None, tuple(roles) or ("submitter",), webhook, True),
        utcnow(),
    )
    click.echo(f"API key for {sub.type} {sub.id} (key id {key_id}). Store it now; it is not shown again:\n\n  {token}\n")


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
