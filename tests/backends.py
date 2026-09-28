"""Ledger backends for tests.

SQLite always runs.  PostgreSQL runs when ``POLARYS_TEST_PG_DSN`` points at a
server where the test user may create databases, e.g.
``postgresql://postgres@/postgres?host=/run/postgresql``.  Each test gets a fresh database.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from contextlib import contextmanager
from urllib.parse import urlparse, urlunparse

from polarys.db import Database
from polarys.db import pgwire
from polarys.ledger import Ledger
from polarys.util import utcnow

PG_DSN = os.environ.get("POLARYS_TEST_PG_DSN")


def backend_names() -> list[str]:
    return ["sqlite"] + (["postgres"] if PG_DSN else [])


@contextmanager
def fresh_ledger(kind: str, pool_size: int = 8):
    if kind == "sqlite":
        db = Database.open("sqlite:///" + tempfile.mkdtemp() + "/ledger.db")
        ledger = Ledger(db)
        ledger.init_schema(utcnow())
        try:
            yield ledger
        finally:
            db.close()
        return
    name = "polarys_test_" + secrets.token_hex(4)
    admin = pgwire.connect(PG_DSN)
    admin.autocommit = True
    admin.execute(f"CREATE DATABASE {name}")
    u = urlparse(PG_DSN)
    url = urlunparse(u._replace(path="/" + name))
    db = Database.open(url, pool_size)
    ledger = Ledger(db)
    ledger.init_schema(utcnow())
    try:
        yield ledger
    finally:
        db.close()
        admin.execute(f"DROP DATABASE {name} WITH (FORCE)")
        admin.close()
