"""Leader election for the singleton sealer.

Any number of sealer processes may run; exactly one seals at a time.

* PostgreSQL: a session-level advisory lock held on a dedicated connection. If
  the leader's process or connection dies, the server releases the lock and a
  standby takes over within its polling period.
* SQLite: an exclusive ``flock`` on ``<ledger>.sealer.lock`` (single host).

The sealing transactions are also safe on their own (block ids are primary
keys and closing an interval is a single conditional UPDATE), so a brief
overlap during failover cannot fork the chain.
"""

from __future__ import annotations

import fcntl
import os
from urllib.parse import urlparse

from .db import Database, PostgresDatabase

SEALER_LOCK_KEY = 7331002


class LeaderLock:
    def acquire(self) -> bool:
        raise NotImplementedError

    def still_held(self) -> bool:
        raise NotImplementedError

    def release(self) -> None:
        raise NotImplementedError

    @staticmethod
    def for_database(db: Database, lock_key: int = SEALER_LOCK_KEY) -> "LeaderLock":
        if isinstance(db, PostgresDatabase):
            return PgAdvisoryLock(db, lock_key)
        path = db.url.split("sqlite:///", 1)[-1] or "polarys-ledger.db"
        return FileLock(path + ".sealer.lock")


class PgAdvisoryLock(LeaderLock):
    def __init__(self, db: PostgresDatabase, key: int):
        self.db, self.key = db, key
        self.conn = None
        self.held = False

    def _connection(self):
        if self.conn is None or getattr(self.conn, "closed", False):
            self.conn = self.db._connect()
            self.conn.autocommit = True
            self.held = False
        return self.conn

    def acquire(self) -> bool:
        if self.held and self.still_held():
            return True
        try:
            row = self._connection().execute("SELECT pg_try_advisory_lock(%s)", (self.key,)).fetchone()
            self.held = bool(row[0])
        except Exception:
            self._drop()
        return self.held

    def still_held(self) -> bool:
        if not self.held or self.conn is None:
            return False
        try:
            row = self.conn.execute(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() "
                "AND objid = %s AND granted", (self.key,)
            ).fetchone()
            self.held = int(row[0]) > 0
        except Exception:
            self._drop()
        return self.held

    def release(self) -> None:
        if self.conn is not None and self.held:
            try:
                self.conn.execute("SELECT pg_advisory_unlock(%s)", (self.key,))
            except Exception:
                pass
        self._drop()

    def _drop(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None
        self.held = False


class FileLock(LeaderLock):
    def __init__(self, path: str):
        self.path = path
        self.fd: int | None = None

    def acquire(self) -> bool:
        if self.fd is not None:
            return True
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        self.fd = fd
        return True

    def still_held(self) -> bool:
        return self.fd is not None

    def release(self) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def describe(db: Database) -> str:
    if isinstance(db, PostgresDatabase):
        u = urlparse(db.url)
        return f"postgres advisory lock {SEALER_LOCK_KEY} on {u.hostname or 'local socket'}"
    return "file lock"
