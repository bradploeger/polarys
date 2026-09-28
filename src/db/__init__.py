"""Database access for the ledger.

``Database.open(url)`` accepts

* ``postgresql://…``  PostgreSQL (production). Uses psycopg 3 when installed, else the
  built-in ``pgwire`` client.  Force one with ``?driver=psycopg`` or ``?driver=pgwire``.
* ``sqlite:///path/to/ledger.db``  single-process development mode (stdlib sqlite3).

All SQL is written with ``%s`` placeholders.  Transactions come from
``db.transaction()``; the yielded object has ``execute(sql, params) -> list[tuple]``
and ``rowcount``.  PostgreSQL uses a small thread-safe connection pool; SQLite
uses one connection and serialises transactions with ``BEGIN IMMEDIATE``.
"""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


class DatabaseError(Exception):
    pass


class UniqueViolation(DatabaseError):
    pass


class Tx:
    def __init__(self, conn, dialect: str):
        self._conn = conn
        self.dialect = dialect
        self.rowcount = -1

    def execute(self, sql: str, params: tuple | list = ()) -> list[tuple]:
        try:
            if self.dialect == "sqlite":
                cur = self._conn.execute(sql.replace("%s", "?"), tuple(params))
                rows = cur.fetchall()
            else:
                cur = self._conn.execute(sql, tuple(params))
                rows = cur.fetchall() if cur.description else []
        except Exception as e:  # map driver-specific unique violations
            if _is_unique_violation(e):
                raise UniqueViolation(str(e)) from e
            raise
        self.rowcount = cur.rowcount
        return rows

    def one(self, sql: str, params: tuple | list = ()):
        rows = self.execute(sql, params)
        return rows[0] if rows else None


def _is_unique_violation(e: Exception) -> bool:
    if isinstance(e, sqlite3.IntegrityError) and "UNIQUE" in str(e):
        return True
    return getattr(e, "sqlstate", None) == "23505"


class Database:
    def __init__(self, dialect: str, url: str):
        self.dialect = dialect
        self.url = url

    @staticmethod
    def open(url: str, pool_size: int = 8) -> "Database":
        if url.startswith("sqlite:"):
            return SQLiteDatabase(url)
        if url.startswith(("postgresql:", "postgres:")):
            return PostgresDatabase(url, pool_size)
        raise ValueError("database URL must start with postgresql:// or sqlite:///")

    @contextmanager
    def transaction(self):
        raise NotImplementedError

    def close(self) -> None:
        pass


class SQLiteDatabase(Database):
    def __init__(self, url: str):
        super().__init__("sqlite", url)
        path = url.split("sqlite:///", 1)[1] if url.startswith("sqlite:///") else ":memory:"
        self._conn = sqlite3.connect(path or ":memory:", check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield Tx(self._conn, "sqlite")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def executescript(self, script: str) -> None:
        with self._lock:
            self._conn.executescript(script)

    def close(self) -> None:
        self._conn.close()


class PostgresDatabase(Database):
    def __init__(self, url: str, pool_size: int = 8):
        super().__init__("postgres", url)
        u = urlparse(url)
        q = {k: v[-1] for k, v in parse_qs(u.query).items()}
        self.driver = q.pop("driver", None) or _default_driver()
        self._dsn = urlunparse(u._replace(query=urlencode(q)))
        self._pool: queue.LifoQueue = queue.LifoQueue()
        self._size = pool_size
        self._created = 0
        self._lock = threading.Lock()

    def _connect(self):
        if self.driver == "psycopg":
            import psycopg

            return psycopg.connect(self._dsn, autocommit=False, options="-c TimeZone=UTC")
        from . import pgwire

        return pgwire.connect(self._dsn)

    def _acquire(self):
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            if self._created < self._size:
                self._created += 1
                try:
                    return self._connect()
                except Exception:
                    self._created -= 1
                    raise
        return self._pool.get(timeout=30)

    def _release(self, conn, broken: bool) -> None:
        if broken or getattr(conn, "closed", False):
            try:
                conn.close()
            except Exception:
                pass
            with self._lock:
                self._created -= 1
        else:
            self._pool.put(conn)

    @contextmanager
    def transaction(self):
        conn = self._acquire()
        broken = False
        try:
            yield Tx(conn, "postgres")
            conn.commit()
        except BaseException as e:
            try:
                conn.rollback()
            except Exception:
                broken = True
            if isinstance(e, (OSError, ConnectionError)) or type(e).__name__ in ("InterfaceError", "OperationalError"):
                broken = True
            raise
        finally:
            self._release(conn, broken)

    def close(self) -> None:
        while True:
            try:
                self._pool.get_nowait().close()
            except queue.Empty:
                break


def _default_driver() -> str:
    try:
        import psycopg  # noqa: F401

        return "psycopg"
    except ImportError:
        return "pgwire"


def retry_serialization(fn, attempts: int = 5):
    """Retry ``fn`` on serialization failures and deadlocks (SQLSTATE 40001 / 40P01)."""
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            if getattr(e, "sqlstate", None) in ("40001", "40P01") and i < attempts - 1:
                time.sleep(0.01 * 2**i)
                continue
            raise
