"""The ledger: records, intervals, data keys, API clients, blocks and receipts.

Interval hand-off
-----------------
Exactly one interval is ``open`` at a time.  Every ingest transaction reads the
open interval with ``FOR SHARE``; the sealer closes it with an ``UPDATE`` that
waits for those share locks, and opens the next interval in the same
transaction.  So when the sealer holds a closed interval, every record that
will ever belong to it has committed: no record can straddle a seal and no
timing heuristic is needed.  (SQLite, single process, gets the same guarantee
from ``BEGIN IMMEDIATE``.)
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime

from .db import Database, Tx
from .db.schema import MIGRATIONS, POSTGRES, SCHEMA_VERSION, SQLITE
from .util import parse_rfc3339, rfc3339


class LedgerError(Exception):
    pass


def new_interval_id(t: datetime) -> str:
    return t.strftime("%Y%m%dT%H%M%S") + f".{t.microsecond // 1000:03d}Z"


@dataclass(frozen=True)
class Interval:
    interval_id: str
    opened_at: datetime
    closed_at: datetime | None = None
    record_count: int | None = None


@dataclass(frozen=True)
class ApiClient:
    key_id: str
    secret_hash: bytes
    submitter_type: str
    submitter_id: str
    display_name: str | None
    auth_method: str
    allowed_sources: tuple[str, ...]
    allowed_classes: tuple[str, ...] | None
    roles: tuple[str, ...]
    webhook_url: str | None
    active: bool
    webhook_secret: str | None = None


_RECORD_COLS = (
    "record_id, interval_id, received_at, source_type, submitter_type, submitter_id, record_class, "
    "retention_rule, retain_until, legal_hold, content_type, payload_sha256, payload_size, document_count, "
    "signing_key_id, signature, leaf_hash, object_key, object_state, api_key_id, idempotency_key, request_hash, "
    "status, block_id, leaf_index, ingest_seq"
)


class Ledger:
    def __init__(self, db: Database):
        self.db = db
        self.pg = db.dialect == "postgres"
        self.J = "%s::jsonb" if self.pg else "%s"  # JSON parameter placeholder
        self.FOR_SHARE = " FOR SHARE" if self.pg else ""

    # -- value conversion ----------------------------------------------------------

    def _t(self, dt: datetime | None):
        if dt is None:
            return None
        return dt if self.pg else rfc3339(dt)

    @staticmethod
    def _dt(v) -> datetime | None:
        if v is None:
            return None
        return v if isinstance(v, datetime) else parse_rfc3339(v)

    @staticmethod
    def _json(v):
        if v is None:
            return None
        return json.loads(v) if isinstance(v, (str, bytes)) else v

    @staticmethod
    def _s(v) -> str | None:
        return None if v is None else str(v)

    # -- schema -------------------------------------------------------------------------

    def init_schema(self, now: datetime) -> Interval:
        """Create or migrate the schema to SCHEMA_VERSION (safe to re-run), then ensure an open interval."""
        if self.pg:
            with self.db.transaction() as tx:
                tx.execute("SELECT pg_advisory_xact_lock(7331001)")
                for stmt in [s.strip() for s in POSTGRES.split(";") if s.strip()]:
                    tx.execute(stmt)
                self._migrate(tx)
        else:
            self.db.executescript(SQLITE)
            with self.db.transaction() as tx:
                self._migrate(tx)
        return self.ensure_open_interval(now)

    def _migrate(self, tx: Tx) -> None:
        row = tx.one("SELECT value FROM schema_meta WHERE key = 'version'")
        version = int(row[0]) if row else 1
        if version > SCHEMA_VERSION:
            raise LedgerError(f"ledger schema version {version} is newer than this software ({SCHEMA_VERSION})")
        for v in range(version + 1, SCHEMA_VERSION + 1):
            for stmt in MIGRATIONS[v]["postgres" if self.pg else "sqlite"]:
                tx.execute(stmt)
        if row is None:
            tx.execute("INSERT INTO schema_meta (key, value) VALUES ('version', %s)", (str(SCHEMA_VERSION),))
        else:
            tx.execute("UPDATE schema_meta SET value = %s WHERE key = 'version'", (str(SCHEMA_VERSION),))

    def schema_version(self) -> int:
        with self.db.transaction() as tx:
            row = tx.one("SELECT value FROM schema_meta WHERE key = 'version'")
        return int(row[0]) if row else 0

    def ensure_open_interval(self, now: datetime) -> Interval:
        with self.db.transaction() as tx:
            row = tx.one("SELECT interval_id, opened_at FROM intervals WHERE state = 'open'")
            if row:
                return Interval(row[0], self._dt(row[1]))
            iid = new_interval_id(now)
            tx.execute(
                "INSERT INTO intervals (interval_id, opened_at, state) VALUES (%s, %s, 'open') ON CONFLICT DO NOTHING",
                (iid, self._t(now)),
            )
            row = tx.one("SELECT interval_id, opened_at FROM intervals WHERE state = 'open'")
            return Interval(row[0], self._dt(row[1]))

    # -- ingest -------------------------------------------------------------------------

    def ingest(self):
        """Context manager for one ingest transaction (see ``IngestTx``)."""
        return _IngestContext(self)

    # -- records ------------------------------------------------------------------------

    def _record_row(self, r) -> dict:
        names = [c.strip() for c in _RECORD_COLS.split(",")]
        d = dict(zip(names, r))
        d["record_id"] = self._s(d["record_id"])
        for k in ("received_at", "retain_until"):
            d[k] = self._dt(d[k])
        d["legal_hold"] = bool(d["legal_hold"])
        d["signature"] = bytes(d["signature"])
        d["leaf_hash"] = bytes(d["leaf_hash"])
        return d

    def get_record(self, record_id: str) -> dict | None:
        try:
            uuid.UUID(record_id)
        except ValueError:
            return None
        with self.db.transaction() as tx:
            r = tx.one(f"SELECT {_RECORD_COLS} FROM records WHERE record_id = %s", (record_id,))
        return self._record_row(r) if r else None

    def interval_records(self, interval_id: str) -> list[dict]:
        with self.db.transaction() as tx:
            rows = tx.execute(f"SELECT {_RECORD_COLS} FROM records WHERE interval_id = %s ORDER BY ingest_seq", (interval_id,))
        return [self._record_row(r) for r in rows]

    def count_records(self) -> int:
        with self.db.transaction() as tx:
            return int(tx.one("SELECT count(*) FROM records")[0])

    def get_dek_row(self, interval_id: str, record_class: str) -> tuple[str, str, bytes] | None:
        with self.db.transaction() as tx:
            r = tx.one(
                "SELECT dek_id, kek_id, wrapped FROM data_keys WHERE interval_id = %s AND record_class = %s AND destroyed_at IS NULL",
                (interval_id, record_class),
            )
        return (r[0], r[1], bytes(r[2])) if r else None

    # -- object store spooling --------------------------------------------------------

    def spooled_records(self) -> list[dict]:
        with self.db.transaction() as tx:
            rows = tx.execute(f"SELECT {_RECORD_COLS} FROM records WHERE object_state = 'spooled' ORDER BY ingest_seq")
        return [self._record_row(r) for r in rows]

    def mark_stored(self, record_id: str) -> None:
        with self.db.transaction() as tx:
            tx.execute("UPDATE records SET object_state = 'stored' WHERE record_id = %s", (record_id,))

    # -- intervals and blocks (used by the Phase 3 sealer) -------------------------------

    def freeze_open_interval(self, now: datetime) -> Interval | None:
        """Close the open interval and open the next one atomically.

        Returns the closed interval, or None when it held no records (it is then
        marked ``empty`` and no block is made for it).
        """
        with self.db.transaction() as tx:
            row = tx.one(
                "UPDATE intervals SET state = 'sealing', closed_at = %s WHERE state = 'open' RETURNING interval_id, opened_at",
                (self._t(now),),
            )
            if row is None:
                raise LedgerError("there is no open interval")
            iid, opened = row[0], self._dt(row[1])
            nid = new_interval_id(now)
            if nid == iid:
                raise LedgerError("interval ids collide; wait at least 1 ms between seals")
            tx.execute("INSERT INTO intervals (interval_id, opened_at, state) VALUES (%s, %s, 'open')", (nid, self._t(now)))
            count = int(tx.one("SELECT count(*) FROM records WHERE interval_id = %s", (iid,))[0])
            if count == 0:
                tx.execute("UPDATE intervals SET state = 'empty' WHERE interval_id = %s", (iid,))
                return None
            return Interval(iid, opened, now, count)

    def sealing_intervals(self) -> list[Interval]:
        with self.db.transaction() as tx:
            rows = tx.execute(
                "SELECT i.interval_id, i.opened_at, i.closed_at, (SELECT count(*) FROM records r WHERE r.interval_id = i.interval_id) "
                "FROM intervals i WHERE i.state = 'sealing' ORDER BY i.opened_at"
            )
        return [Interval(r[0], self._dt(r[1]), self._dt(r[2]), int(r[3])) for r in rows]

    def store_block(
        self,
        header: dict,
        block_hash: bytes,
        interval_id: str,
        leaves: list[tuple[str, int]],
        token: bytes | None = None,
        tsa_name: str | None = None,
        gen_time: datetime | None = None,
    ) -> None:
        state = "anchored" if token else "sealed"
        with self.db.transaction() as tx:
            tx.execute(
                "INSERT INTO blocks (block_id, block_uuid, interval_id, created_at, header, block_hash, entry_count, token, tsa_name, gen_time, state) "
                f"VALUES (%s, %s, %s, %s, {self.J}, %s, %s, %s, %s, %s, %s)",
                (header["block_id"], header["block_uuid"], interval_id, self._t(parse_rfc3339(header["created_at"])),
                 json.dumps(header), block_hash, header["entry_count"], token, tsa_name, self._t(gen_time), state),
            )
            for record_id, leaf_index in leaves:
                tx.execute(
                    "UPDATE records SET block_id = %s, leaf_index = %s, status = %s WHERE record_id = %s AND interval_id = %s",
                    (header["block_id"], leaf_index, state, record_id, interval_id),
                )
                if tx.rowcount != 1:
                    raise LedgerError(f"record {record_id} is not in interval {interval_id}")
            tx.execute("UPDATE intervals SET state = 'sealed', block_id = %s WHERE interval_id = %s", (header["block_id"], interval_id))

    def anchor_block(self, block_id: int, token: bytes, tsa_name: str, gen_time: datetime) -> None:
        with self.db.transaction() as tx:
            tx.execute(
                "UPDATE blocks SET token = %s, tsa_name = %s, gen_time = %s, state = 'anchored' WHERE block_id = %s AND token IS NULL",
                (token, tsa_name, self._t(gen_time), block_id),
            )
            if tx.rowcount != 1:
                raise LedgerError(f"block {block_id} is missing or already anchored")
            tx.execute("UPDATE records SET status = 'anchored' WHERE block_id = %s", (block_id,))

    def _block_row(self, r) -> dict:
        return {
            "block_id": int(r[0]),
            "header": self._json(r[1]),
            "block_hash": bytes(r[2]),
            "token": bytes(r[3]) if r[3] is not None else None,
            "tsa_name": r[4],
            "gen_time": self._dt(r[5]),
            "state": r[6],
            "interval_id": r[7],
            "restamps": int(r[8]),
        }

    _BLOCK_COLS = "block_id, header, block_hash, token, tsa_name, gen_time, state, interval_id, restamps"

    def get_block(self, block_id: int) -> dict | None:
        with self.db.transaction() as tx:
            r = tx.one(f"SELECT {self._BLOCK_COLS} FROM blocks WHERE block_id = %s", (block_id,))
        return self._block_row(r) if r else None

    def latest_block(self) -> dict | None:
        with self.db.transaction() as tx:
            r = tx.one(f"SELECT {self._BLOCK_COLS} FROM blocks ORDER BY block_id DESC LIMIT 1")
        return self._block_row(r) if r else None

    def store_receipt(self, record_id: str, block_id: int, receipt: dict, now: datetime) -> None:
        self.store_receipts([(record_id, block_id, receipt)], now)

    def store_receipts(self, items: list[tuple[str, int, dict]], now: datetime) -> int:
        """Insert receipts (idempotent) and mark their records ``receipted``. Delivery is due immediately."""
        n = 0
        with self.db.transaction() as tx:
            for record_id, block_id, receipt in items:
                tx.execute(
                    "INSERT INTO receipts (record_id, block_id, receipt, created_at, next_attempt_at) "
                    f"VALUES (%s, %s, {self.J}, %s, %s) ON CONFLICT DO NOTHING",
                    (record_id, block_id, json.dumps(receipt), self._t(now), self._t(now)),
                )
                n += tx.rowcount
                tx.execute("UPDATE records SET status = 'receipted' WHERE record_id = %s", (record_id,))
        return n

    # -- sealer queries -------------------------------------------------------------------

    def blocks_in_state(self, state: str) -> list[dict]:
        with self.db.transaction() as tx:
            rows = tx.execute(f"SELECT {self._BLOCK_COLS} FROM blocks WHERE state = %s ORDER BY block_id", (state,))
        return [self._block_row(r) for r in rows]

    def blocks_range(self, first: int | None = None, last: int | None = None) -> list[dict]:
        with self.db.transaction() as tx:
            rows = tx.execute(
                f"SELECT {self._BLOCK_COLS} FROM blocks WHERE block_id >= %s AND block_id <= %s ORDER BY block_id",
                (first if first is not None else 0, last if last is not None else 2**62),
            )
        return [self._block_row(r) for r in rows]

    def restamp_block(self, block_id: int, header: dict, block_hash: bytes) -> None:
        """Replace the header of a block that has not been anchored yet (see Sealer.anchor)."""
        with self.db.transaction() as tx:
            tx.execute(
                f"UPDATE blocks SET header = {self.J}, block_hash = %s, block_uuid = %s, created_at = %s, restamps = restamps + 1 "
                "WHERE block_id = %s AND state = 'sealed' AND token IS NULL",
                (json.dumps(header), block_hash, header["block_uuid"], self._t(parse_rfc3339(header["created_at"])), block_id),
            )
            if tx.rowcount != 1:
                raise LedgerError(f"block {block_id} is anchored or missing and cannot be re-stamped")

    def block_records(self, block_id: int) -> list[dict]:
        with self.db.transaction() as tx:
            rows = tx.execute(f"SELECT {_RECORD_COLS} FROM records WHERE block_id = %s ORDER BY leaf_index", (block_id,))
        return [self._record_row(r) for r in rows]

    def blocks_awaiting_receipts(self, sources: tuple[str, ...]) -> list[int]:
        marks = ", ".join(["%s"] * len(sources))
        with self.db.transaction() as tx:
            rows = tx.execute(
                f"SELECT DISTINCT block_id FROM records WHERE status = 'anchored' AND source_type IN ({marks}) ORDER BY block_id",
                sources,
            )
        return [int(r[0]) for r in rows]

    def records_missing_receipts(self, block_id: int, sources: tuple[str, ...]) -> list[dict]:
        marks = ", ".join(["%s"] * len(sources))
        with self.db.transaction() as tx:
            rows = tx.execute(
                f"SELECT {', '.join('r.' + c.strip() for c in _RECORD_COLS.split(','))} FROM records r "
                f"LEFT JOIN receipts x ON x.record_id = r.record_id "
                f"WHERE r.block_id = %s AND r.source_type IN ({marks}) AND x.record_id IS NULL ORDER BY r.leaf_index",
                (block_id, *sources),
            )
        return [self._record_row(r) for r in rows]

    # -- webhook delivery -------------------------------------------------------------------

    def due_deliveries(self, now: datetime, limit: int = 100) -> list[dict]:
        not_gave_up = "NOT x.gave_up" if self.pg else "x.gave_up = 0"
        with self.db.transaction() as tx:
            rows = tx.execute(
                "SELECT x.record_id, x.receipt, x.created_at, x.delivery_attempts, c.webhook_url, c.webhook_secret, c.key_id "
                "FROM receipts x JOIN records r ON r.record_id = x.record_id JOIN api_clients c ON c.key_id = r.api_key_id "
                f"WHERE x.delivered_at IS NULL AND {not_gave_up} AND x.next_attempt_at <= %s AND c.webhook_url IS NOT NULL "
                "ORDER BY x.next_attempt_at LIMIT %s",
                (self._t(now), limit),
            )
        return [
            {"record_id": self._s(r[0]), "receipt": self._json(r[1]), "created_at": self._dt(r[2]), "attempts": int(r[3]),
             "url": r[4], "secret": r[5], "key_id": r[6]}
            for r in rows
        ]

    def mark_delivered(self, record_id: str, now: datetime) -> None:
        with self.db.transaction() as tx:
            tx.execute(
                "UPDATE receipts SET delivered_at = %s, delivery_attempts = delivery_attempts + 1, last_error = NULL WHERE record_id = %s",
                (self._t(now), record_id),
            )

    def mark_delivery_failed(self, record_id: str, error: str, next_attempt_at: datetime | None) -> None:
        """Record a failed attempt; ``next_attempt_at=None`` means give up."""
        with self.db.transaction() as tx:
            tx.execute(
                "UPDATE receipts SET delivery_attempts = delivery_attempts + 1, last_error = %s, next_attempt_at = %s, gave_up = %s "
                "WHERE record_id = %s",
                (error[:500], self._t(next_attempt_at), (next_attempt_at is None) if self.pg else int(next_attempt_at is None), record_id),
            )

    def delivery_status(self, record_id: str) -> dict | None:
        with self.db.transaction() as tx:
            r = tx.one(
                "SELECT delivered_at, delivery_attempts, last_error, next_attempt_at, gave_up FROM receipts WHERE record_id = %s",
                (record_id,),
            )
        if not r:
            return None
        return {"delivered_at": self._dt(r[0]), "attempts": int(r[1]), "last_error": r[2],
                "next_attempt_at": self._dt(r[3]), "gave_up": bool(r[4])}

    def get_receipt(self, record_id: str) -> dict | None:
        with self.db.transaction() as tx:
            r = tx.one("SELECT receipt FROM receipts WHERE record_id = %s", (record_id,))
        return self._json(r[0]) if r else None

    # -- API clients ------------------------------------------------------------------------

    def add_client(self, c: ApiClient, now: datetime) -> None:
        with self.db.transaction() as tx:
            tx.execute(
                "INSERT INTO api_clients (key_id, secret_hash, submitter_type, submitter_id, display_name, auth_method, "
                f"allowed_sources, allowed_classes, roles, webhook_url, active, created_at, webhook_secret) VALUES "
                f"(%s, %s, %s, %s, %s, %s, {self.J}, {self.J}, {self.J}, %s, %s, %s, %s)",
                (c.key_id, c.secret_hash, c.submitter_type, c.submitter_id, c.display_name, c.auth_method,
                 json.dumps(list(c.allowed_sources)), json.dumps(list(c.allowed_classes)) if c.allowed_classes is not None else None,
                 json.dumps(list(c.roles)), c.webhook_url, c.active if self.pg else int(c.active), self._t(now), c.webhook_secret),
            )

    _CLIENT_COLS = ("key_id, secret_hash, submitter_type, submitter_id, display_name, auth_method, allowed_sources, "
                    "allowed_classes, roles, webhook_url, active, webhook_secret")

    def _client_row(self, r) -> ApiClient:
        classes = self._json(r[7])
        return ApiClient(r[0], bytes(r[1]), r[2], r[3], r[4], r[5], tuple(self._json(r[6])),
                         tuple(classes) if classes is not None else None, tuple(self._json(r[8])), r[9], bool(r[10]), r[11])

    def get_client(self, key_id: str) -> ApiClient | None:
        with self.db.transaction() as tx:
            r = tx.one(f"SELECT {self._CLIENT_COLS} FROM api_clients WHERE key_id = %s", (key_id,))
        return self._client_row(r) if r else None

    def list_clients(self) -> list[ApiClient]:
        with self.db.transaction() as tx:
            rows = tx.execute(f"SELECT {self._CLIENT_COLS} FROM api_clients ORDER BY created_at")
        return [self._client_row(r) for r in rows]

    def revoke_client(self, key_id: str, now: datetime) -> bool:
        with self.db.transaction() as tx:
            tx.execute(
                "UPDATE api_clients SET active = %s, revoked_at = %s WHERE key_id = %s AND active = %s",
                (False if self.pg else 0, self._t(now), key_id, True if self.pg else 1),
            )
            return tx.rowcount == 1

    # -- index queue (consumed by the Phase 5 indexer) ---------------------------------

    def index_queue_size(self) -> int:
        with self.db.transaction() as tx:
            return int(tx.one("SELECT count(*) FROM index_queue")[0])


class _IngestContext:
    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self._cm = None

    def __enter__(self) -> "IngestTx":
        self._cm = self.ledger.db.transaction()
        tx = self._cm.__enter__()
        return IngestTx(self.ledger, tx)

    def __exit__(self, *exc):
        return self._cm.__exit__(*exc)


class IngestTx:
    """Operations inside one ingest transaction."""

    def __init__(self, ledger: Ledger, tx: Tx):
        self.l = ledger
        self.tx = tx
        self._interval: Interval | None = None

    def open_interval(self) -> Interval:
        """Share-lock the open interval. Retries while a seal is switching intervals."""
        if self._interval:
            return self._interval
        for _ in range(200):
            row = self.tx.one(f"SELECT interval_id, opened_at FROM intervals WHERE state = 'open'{self.l.FOR_SHARE}")
            if row:
                self._interval = Interval(row[0], self.l._dt(row[1]))
                return self._interval
            time.sleep(0.005)
        raise LedgerError("no open interval (run `polarys init-db`)")

    def get_dek(self, interval_id: str, record_class: str) -> tuple[str, str, bytes] | None:
        r = self.tx.one(
            "SELECT dek_id, kek_id, wrapped FROM data_keys WHERE interval_id = %s AND record_class = %s AND destroyed_at IS NULL",
            (interval_id, record_class),
        )
        return (r[0], r[1], bytes(r[2])) if r else None

    def insert_dek(self, interval_id: str, record_class: str, dek_id: str, kek_id: str, wrapped: bytes, now: datetime) -> bool:
        self.tx.execute(
            "INSERT INTO data_keys (interval_id, record_class, dek_id, kek_id, wrapped, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (interval_id, record_class, dek_id, kek_id, wrapped, self.l._t(now)),
        )
        return self.tx.rowcount == 1

    def find_idempotent(self, api_key_id: str, idempotency_key: str) -> dict | None:
        r = self.tx.one(
            f"SELECT {_RECORD_COLS} FROM records WHERE api_key_id = %s AND idempotency_key = %s",
            (api_key_id, idempotency_key),
        )
        return self.l._record_row(r) if r else None

    def insert_record(self, row: dict) -> int:
        l = self.l
        seq = self.tx.one(
            "INSERT INTO records (record_id, interval_id, received_at, source_type, submitter_type, submitter_id, record_class, "
            "retention_rule, retain_until, legal_hold, content_type, payload_sha256, payload_size, document_count, signing_key_id, "
            "signature, leaf_hash, object_key, object_state, api_key_id, idempotency_key, request_hash) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING ingest_seq",
            (row["record_id"], row["interval_id"], l._t(row["received_at"]), row["source_type"], row["submitter_type"],
             row["submitter_id"], row["record_class"], row["retention_rule"], l._t(row["retain_until"]),
             row["legal_hold"] if l.pg else int(row["legal_hold"]), row["content_type"], row["payload_sha256"],
             row["payload_size"], row["document_count"], row["signing_key_id"], row["signature"], row["leaf_hash"],
             row["object_key"], row["object_state"], row.get("api_key_id"), row.get("idempotency_key"), row.get("request_hash")),
        )[0]
        self.tx.execute(
            "INSERT INTO index_queue (ingest_seq, record_id, enqueued_at) VALUES (%s, %s, %s)",
            (seq, row["record_id"], l._t(row["received_at"])),
        )
        return int(seq)
