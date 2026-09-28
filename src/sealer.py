"""The sealer: turns each closed interval into a signed, hash-chained, timestamped block.

One cycle (``Sealer.run_cycle``), normally at each 5-minute wall-clock boundary:

1. **Finish unanchored blocks.** A block without a timestamp token is anchored first.
   If every TSA fails, the cycle stops here: no new interval is closed, so the open
   interval keeps growing and no record is lost or delayed beyond the outage.
2. **Finish closed intervals** that have no block yet (a crash after the close).
3. **Issue missing receipts** for anchored blocks (a crash after anchoring).
4. **Close the open interval.** An empty interval is marked empty and skipped.
5. **Build the block** from the ledger's leaf hashes (no decryption needed): Merkle
   tree, header with the previous block's hash and token, sealer signature. Persist
   it, and the record-to-leaf assignment, in one transaction.
6. **Anchor** it: RFC 3161 token over the block hash, TSAs tried in the configured
   order. The token's genTime must be within ``max_clock_skew`` of local time or the
   token is refused (the local clock would make ``created_at`` untrustworthy).
7. **Write** ``trees/<id>.bin``, ``blocks/<id>.json`` and ``tokens/<id>.tsr`` to the
   object store, and **issue receipts** for API and upload records.

Every step is idempotent, so a crash at any point is repaired by the next cycle.

Re-stamping: if a block waited more than ``restamp_after`` for its token (a TSA
outage), its header is re-issued with a fresh ``created_at`` and signature before
the next attempt.  Nothing can reference an unanchored block (the next block
needs its token), so this is safe, and it keeps genTime close to ``created_at``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .blocks import GENESIS_PREV_HASH, block_hash, build_header, sign_header, summarize_submitters
from .ingest import RECEIPT_SOURCES, RecordReader
from .keys import KeyProvider
from .ledger import Interval, Ledger
from .merkle import MerkleTree
from .receipts import build_receipt
from .store import ObjectExists, ObjectStore
from .tsa import AllTSAsFailed, TSAClient
from .util import parse_rfc3339, rfc3339, utcnow, uuid7

log = logging.getLogger("polarys.sealer")


class SealerError(Exception):
    pass


class ClockSkewError(SealerError):
    pass


@dataclass
class CycleReport:
    started_at: str
    closed_interval: str | None = None
    empty_interval: bool = False
    sealed: list[int] = field(default_factory=list)
    anchored: list[int] = field(default_factory=list)
    restamped: list[int] = field(default_factory=list)
    receipts: int = 0
    freeze_skipped: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def put_idempotent(store: ObjectStore, key: str, data: bytes, content_type: str) -> bytes:
    """Write ``data``; if the key exists, return the existing bytes (the canonical copy)."""
    try:
        store.put(key, data, content_type)
        return data
    except ObjectExists:
        return store.get(key)


class Sealer:
    def __init__(
        self,
        ledger: Ledger,
        store: ObjectStore,
        provider: KeyProvider,
        tsa: TSAClient,
        reader: RecordReader,
        *,
        clock=utcnow,
        restamp_after: timedelta = timedelta(minutes=2),
        max_clock_skew: timedelta = timedelta(seconds=60),
        receipt_batch: int = 500,
    ):
        self.ledger, self.store, self.provider, self.tsa, self.reader = ledger, store, provider, tsa, reader
        self.clock = clock
        self.restamp_after = restamp_after
        self.max_clock_skew = max_clock_skew
        self.receipt_batch = receipt_batch

    # -- the cycle -------------------------------------------------------------------------

    def run_cycle(self, freeze: bool = True) -> CycleReport:
        rep = CycleReport(started_at=rfc3339(self.clock()))

        for b in self.ledger.blocks_in_state("sealed"):
            if not self._anchor(b, rep):
                rep.freeze_skipped = f"block {b['block_id']} is not anchored yet"
                self._receipts_backlog(rep)
                return rep

        for iv in self.ledger.sealing_intervals():  # closed by an earlier, interrupted cycle
            b = self._build(iv, rep)
            if not self._anchor(b, rep):
                rep.freeze_skipped = f"block {b['block_id']} is not anchored yet"
                return rep

        self._receipts_backlog(rep)

        if freeze:
            iv = self.ledger.freeze_open_interval(self.clock())
            if iv is None:
                rep.empty_interval = True
            else:
                rep.closed_interval = iv.interval_id
                b = self._build(iv, rep)
                if self._anchor(b, rep):
                    self._receipts(b["block_id"], rep)
        return rep

    # -- steps -----------------------------------------------------------------------------

    def _build(self, iv: Interval, rep: CycleReport) -> dict:
        rows = self.ledger.interval_records(iv.interval_id)
        if not rows:
            raise SealerError(f"interval {iv.interval_id} is sealing but has no records")
        prev = self.ledger.latest_block()
        if prev is not None and prev["state"] != "anchored":
            raise SealerError(f"block {prev['block_id']} must be anchored before the next block is built")
        block_id = 0 if prev is None else prev["block_id"] + 1
        tree = MerkleTree([r["leaf_hash"] for r in rows])
        now = self.clock()
        header = build_header(
            block_id=block_id,
            interval_start=iv.opened_at,
            interval_end=iv.closed_at or now,
            created_at=now,
            prev_block_hash=prev["block_hash"].hex() if prev else GENESIS_PREV_HASH,
            prev_timestamp_token=prev["token"] if prev else None,
            merkle_root=tree.root,
            entry_count=tree.size,
            submitters=summarize_submitters([(i, {"type": r["submitter_type"], "id": r["submitter_id"]}) for i, r in enumerate(rows)]),
        )
        header = sign_header(header, self.provider)
        bh = block_hash(header)
        self.ledger.store_block(header, bh, iv.interval_id, [(r["record_id"], i) for i, r in enumerate(rows)])
        put_idempotent(self.store, f"trees/{block_id}.bin", tree.to_bytes(), "application/octet-stream")
        rep.sealed.append(block_id)
        log.info("sealed block %s: %s records, root %s", block_id, tree.size, tree.root.hex())
        return {"block_id": block_id, "header": header, "block_hash": bh, "state": "sealed", "token": None}

    def _anchor(self, b: dict, rep: CycleReport) -> bool:
        header = b["header"]
        now = self.clock()
        if now - parse_rfc3339(header["created_at"]) > self.restamp_after:
            header = self._restamp(header, now)
            rep.restamped.append(b["block_id"])
        bh = block_hash(header)
        try:
            ts = self.tsa.timestamp(bh)
        except AllTSAsFailed as e:
            rep.errors.append(f"block {b['block_id']}: {e}")
            log.warning("could not anchor block %s: %s", b["block_id"], e)
            return False
        skew = abs(ts.info.gen_time - self.clock())
        if skew > self.max_clock_skew:
            msg = (f"local clock differs from {ts.tsa.name} genTime by {skew.total_seconds():.0f}s "
                   f"(limit {self.max_clock_skew.total_seconds():.0f}s); block {b['block_id']} not anchored")
            rep.errors.append(msg)
            log.error(msg)
            return False
        self.ledger.anchor_block(b["block_id"], ts.token, ts.tsa.name, ts.info.gen_time)
        put_idempotent(self.store, f"blocks/{b['block_id']}.json", json.dumps(header, indent=2).encode(), "application/json")
        put_idempotent(self.store, f"tokens/{b['block_id']}.tsr", ts.token, "application/timestamp-reply")
        rep.anchored.append(b["block_id"])
        log.info("anchored block %s with %s at %s", b["block_id"], ts.tsa.name, ts.info.gen_time.isoformat())
        return True

    def _restamp(self, header: dict, now: datetime) -> dict:
        fresh = {k: v for k, v in header.items() if k not in ("sealer_signature", "signing_key_id")}
        fresh["created_at"] = rfc3339(now)
        fresh["block_uuid"] = uuid7(int(now.timestamp() * 1000))
        fresh = sign_header(fresh, self.provider)
        self.ledger.restamp_block(header["block_id"], fresh, block_hash(fresh))
        log.info("re-stamped block %s (waited since %s)", header["block_id"], header["created_at"])
        return fresh

    def _receipts_backlog(self, rep: CycleReport) -> None:
        for block_id in self.ledger.blocks_awaiting_receipts(RECEIPT_SOURCES):
            self._receipts(block_id, rep)

    def _receipts(self, block_id: int, rep: CycleReport) -> None:
        missing = self.ledger.records_missing_receipts(block_id, RECEIPT_SOURCES)
        if not missing:
            return
        block = self.ledger.get_block(block_id)
        tree = MerkleTree([r["leaf_hash"] for r in self.ledger.block_records(block_id)])
        if tree.root.hex() != block["header"]["merkle_root"]:
            raise SealerError(f"ledger leaves for block {block_id} do not match its Merkle root")
        batch: list[tuple[str, int, dict]] = []
        for row in missing:
            try:
                record = self.reader.signed_record(row)
                receipt = build_receipt(record, tree.proof(row["leaf_index"]), block["header"], block["token"],
                                        block["tsa_name"], self.provider)
                stored = put_idempotent(self.store, f"receipts/{row['record_id']}.json",
                                        json.dumps(receipt, indent=2).encode(), "application/json")
                batch.append((row["record_id"], block_id, json.loads(stored)))
            except Exception as e:  # one unreadable record must not hold back the others
                rep.errors.append(f"receipt for {row['record_id']}: {type(e).__name__}: {e}")
                log.error("receipt for %s failed: %s", row["record_id"], e)
            if len(batch) >= self.receipt_batch:
                rep.receipts += self.ledger.store_receipts(batch, self.clock())
                batch = []
        if batch:
            rep.receipts += self.ledger.store_receipts(batch, self.clock())
