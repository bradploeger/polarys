"""Sealing: turn one interval's signed records into a timestamped block.

This is the core algorithm the Phase 3 sealer service runs every 5 minutes.
Here it works on an in-memory interval and a directory laid out like the
object store, which is what the tests, the demo and ``logverify chain`` use:

    records/<yyyy>/<mm>/<dd>/<interval_id>/<record_id>.bin   encrypted signed record
    trees/<block_id>.bin                                      all Merkle tree levels
    blocks/<block_id>.json                                    block header
    tokens/<block_id>.tsr                                     RFC 3161 token (DER)
    keys/dek/<interval_id>/<record_class>.json                wrapped data key
    receipts/<record_id>.json                                 receipts (upload / API submitters only)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import cipher
from .blocks import GENESIS_PREV_HASH, block_hash, build_header, sign_header, summarize_submitters
from .keys import KeyProvider, WrappedKey
from .merkle import CompactRange, MerkleTree
from .receipts import build_receipt
from .records import SignedRecord
from .tsa import TimestampResult, TSAClient

INTERVAL = timedelta(minutes=5)
RECEIPT_SOURCES = ("upload", "api")


def interval_bounds(t: datetime) -> tuple[datetime, datetime]:
    """The 5-minute wall-clock window (UTC) containing ``t``."""
    t = t.astimezone(timezone.utc)
    start = t.replace(minute=t.minute - t.minute % 5, second=0, microsecond=0)
    return start, start + INTERVAL


def interval_id(start: datetime) -> str:
    return start.strftime("%Y%m%dT%H%MZ")


@dataclass
class OpenInterval:
    start: datetime
    end: datetime
    records: list[SignedRecord] = field(default_factory=list)
    compact: CompactRange = field(default_factory=CompactRange)

    @property
    def id(self) -> str:
        return interval_id(self.start)

    def add(self, record: SignedRecord) -> int:
        """Append a record; returns its sequence number (leaf index)."""
        self.records.append(record)
        self.compact.append(record.leaf_hash)
        return len(self.records) - 1


@dataclass
class SealedBlock:
    header: dict
    token: bytes
    tree: MerkleTree
    records: list[SignedRecord]
    timestamp: TimestampResult

    @property
    def block_id(self) -> int:
        return self.header["block_id"]

    @property
    def hash(self) -> bytes:
        return block_hash(self.header)


def seal(
    interval: OpenInterval,
    *,
    block_id: int,
    prev: SealedBlock | None,
    provider: KeyProvider,
    tsa: TSAClient,
    created_at: datetime | None = None,
) -> SealedBlock:
    if not interval.records:
        raise ValueError("empty intervals are not sealed")
    created_at = created_at or datetime.now(timezone.utc)
    tree = MerkleTree([r.leaf_hash for r in interval.records])
    if tree.root != interval.compact.root():
        raise RuntimeError("compact range and full tree disagree")  # never expected; guards memory corruption
    header = build_header(
        block_id=block_id,
        interval_start=interval.start,
        interval_end=interval.end,
        created_at=created_at,
        prev_block_hash=prev.hash.hex() if prev else GENESIS_PREV_HASH,
        prev_timestamp_token=prev.token if prev else None,
        merkle_root=tree.root,
        entry_count=tree.size,
        submitters=summarize_submitters([(i, r.envelope["submitter"]) for i, r in enumerate(interval.records)]),
    )
    header = sign_header(header, provider)
    ts = tsa.timestamp(block_hash(header), reference_time=created_at)
    return SealedBlock(header, ts.token, tree, list(interval.records), ts)


def receipts_for(block: SealedBlock, provider: KeyProvider) -> dict[str, dict]:
    out = {}
    for i, rec in enumerate(block.records):
        if rec.envelope["source_type"] in RECEIPT_SOURCES:
            out[rec.record_id] = build_receipt(rec, block.tree.proof(i), block.header, block.token, block.timestamp.tsa.name, provider)
    return out


class DirectoryStore:
    """Writes sealed blocks in the object-store layout (local filesystem backend)."""

    def __init__(self, root: str | Path, provider: KeyProvider):
        self.root = Path(root)
        self.provider = provider

    def _write(self, rel: str, data: bytes) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(p)
        return p

    def write_block(self, block: SealedBlock, interval: OpenInterval) -> None:
        deks: dict[str, cipher.DataKey] = {}
        for rec in block.records:
            cls = rec.envelope["record_class"]
            if cls not in deks:
                deks[cls] = cipher.DataKey.generate(self.provider, interval.id, cls)
                self._write(f"keys/dek/{interval.id}/{cls}.json", json.dumps(deks[cls].wrapped_document(), indent=2).encode())
            obj = cipher.encrypt(deks[cls], rec.plaintext(), cipher.record_aad(rec.record_id, rec.leaf_hash))
            obj.update(record_id=rec.record_id, leaf_hash=rec.leaf_hash.hex(), block_id=block.block_id)
            day = interval.start.strftime("%Y/%m/%d")
            self._write(f"records/{day}/{interval.id}/{rec.record_id}.bin", json.dumps(obj).encode())
        self._write(f"trees/{block.block_id}.bin", block.tree.to_bytes())
        self._write(f"tokens/{block.block_id}.tsr", block.token)
        self._write(f"blocks/{block.block_id}.json", json.dumps(block.header, indent=2).encode())

    def write_receipts(self, receipts: dict[str, dict]) -> None:
        for rid, r in receipts.items():
            self._write(f"receipts/{rid}.json", json.dumps(r, indent=2).encode())

    def read_record(self, path: str | Path) -> SignedRecord:
        """Decrypt one stored record; the AAD check binds it to its record_id and leaf hash."""
        p = Path(path)
        obj = json.loads(p.read_text())
        interval_dir = p.parent.name
        cls_id = obj["dek_id"].split("/", 1)[1]
        wrapped = json.loads((self.root / f"keys/dek/{interval_dir}/{cls_id}.json").read_text())
        dek = cipher.DataKey.unwrap(self.provider, wrapped["dek_id"], WrappedKey.from_dict(wrapped))
        leaf = bytes.fromhex(obj["leaf_hash"])
        pt = cipher.decrypt(dek, obj, cipher.record_aad(obj["record_id"], leaf))
        rec = SignedRecord.from_dict(json.loads(pt))
        if rec.record_id != obj["record_id"] or rec.leaf_hash != leaf:
            raise ValueError("stored record does not match its record_id / leaf hash binding")
        return rec
