"""The ingest pipeline: from a validated submission to a durable, acknowledged record.

For each record, inside one ledger transaction that holds the open interval:

1. classify the record and resolve its retention
2. build and canonicalize the envelope, sign it (record key), compute the leaf hash
3. encrypt the signed record (and each document of a business submission) with the
   interval's data key for the record class
4. write the encrypted objects to the object store (or the local spool when it is down)
5. insert the ledger row and queue the record for indexing
6. after the transaction commits, return the acknowledgement

Records are processed in transactions of at most ``tx_batch`` (default 500).
A record is acknowledged only after its objects are durable and its ledger row has
committed.  If a transaction fails, none of its records are acknowledged; objects
already written for them are orphans that are never referenced (harmless).
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from . import cipher
from .classes import ClassRegistry, RetentionError
from .keys import KeyProvider, WrappedKey
from .ledger import IngestTx, Interval, Ledger
from .manifest import MANIFEST_CONTENT_TYPE, Document, build_manifest, manifest_payload
from .records import SignedRecord, Submitter, build_envelope, sign_record
from .sealing import interval_bounds
from .store import ObjectStore, Retention
from .store.spool import SpoolingStore
from .util import b64e, parse_rfc3339, rfc3339, utcnow, uuid7

RECEIPT_SOURCES = ("api", "upload")


class IngestError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message}


@dataclass
class Submission:
    source_type: str
    submitter: Submitter
    content_type: str = "application/octet-stream"
    payload: bytes | None = None
    documents: list[Document] | None = None
    title: str | None = None
    record_class: str | None = None
    attributes: dict = field(default_factory=dict)
    origin: dict = field(default_factory=dict)
    api_key_id: str | None = None
    idempotency_key: str | None = None
    request_hash: str | None = None


@dataclass
class Outcome:
    ack: dict | None = None
    error: IngestError | None = None
    replayed: bool = False

    @property
    def ok(self) -> bool:
        return self.ack is not None


class Ingestor:
    def __init__(
        self,
        ledger: Ledger,
        store: ObjectStore,
        provider: KeyProvider,
        registry: ClassRegistry | None = None,
        *,
        max_record_bytes: int = 1 << 20,
        max_submission_bytes: int = 50 << 20,
        tx_batch: int = 500,
        clock: Callable[[], datetime] = utcnow,
    ):
        self.ledger = ledger
        self.store = store
        self.provider = provider
        self.registry = registry or ClassRegistry()
        self.max_record_bytes = max_record_bytes
        self.max_submission_bytes = max_submission_bytes
        self.tx_batch = tx_batch
        self.clock = clock
        self._deks: dict[tuple[str, str], cipher.DataKey] = {}
        self._dek_lock = threading.Lock()

    # -- public ------------------------------------------------------------------------

    def submit(self, subs: list[Submission]) -> list[Outcome]:
        out: list[Outcome | None] = [None] * len(subs)
        ready: list[tuple[int, Submission, str]] = []
        for i, s in enumerate(subs):
            try:
                ready.append((i, s, self._validate(s)))
            except IngestError as e:
                out[i] = Outcome(error=e)
        for start in range(0, len(ready), self.tx_batch):
            chunk = ready[start : start + self.tx_batch]
            try:
                results = self._run_chunk(chunk)
            except IngestError as e:
                results = [Outcome(error=e)] * len(chunk)
            except Exception as e:  # ledger or store failure: nothing in this chunk is acknowledged
                err = IngestError(503, "ingest_unavailable", f"record was not stored ({type(e).__name__}: {e}); retry")
                results = [Outcome(error=err)] * len(chunk)
            for (i, _, _), res in zip(chunk, results):
                out[i] = res
        return out  # type: ignore[return-value]

    def submit_one(self, sub: Submission) -> Outcome:
        return self.submit([sub])[0]

    # -- validation ------------------------------------------------------------------

    def _validate(self, s: Submission) -> str:
        try:
            cls = self.registry.classify(s.source_type, s.record_class)
        except (RetentionError, KeyError) as e:
            raise IngestError(422, "invalid_record_class", str(e).strip("'\"")) from None
        if s.documents:
            if s.payload is not None:
                raise IngestError(422, "invalid_record", "send either a payload or documents, not both")
            total = sum(len(d.data) for d in s.documents)
            if total > self.max_submission_bytes:
                raise IngestError(413, "submission_too_large", f"documents total {total} bytes; limit is {self.max_submission_bytes}")
            if cls.id == "device_logs":
                raise IngestError(422, "invalid_record_class", "device logs cannot be document submissions")
        else:
            if s.payload is None:
                raise IngestError(422, "invalid_record", "a payload or at least one document is required")
            if len(s.payload) > self.max_record_bytes:
                raise IngestError(413, "record_too_large", f"payload is {len(s.payload)} bytes; limit is {self.max_record_bytes}")
        return cls.id

    # -- the transaction ---------------------------------------------------------------

    def _run_chunk(self, chunk: list[tuple[int, Submission, str]]) -> list[Outcome]:
        results: list[Outcome] = []
        new_deks: dict[tuple[str, str], cipher.DataKey] = {}
        with self.ledger.ingest() as itx:
            interval = itx.open_interval()
            for _, sub, class_id in chunk:
                results.append(self._one(itx, interval, sub, class_id, new_deks))
        # Cache new data keys only after their rows have committed.
        with self._dek_lock:
            for k in [k for k in self._deks if k[0] != interval.interval_id]:
                del self._deks[k]
            self._deks.update(new_deks)
        return results

    def _one(self, itx: IngestTx, interval: Interval, sub: Submission, class_id: str, new_deks: dict) -> Outcome:
        if sub.api_key_id and sub.idempotency_key:
            prior = itx.find_idempotent(sub.api_key_id, sub.idempotency_key)
            if prior:
                if prior["request_hash"] != sub.request_hash:
                    return Outcome(error=IngestError(409, "idempotency_conflict", "Idempotency-Key was already used for a different request"))
                return Outcome(ack=self.ack_from_row(prior), replayed=True)

        now = self.clock()
        cls = self.registry.get(class_id)
        retention = self.registry.resolve(cls, sub.attributes, now)
        manifest = None
        if sub.documents:
            manifest = build_manifest(sub.title or sub.documents[0].name, class_id, sub.documents)
            payload, content_type = manifest_payload(manifest), MANIFEST_CONTENT_TYPE
        else:
            payload, content_type = sub.payload, sub.content_type
        envelope = build_envelope(
            source_type=sub.source_type,
            submitter=sub.submitter,
            payload=payload,
            content_type=content_type,
            record_class=class_id,
            retention=retention,
            origin=sub.origin,
            received_at=now,
            record_id=uuid7(int(now.timestamp() * 1000)),
            attributes=sub.attributes or None,
        )
        signed = sign_record(envelope, self.provider)
        leaf = signed.leaf_hash
        rid = signed.record_id

        dek = self._dek(itx, interval.interval_id, class_id, now, new_deks)
        base = f"records/{interval.opened_at:%Y/%m/%d}/{interval.interval_id}/{rid}"
        retain_until = parse_rfc3339(retention["retain_until"]) if retention["retain_until"] else None
        lock = Retention.for_record(retain_until, retention["retention_rule"])

        objects = []
        obj = cipher.encrypt(dek, signed.plaintext(), cipher.record_aad(rid, leaf))
        obj.update(record_id=rid, leaf_hash=leaf.hex())
        objects.append((f"{base}.bin", json.dumps(obj).encode()))
        for i, doc in enumerate(sub.documents or []):
            dobj = cipher.encrypt(dek, doc.data, cipher.document_aad(rid, leaf, i))
            dobj.update(record_id=rid, leaf_hash=leaf.hex(), document_index=i)
            objects.append((f"{base}/{i}.bin", json.dumps(dobj).encode()))

        spooled = False
        for key, data in objects:
            if isinstance(self.store, SpoolingStore):
                spooled |= self.store.put_or_spool(key, data, "application/json", lock)
            else:
                self.store.put(key, data, "application/json", lock)

        row = {
            "record_id": rid,
            "interval_id": interval.interval_id,
            "received_at": now,
            "source_type": sub.source_type,
            "submitter_type": sub.submitter.type,
            "submitter_id": sub.submitter.id,
            "record_class": class_id,
            "retention_rule": retention["retention_rule"],
            "retain_until": retain_until,
            "legal_hold": False,
            "content_type": content_type,
            "payload_sha256": envelope["payload_sha256"],
            "payload_size": len(payload),
            "document_count": len(sub.documents or []),
            "signing_key_id": signed.key_id,
            "signature": signed.signature,
            "leaf_hash": leaf,
            "object_key": f"{base}.bin",
            "object_state": "spooled" if spooled else "stored",
            "api_key_id": sub.api_key_id,
            "idempotency_key": sub.idempotency_key,
            "request_hash": sub.request_hash,
            "status": "committed",
        }
        row["ingest_seq"] = itx.insert_record(row)
        ack = self.ack_from_row(row)
        if manifest:
            ack["manifest"] = manifest
        return Outcome(ack=ack)

    def _dek(self, itx: IngestTx, interval_id: str, class_id: str, now: datetime, new_deks: dict) -> cipher.DataKey:
        k = (interval_id, class_id)
        with self._dek_lock:
            if k in self._deks:
                return self._deks[k]
        if k in new_deks:
            return new_deks[k]
        row = itx.get_dek(interval_id, class_id)
        if row is None:
            dek = cipher.DataKey.generate(self.provider, interval_id, class_id)
            if itx.insert_dek(interval_id, class_id, dek.dek_id, dek.wrapped.kek_id, dek.wrapped.blob, now):
                new_deks[k] = dek
                return dek
            row = itx.get_dek(interval_id, class_id)  # another process created it first
        dek = cipher.DataKey.unwrap(self.provider, row[0], WrappedKey(row[1], row[2]))
        new_deks[k] = dek
        return dek

    # -- acknowledgements --------------------------------------------------------------------

    @staticmethod
    def ack_from_row(row: dict) -> dict:
        received = row["received_at"]
        return {
            "record_id": row["record_id"],
            "status": row.get("status", "committed"),
            "received_at": rfc3339(received),
            "source_type": row["source_type"],
            "submitter": {"type": row["submitter_type"], "id": row["submitter_id"]},
            "record_class": row["record_class"],
            "retention_rule": row["retention_rule"],
            "retain_until": rfc3339(row["retain_until"]) if row["retain_until"] else None,
            "payload_sha256": row["payload_sha256"],
            "document_count": row["document_count"],
            "leaf_hash": row["leaf_hash"].hex(),
            "signature": b64e(row["signature"]),
            "signing_key_id": row["signing_key_id"],
            "interval_id": row["interval_id"],
            "expected_seal_after": rfc3339(interval_bounds(received)[1]),
            "receipt_available": row["source_type"] in RECEIPT_SOURCES,
        }


class RecordReader:
    """Decrypts stored records and documents (for the sealer, receipts and audits)."""

    def __init__(self, ledger: Ledger, store: ObjectStore, provider: KeyProvider):
        self.ledger, self.store, self.provider = ledger, store, provider

    def _dek(self, interval_id: str, record_class: str) -> cipher.DataKey:
        row = self.ledger.get_dek_row(interval_id, record_class)
        if row is None:
            raise LookupError(f"data key for {interval_id}/{record_class} is missing or destroyed")
        return cipher.DataKey.unwrap(self.provider, row[0], WrappedKey(row[1], row[2]))

    def signed_record(self, row: dict) -> SignedRecord:
        obj = json.loads(self.store.get(row["object_key"]))
        dek = self._dek(row["interval_id"], row["record_class"])
        rec = SignedRecord.from_dict(json.loads(cipher.decrypt(dek, obj, cipher.record_aad(row["record_id"], row["leaf_hash"]))))
        if rec.leaf_hash != row["leaf_hash"] or rec.record_id != row["record_id"]:
            raise ValueError(f"stored object for {row['record_id']} does not match the ledger")
        return rec

    def document(self, row: dict, index: int) -> bytes:
        key = row["object_key"][: -len(".bin")] + f"/{index}.bin"
        obj = json.loads(self.store.get(key))
        dek = self._dek(row["interval_id"], row["record_class"])
        return cipher.decrypt(dek, obj, cipher.document_aad(row["record_id"], row["leaf_hash"], index))


def drain_spool(ledger: Ledger, store: ObjectStore) -> dict:
    """Upload spooled objects and mark records whose objects have all landed as ``stored``."""
    if not isinstance(store, SpoolingStore):
        return {"uploaded": 0, "pending": 0, "records_stored": 0}
    uploaded, pending = store.drain()
    marked = 0
    for row in ledger.spooled_records():
        base = row["object_key"][: -len(".bin")]
        if not any(k == row["object_key"] or k.startswith(base + "/") for k in pending):
            ledger.mark_stored(row["record_id"])
            marked += 1
    return {"uploaded": len(uploaded), "pending": len(pending), "records_stored": marked}


def request_hash(item: dict) -> str:
    from .jcs import canonicalize

    return hashlib.sha256(canonicalize(item)).hexdigest()


__all__ = ["Ingestor", "Submission", "Outcome", "IngestError", "RecordReader", "drain_spool", "request_hash"]
