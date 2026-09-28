"""Ingest pipeline and ledger, run against every available backend (SQLite, PostgreSQL)."""

import json
import tempfile
import threading
import time
import unittest
from datetime import timedelta

import httpx

from polarys import cipher
from polarys.classes import ClassRegistry
from polarys.ingest import Ingestor, RecordReader, Submission, drain_spool
from polarys.manifest import MANIFEST_CONTENT_TYPE, Document
from polarys.receipts import verify_receipt
from polarys.records import Submitter
from polarys.sealing import OpenInterval, receipts_for, seal
from polarys.store import StoreError, StoreUnavailable
from polarys.store.local import LocalFSStore
from polarys.store.spool import SpoolingStore
from polarys.util import utcnow

from backends import backend_names, fresh_ledger
from helpers import Clock, dev_tsa, provider

ALICE = Submitter("user", "alice@example.com", "api-key", "Alice")
FW = Submitter("device", "fw01.example.com", "api-key")


def sub(i=0, **kw):
    base = dict(source_type="api", submitter=ALICE, content_type="application/json",
                payload=json.dumps({"n": i}).encode(), record_class="correspondence", api_key_id="k1")
    base.update(kw)
    return Submission(**base)


class Flaky(LocalFSStore):
    mode = None  # None | "unavailable" | "broken"

    def put(self, key, data, content_type="application/octet-stream", retention=None):
        if self.mode == "unavailable":
            raise StoreUnavailable("primary down")
        if self.mode == "broken":
            raise StoreError("access denied")
        super().put(key, data, content_type, retention)


class IngestContract:
    """Mixed into one TestCase per backend."""

    backend = "sqlite"

    def setUp(self):
        self._ctx = fresh_ledger(self.backend)
        self.ledger = self._ctx.__enter__()
        self.primary = Flaky(tempfile.mkdtemp())
        self.store = SpoolingStore(self.primary, tempfile.mkdtemp())
        self.ing = Ingestor(self.ledger, self.store, provider(), tx_batch=500)
        self.reader = RecordReader(self.ledger, self.store, provider())

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    # -- basics --------------------------------------------------------------------------

    def test_single_record_is_signed_encrypted_and_recorded(self):
        out = self.ing.submit_one(sub(1))
        self.assertTrue(out.ok, out.error and out.error.message)
        ack = out.ack
        row = self.ledger.get_record(ack["record_id"])
        self.assertEqual(row["leaf_hash"].hex(), ack["leaf_hash"])
        self.assertEqual((row["status"], row["object_state"]), ("committed", "stored"))
        rec = self.reader.signed_record(row)
        self.assertEqual(rec.payload, b'{"n": 1}')
        self.assertEqual(rec.envelope["submitter"]["id"], "alice@example.com")
        self.assertEqual(rec.envelope["origin"], {})
        raw = self.primary.get(row["object_key"])
        self.assertNotIn(b'"n"', raw)  # ciphertext only
        self.assertEqual(self.ledger.index_queue_size(), 1)
        self.assertTrue(ack["receipt_available"])

    def test_device_logs_retention_and_no_receipt(self):
        acks = [o.ack for o in self.ing.submit([
            sub(source_type="windows_event", submitter=FW, record_class=None, attributes={"security": True}),
            sub(source_type="windows_event", submitter=FW, record_class=None, attributes={"severity": 6}),
        ])]
        self.assertEqual([a["retention_rule"] for a in acks], ["P7Y", "P90D"])
        self.assertFalse(acks[0]["receipt_available"])

    def test_validation_errors_do_not_block_others(self):
        docs = [Document("x.log", "text/plain", b"x")]
        outs = self.ing.submit([sub(record_class="nope"), sub(1), sub(payload=b"x" * (2 << 20)),
                                sub(payload=None, documents=docs, record_class="device_logs"), sub(payload=None)])
        self.assertEqual([o.ok for o in outs], [False, True, False, False, False])
        self.assertEqual([o.error.code for o in outs if o.error],
                         ["invalid_record_class", "record_too_large", "invalid_record_class", "invalid_record"])

    # -- business documents ----------------------------------------------------------

    def test_document_submission_is_one_record(self):
        docs = [Document("return.pdf", "application/pdf", b"%PDF return"), Document("sched.pdf", "application/pdf", b"%PDF sched")]
        out = self.ing.submit_one(Submission(source_type="api", submitter=ALICE, documents=docs, title="2025 return",
                                             record_class="expense_docs"))
        self.assertTrue(out.ok, out.error and out.error.message)
        self.assertEqual(out.ack["document_count"], 2)
        self.assertEqual(out.ack["manifest"]["documents"][1]["name"], "sched.pdf")
        row = self.ledger.get_record(out.ack["record_id"])
        self.assertEqual(row["content_type"], MANIFEST_CONTENT_TYPE)
        self.assertEqual([self.reader.document(row, i) for i in range(2)], [b"%PDF return", b"%PDF sched"])
        # Swapping the two encrypted documents is detected: each is bound to its position.
        base = row["object_key"][:-4]
        d0, d1 = self.primary.get(f"{base}/0.bin"), self.primary.get(f"{base}/1.bin")
        dek = self.reader._dek(row["interval_id"], row["record_class"])
        with self.assertRaises(Exception):
            cipher.decrypt(dek, json.loads(d1), cipher.document_aad(row["record_id"], row["leaf_hash"], 0))
        self.assertEqual(cipher.decrypt(dek, json.loads(d0), cipher.document_aad(row["record_id"], row["leaf_hash"], 0)), b"%PDF return")

    # -- idempotency --------------------------------------------------------------------

    def test_idempotency(self):
        first = self.ing.submit_one(sub(1, idempotency_key="abc", request_hash="h1"))
        again = self.ing.submit_one(sub(1, idempotency_key="abc", request_hash="h1"))
        self.assertTrue(again.replayed)
        self.assertEqual(again.ack["record_id"], first.ack["record_id"])
        self.assertEqual(again.ack["signature"], first.ack["signature"])
        clash = self.ing.submit_one(sub(2, idempotency_key="abc", request_hash="h2"))
        self.assertEqual(clash.error.status, 409)
        other_client = self.ing.submit_one(sub(1, idempotency_key="abc", request_hash="h1", api_key_id="k2"))
        self.assertFalse(other_client.replayed)
        self.assertEqual(self.ledger.count_records(), 2)

    # -- transactions and data keys ---------------------------------------------------

    def test_batches_are_split_into_transactions(self):
        self.ing.tx_batch = 250
        outs = self.ing.submit([sub(i) for i in range(600)])
        self.assertTrue(all(o.ok for o in outs))
        iid = outs[0].ack["interval_id"]
        rows = self.ledger.interval_records(iid)
        self.assertEqual(len(rows), 600)
        self.assertEqual([json.loads(self.reader.signed_record(r).payload)["n"] for r in rows[:3]], [0, 1, 2])

    def test_one_data_key_per_interval_and_class(self):
        self.ing.submit([sub(1), sub(2, record_class="payroll"), sub(3)])
        iv = self.ledger.ensure_open_interval(utcnow())
        self.assertIsNotNone(self.ledger.get_dek_row(iv.interval_id, "correspondence"))
        self.assertIsNotNone(self.ledger.get_dek_row(iv.interval_id, "payroll"))
        self.assertIsNone(self.ledger.get_dek_row(iv.interval_id, "legal"))
        closed = self.ledger.freeze_open_interval(utcnow())
        self.assertEqual(closed.record_count, 3)
        out = self.ing.submit_one(sub(4))
        self.assertNotEqual(out.ack["interval_id"], closed.interval_id)
        row = self.ledger.get_record(out.ack["record_id"])
        self.assertEqual(json.loads(self.reader.signed_record(row).payload), {"n": 4})

    def test_rolled_back_data_key_is_never_used(self):
        """A key created in a failed transaction must not be cached and reused for later records."""
        self.primary.mode = "broken"  # not spoolable: the whole transaction fails after the DEK insert
        out = self.ing.submit_one(sub(1, record_class="legal"))
        self.assertEqual(out.error.status, 503)
        self.assertEqual(self.ledger.count_records(), 0)
        self.primary.mode = None
        out = self.ing.submit_one(sub(2, record_class="legal"))
        row = self.ledger.get_record(out.ack["record_id"])
        self.assertEqual(json.loads(self.reader.signed_record(row).payload), {"n": 2})

    # -- spooling ---------------------------------------------------------------------------

    def test_store_outage_spools_then_drains(self):
        self.primary.mode = "unavailable"
        docs = [Document("a.pdf", "application/pdf", b"A"), Document("b.pdf", "application/pdf", b"B")]
        outs = self.ing.submit([sub(1), Submission(source_type="api", submitter=ALICE, documents=docs, record_class="insurance")])
        self.assertTrue(all(o.ok for o in outs))
        self.assertEqual({r["object_state"] for r in self.ledger.spooled_records()}, {"spooled"})
        self.assertEqual(len(self.store.pending()), 4)
        self.assertEqual(drain_spool(self.ledger, self.store)["pending"], 4)  # still down
        self.primary.mode = None
        self.assertEqual(drain_spool(self.ledger, self.store), {"uploaded": 4, "pending": 0, "records_stored": 2})
        self.assertEqual(self.ledger.spooled_records(), [])
        row = self.ledger.get_record(outs[1].ack["record_id"])
        self.assertEqual(self.reader.document(row, 1), b"B")

    # -- interval hand-off under load -----------------------------------------------------

    def test_freeze_during_concurrent_ingest_loses_nothing(self):
        stop = threading.Event()
        acked: list[tuple[str, str]] = []
        lock = threading.Lock()

        def worker(n):
            i = 0
            while not stop.is_set():
                o = self.ing.submit_one(sub(n * 100000 + i))
                if o.ok:
                    with lock:
                        acked.append((o.ack["record_id"], o.ack["interval_id"]))
                i += 1

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
        for t in threads:
            t.start()
        closed = []
        for _ in range(5):
            time.sleep(0.15)
            iv = self.ledger.freeze_open_interval(utcnow())
            if iv:
                # Once frozen, the interval's membership must never change.
                closed.append((iv, len(self.ledger.interval_records(iv.interval_id))))
        stop.set()
        for t in threads:
            t.join()
        time.sleep(0.05)
        self.assertGreater(len(acked), 50)
        for iv, count_at_freeze in closed:
            self.assertEqual(iv.record_count, count_at_freeze)
            self.assertEqual(len(self.ledger.interval_records(iv.interval_id)), count_at_freeze)
        for rid, iid in acked:
            self.assertEqual(self.ledger.get_record(rid)["interval_id"], iid)
        self.assertEqual(self.ledger.count_records(), len(acked))

    # -- blocks and receipts (the Phase 3 path) -------------------------------------------

    def test_ledger_records_seal_into_verifiable_receipts(self):
        outs = self.ing.submit([sub(i) for i in range(5)] + [sub(9, source_type="windows_event", submitter=FW, record_class=None)])
        iv = self.ledger.freeze_open_interval(utcnow())
        rows = self.ledger.interval_records(iv.interval_id)
        oi = OpenInterval(iv.opened_at, iv.closed_at)
        for r in rows:
            oi.add(self.reader.signed_record(r))
        clock = Clock(utcnow() + timedelta(seconds=1))
        dev, client = dev_tsa(clock)
        block = seal(oi, block_id=0, prev=None, provider=provider(), tsa=client, created_at=clock.t)
        self.ledger.store_block(block.header, block.hash, iv.interval_id, [(r["record_id"], i) for i, r in enumerate(rows)],
                                block.token, block.timestamp.tsa.name, block.timestamp.info.gen_time)
        for rid, receipt in receipts_for(block, provider()).items():
            self.ledger.store_receipt(rid, 0, receipt, utcnow())
        self.assertEqual(self.ledger.latest_block()["block_id"], 0)
        first = outs[0].ack["record_id"]
        self.assertEqual(self.ledger.get_record(first)["status"], "receipted")
        self.assertEqual(self.ledger.get_record(outs[5].ack["record_id"])["status"], "anchored")
        self.assertIsNone(self.ledger.get_receipt(outs[5].ack["record_id"]))
        rep = verify_receipt(self.ledger.get_receipt(first), provider().keyring(), [dev.ca_cert])
        self.assertTrue(rep.ok, rep.to_dict())


class SQLiteIngest(IngestContract, unittest.TestCase):
    backend = "sqlite"


if "postgres" in backend_names():

    class PostgresIngest(IngestContract, unittest.TestCase):
        backend = "postgres"


if __name__ == "__main__":
    unittest.main()
