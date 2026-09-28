"""Phase 3: sealer, anchoring, recovery, leader election and webhook delivery, on every backend."""

import json
import tempfile
import threading
import unittest
from datetime import timedelta

import httpx
from click.testing import CliRunner

from polarys.blocks import block_hash
from polarys.cli import main as logverify
from polarys.delivery import Deliverer, verify_signature
from polarys.devtsa import DevTSA
from polarys.ingest import Ingestor, RecordReader, Submission
from polarys.leader import LeaderLock
from polarys.ledger import ApiClient
from polarys.receipts import verify_receipt
from polarys.records import Submitter
from polarys.sealer import Sealer
from polarys.service import SealerService, verify_ledger_chain
from polarys.store.local import LocalFSStore
from polarys.tsa import TSAClient, TSAEndpoint
from polarys.util import parse_rfc3339, utcnow

from backends import backend_names, fresh_ledger
from helpers import Clock, provider

ALICE = Submitter("user", "alice@example.com", "api-key")
DC = Submitter("device", "dc01.corp.example.com", "api-key")


class TSAFarm:
    """Two development TSAs behind switchable failures, sharing the test clock."""

    def __init__(self, clock):
        self.primary = DevTSA.create("Primary TSA", clock=clock)
        self.backup = DevTSA.create("Backup TSA", clock=clock)
        self.down = {"primary": False, "backup": False}
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        name = request.url.host.split(".")[0]
        self.requests.append(name)
        if self.down[name]:
            return httpx.Response(503)
        return httpx.Response(200, content=(self.primary if name == "primary" else self.backup).respond(request.content))

    def client(self) -> TSAClient:
        return TSAClient([TSAEndpoint("Primary", "http://primary.tsa/"), TSAEndpoint("Backup", "http://backup.tsa/")],
                         http=httpx.Client(transport=httpx.MockTransport(self.handler)), retry_delay=0)

    @property
    def roots(self):
        return [self.primary.ca_cert, self.backup.ca_cert]


class SealerContract:
    backend = "sqlite"

    def setUp(self):
        self._ctx = fresh_ledger(self.backend)
        self.ledger = self._ctx.__enter__()
        self.clock = Clock(utcnow().replace(microsecond=0))
        self.store = LocalFSStore(tempfile.mkdtemp())
        self.ing = Ingestor(self.ledger, self.store, provider(), clock=self.clock)
        self.reader = RecordReader(self.ledger, self.store, provider())
        self.tsa = TSAFarm(self.clock)
        self.sealer = self.make_sealer()

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def make_sealer(self, tsa_client=None):
        return Sealer(self.ledger, self.store, provider(), tsa_client or self.tsa.client(), self.reader, clock=self.clock)

    def ingest(self, n_api=3, n_dev=1):
        subs = [Submission("api", ALICE, "text/plain", f"api {i}".encode(), record_class="correspondence", api_key_id="k-alice")
                for i in range(n_api)]
        subs += [Submission("windows_event", DC, "text/plain", f"evt {i}".encode()) for i in range(n_dev)]
        outs = self.ing.submit(subs)
        assert all(o.ok for o in outs), [o.error and o.error.message for o in outs]
        return [o.ack["record_id"] for o in outs]

    def tick(self, minutes=5):
        self.clock.t += timedelta(minutes=minutes)

    def assert_chain_valid(self, expected_blocks):
        res = verify_ledger_chain(self.ledger, provider().keyring(), self.tsa.roots)
        self.assertTrue(res.ok, res.to_dict())
        self.assertEqual(res.checked, expected_blocks)
        self.assertEqual(res.unanchored, [])
        # The object store alone is enough for Phase 1's offline verifier.
        (self.store.root / "keys.json").write_text(json.dumps(provider().keyring().to_document()))
        (self.store.root / "roots.pem").write_bytes(self.tsa.primary.ca_pem() + self.tsa.backup.ca_pem())
        r = CliRunner().invoke(logverify, ["chain", str(self.store.root), "--keys", str(self.store.root / "keys.json"),
                                           "--tsa-ca", str(self.store.root / "roots.pem")])
        self.assertEqual(r.exit_code, 0, r.output)
        self.assertIn(f"VALID: {expected_blocks} block(s)", r.output)

    # -- normal operation ---------------------------------------------------------------

    def test_blocks_receipts_and_statuses(self):
        batches = []
        for _ in range(3):
            batches.append(self.ingest())
            self.tick()
            rep = self.sealer.run_cycle()
            self.assertEqual((rep.errors, rep.receipts, rep.freeze_skipped), ([], 3, None))
        self.assert_chain_valid(3)
        for b, ids in enumerate(batches):
            recs = [self.ledger.get_record(i) for i in ids]
            self.assertEqual([r["block_id"] for r in recs], [b] * 4)
            self.assertEqual([r["status"] for r in recs], ["receipted"] * 3 + ["anchored"])
            self.assertIsNone(self.ledger.get_receipt(ids[3]))
            rec = self.ledger.get_receipt(ids[0])
            self.assertTrue(verify_receipt(rec, provider().keyring(), self.tsa.roots).ok)
            self.assertEqual(json.loads(self.store.get(f"receipts/{ids[0]}.json")), rec)
        head = self.ledger.latest_block()
        self.assertEqual(head["header"]["submitters"], [
            {"type": "user", "id": "alice@example.com", "record_count": 3, "first_seq": 0, "last_seq": 2},
            {"type": "device", "id": "dc01.corp.example.com", "record_count": 1, "first_seq": 3, "last_seq": 3},
        ])
        self.assertEqual(head["tsa_name"], "Primary")

    def test_empty_intervals_make_no_block(self):
        self.tick()
        rep = self.sealer.run_cycle()
        self.assertTrue(rep.empty_interval)
        self.assertIsNone(self.ledger.latest_block())
        self.ingest()
        self.tick()
        self.sealer.run_cycle()
        self.tick()
        self.assertTrue(self.sealer.run_cycle().empty_interval)
        self.ingest(1, 0)
        self.tick()
        self.sealer.run_cycle()
        self.assert_chain_valid(2)

    # -- TSA failures ---------------------------------------------------------------------

    def test_failover_to_second_tsa(self):
        self.tsa.down["primary"] = True
        self.ingest()
        self.tick()
        rep = self.sealer.run_cycle()
        self.assertEqual(rep.anchored, [0])
        self.assertEqual(self.ledger.latest_block()["tsa_name"], "Backup")
        self.assertEqual(self.tsa.requests, ["primary", "primary", "backup"])
        self.assert_chain_valid(1)

    def test_outage_extends_interval_restamps_then_recovers(self):
        first = self.ingest()
        self.tick()
        self.tsa.down.update(primary=True, backup=True)
        rep = self.sealer.run_cycle()
        self.assertEqual((rep.sealed, rep.anchored), ([0], []))
        self.assertTrue(rep.errors)
        self.assertEqual(self.ledger.get_record(first[0])["status"], "sealed")

        later = []
        for _ in range(3):  # 15 minutes of outage: records keep arriving, nothing else is closed
            later += self.ingest(2, 1)
            self.tick()
            rep = self.sealer.run_cycle()
            self.assertEqual(rep.freeze_skipped, "block 0 is not anchored yet")
            self.assertEqual(rep.sealed, [])
        open_iv = self.ledger.ensure_open_interval(self.clock())
        self.assertEqual({self.ledger.get_record(r)["interval_id"] for r in later}, {open_iv.interval_id})

        self.tsa.down.update(primary=False, backup=False)
        self.tick()
        rep = self.sealer.run_cycle()
        self.assertEqual((rep.restamped, rep.anchored, rep.sealed), ([0], [0, 1], [1]))
        b0 = self.ledger.get_block(0)
        self.assertEqual(b0["restamps"], 4)  # before each attempt once the header was more than 2 minutes old
        self.assertLess(abs(b0["gen_time"] - parse_rfc3339(b0["header"]["created_at"])), timedelta(seconds=5))
        self.assertEqual(self.ledger.get_block(1)["header"]["entry_count"], 9)
        self.assert_chain_valid(2)
        for rid in first + later:
            self.assertEqual(self.ledger.get_record(rid)["status"] in ("anchored", "receipted"), True)

    def test_clock_skew_refuses_token(self):
        skewed = Clock(self.clock.t + timedelta(minutes=3))
        bad = DevTSA.create("Skewed TSA", clock=skewed)
        client = TSAClient([bad.endpoint()], http=httpx.Client(transport=bad.transport()), retry_delay=0)
        self.ingest()
        self.tick()
        skewed.t = self.clock.t + timedelta(minutes=3)
        rep = self.make_sealer(client).run_cycle()
        self.assertEqual(rep.anchored, [])
        self.assertIn("local clock differs", rep.errors[0])
        self.assertEqual(self.ledger.get_block(0)["state"], "sealed")
        rep = self.sealer.run_cycle(freeze=False)  # a correct clock: anchored
        self.assertEqual(rep.anchored, [0])

    # -- crash recovery -------------------------------------------------------------------

    def test_crash_at_every_step_is_repaired(self):
        ids = self.ingest()
        self.tick()
        # 1. crash after the interval was closed, before its block was built
        self.ledger.freeze_open_interval(self.clock())
        ids += self.ingest()
        self.tick()
        rep = self.sealer.run_cycle()
        self.assertEqual((rep.sealed, rep.anchored), ([0, 1], [0, 1]))

        # 2. crash after the block was built, before anchoring (an unexpected error from the TSA client)
        ids += self.ingest()
        self.tick()

        class Boom(TSAClient):
            def timestamp(self, *a, **k):
                raise RuntimeError("process killed")

        with self.assertRaises(RuntimeError):
            self.make_sealer(Boom([TSAEndpoint("x", "http://x/")])).run_cycle()
        self.assertEqual(self.ledger.get_block(2)["state"], "sealed")

        # 3. crash after anchoring, before receipts
        orig = Sealer._receipts
        Sealer._receipts = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("killed"))
        try:
            with self.assertRaises(RuntimeError):
                self.sealer.run_cycle(freeze=False)
        finally:
            Sealer._receipts = orig
        self.assertEqual(self.ledger.get_block(2)["state"], "anchored")
        self.assertEqual(self.ledger.blocks_awaiting_receipts(("api", "upload")), [2])

        # 4. crash after receipt objects were written, before the ledger rows
        orig_store = self.ledger.store_receipts
        self.ledger.store_receipts = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("killed"))
        with self.assertRaises(RuntimeError):
            self.sealer.run_cycle(freeze=False)
        self.ledger.store_receipts = orig_store
        written = {rid: json.loads(self.store.get(f"receipts/{rid}.json")) for rid in ids[8:11]}
        self.tick()
        rep = self.sealer.run_cycle()
        self.assertEqual(rep.receipts, 3)
        for rid, obj in written.items():
            self.assertEqual(self.ledger.get_receipt(rid), obj)  # the first-written copy is the one kept
        self.assert_chain_valid(3)
        for rid in ids:
            row = self.ledger.get_record(rid)
            self.assertEqual(row["status"], "receipted" if row["source_type"] == "api" else "anchored")

    # -- leader election -------------------------------------------------------------------

    def test_only_one_leader(self):
        a, b = LeaderLock.for_database(self.ledger.db), LeaderLock.for_database(self.ledger.db)
        self.assertTrue(a.acquire())
        self.assertTrue(a.acquire())  # re-entrant for the holder
        self.assertFalse(b.acquire())
        self.assertTrue(a.still_held())
        a.release()
        self.assertTrue(b.acquire())
        self.assertFalse(a.acquire())
        b.release()

    def test_concurrent_sealers_cannot_fork_the_chain(self):
        """Even without the lock, the ledger's constraints keep one linear chain."""
        for _ in range(4):
            self.ingest(5, 0)
            self.tick()
            others = [self.make_sealer() for _ in range(3)]
            errors = []

            def go(s):
                try:
                    s.run_cycle()
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=go, args=(s,)) for s in others]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.sealer.run_cycle(freeze=False)  # finish anything a losing thread left behind
        res = verify_ledger_chain(self.ledger, provider().keyring(), self.tsa.roots)
        self.assertTrue(res.ok, res.to_dict())
        with self.ledger.db.transaction() as tx:
            unsealed = tx.one("SELECT count(*) FROM records WHERE block_id IS NULL")[0]
            total = tx.one("SELECT count(*) FROM records")[0]
            in_blocks = tx.one("SELECT sum(entry_count) FROM blocks")[0]
        self.assertEqual(int(unsealed), 0)
        self.assertEqual(int(in_blocks), int(total))

    # -- the service loop -----------------------------------------------------------------

    def test_service_seals_on_wall_clock_boundaries(self):
        lock = LeaderLock.for_database(self.ledger.db)
        svc = SealerService(self.sealer, None, lock, interval_seconds=300, clock=self.clock, sleep=None)
        created = []

        def fake_sleep(seconds):
            self.clock.t += timedelta(seconds=seconds)
            self.ingest(1, 0)
            if svc.cycles >= 4:
                svc.stop.set()

        svc.sleep = fake_sleep
        svc.run()
        blocks = self.ledger.blocks_range()
        self.assertGreaterEqual(len(blocks), 3)
        for b in blocks:
            created.append(parse_rfc3339(b["header"]["interval"]["end"]))
        for end in created:
            self.assertEqual((end.minute % 5, end.second), (0, 0))
        self.assertFalse(lock.still_held())  # released on stop
        self.assert_chain_valid(len(blocks))

    # -- webhooks ---------------------------------------------------------------------------

    def test_webhook_delivery_signature_and_retries(self):
        secret = "whsec_test"
        self.ledger.add_client(ApiClient("k-alice", b"x" * 32, "user", "alice@example.com", None, "api-key", ("api",), None,
                                         ("submitter",), "https://hooks.example.com/polarys", True, secret), utcnow())
        received, status = [], {"code": 500}

        def handler(request: httpx.Request) -> httpx.Response:
            ok = verify_signature(secret, request.headers["x-polarys-timestamp"], request.content,
                                  request.headers["x-polarys-signature"], now=self.clock().timestamp())
            received.append((request.headers["x-polarys-delivery"], ok, json.loads(request.content)))
            return httpx.Response(status["code"])

        d = Deliverer(self.ledger, http=httpx.Client(transport=httpx.MockTransport(handler)), clock=self.clock)
        ids = self.ingest(2, 1)
        self.tick()
        self.sealer.run_cycle()
        r = d.run_once()
        self.assertEqual((r.attempted, r.failed), (2, 2))
        self.assertTrue(all(ok for _, ok, _ in received))
        self.assertEqual(d.run_once().attempted, 0)  # backing off
        st = self.ledger.delivery_status(ids[0])
        self.assertEqual((st["attempts"], st["next_attempt_at"] - self.clock()), (1, timedelta(minutes=1)))
        self.tick(1)
        d.run_once()
        self.assertEqual(self.ledger.delivery_status(ids[0])["attempts"], 2)
        status["code"] = 204
        self.tick(2)
        self.assertEqual(d.run_once().delivered, 2)
        self.assertIsNotNone(self.ledger.delivery_status(ids[0])["delivered_at"])
        self.assertEqual(received[-1][2], self.ledger.get_receipt(received[-1][0]))
        self.assertNotIn(ids[2], [x[0] for x in received])  # device records have no receipt

        # A receiver that stays down is given up on after 24 hours.
        status["code"] = 503
        more = self.ingest(1, 0)
        self.tick()
        self.sealer.run_cycle()
        for _ in range(40):
            d.run_once()
            self.tick(60)
        st = self.ledger.delivery_status(more[0])
        self.assertTrue(st["gave_up"])
        self.assertLessEqual(st["attempts"], 30)
        self.assertEqual(st["last_error"], "HTTP 503")

    def test_webhook_signature_check(self):
        from polarys.delivery import sign_payload

        sig = sign_payload("s", 1000, b"{}")
        self.assertTrue(verify_signature("s", "1000", b"{}", sig, now=1100))
        self.assertFalse(verify_signature("s", "1000", b"{ }", sig, now=1100))
        self.assertFalse(verify_signature("t", "1000", b"{}", sig, now=1100))
        self.assertFalse(verify_signature("s", "1000", b"{}", sig, now=2000))  # replayed too late


class SQLiteSealer(SealerContract, unittest.TestCase):
    backend = "sqlite"


if "postgres" in backend_names():

    class PostgresSealer(SealerContract, unittest.TestCase):
        backend = "postgres"


class DevTSAPersistence(unittest.TestCase):
    def test_same_ca_after_restart(self):
        d = tempfile.mkdtemp()
        a, b = DevTSA.load_or_create(d), DevTSA.load_or_create(d)
        self.assertEqual(a.ca_pem(), b.ca_pem())
        self.assertEqual(block_hash.__name__, "block_hash")


if __name__ == "__main__":
    unittest.main()
