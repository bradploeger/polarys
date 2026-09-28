"""REST API tests (Starlette TestClient), against every available backend."""

import base64
import tempfile
import unittest
from datetime import timedelta

from starlette.testclient import TestClient

from polarys.api import Services, create_app, new_api_key
from polarys.config import Settings
from polarys.ingest import Ingestor, RecordReader
from polarys.ledger import ApiClient
from polarys.receipts import verify_receipt
from polarys.sealing import OpenInterval, receipts_for, seal
from polarys.store.local import LocalFSStore
from polarys.store.spool import SpoolingStore
from polarys.util import utcnow

from backends import backend_names, fresh_ledger
from helpers import Clock, dev_tsa, provider


class ApiContract:
    backend = "sqlite"

    def setUp(self):
        self._ctx = fresh_ledger(self.backend)
        self.ledger = self._ctx.__enter__()
        self.settings = Settings(_env_file=None, database_url="sqlite://", max_record_bytes=1024, max_submission_bytes=4096,
                                 max_request_bytes=200_000, max_batch=50, trusted_proxies=["10.0.0.0/8"], client_cache_seconds=0)
        store = SpoolingStore(LocalFSStore(tempfile.mkdtemp()), tempfile.mkdtemp())
        ing = Ingestor(self.ledger, store, provider(), max_record_bytes=1024, max_submission_bytes=4096, tx_batch=20)
        self.svc = Services(self.settings, self.ledger, store, provider(), ing, RecordReader(self.ledger, store, provider()))
        self.api = TestClient(create_app(self.svc))
        self.alice = self.add_client("user", "alice@example.com", roles=("submitter", "records_manager"))
        self.bob = self.add_client("user", "bob@example.com", classes=("sales_invoices",))
        self.agent = self.add_client("device", "ws01.corp.example.com", sources=("windows_event",))
        self.auditor = self.add_client("user", "audit@example.com", roles=("auditor",))

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def add_client(self, typ, ident, sources=("api",), classes=None, roles=("submitter",)):
        key_id, token, h = new_api_key()
        self.ledger.add_client(ApiClient(key_id, h, typ, ident, None, "api-key", sources, classes, roles, None, True), utcnow())
        return {"Authorization": f"Bearer {token}", "_key_id": key_id}

    def h(self, who, **extra):
        return {k: v for k, v in who.items() if not k.startswith("_")} | extra

    def post(self, who, body, **headers):
        return self.api.post("/v1/records", json=body, headers=self.h(who, **headers))

    # -- authentication ----------------------------------------------------------------

    def test_authentication(self):
        body = {"record_class": "correspondence", "text": "hi"}
        self.assertEqual(self.api.post("/v1/records", json=body).status_code, 401)
        self.assertEqual(self.api.post("/v1/records", json=body, headers={"Authorization": "Bearer nope"}).status_code, 401)
        bad = self.alice["Authorization"][:-3] + "xyz"
        self.assertEqual(self.api.post("/v1/records", json=body, headers={"Authorization": bad}).status_code, 401)
        self.assertEqual(self.post(self.alice, body).status_code, 201)
        self.ledger.revoke_client(self.alice["_key_id"], utcnow())
        r = self.post(self.alice, body)
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (401, "unauthenticated"))
        self.assertEqual(r.headers["www-authenticate"], "Bearer")

    # -- submission ------------------------------------------------------------------------

    def test_submit_kinds(self):
        r = self.post(self.alice, {"record_class": "customer_data", "data": {"customer": "Contoso", "tier": 2}})
        self.assertEqual(r.status_code, 201, r.text)
        ack = r.json()
        self.assertEqual(r.headers["location"], f"/v1/records/{ack['record_id']}")
        self.assertEqual((ack["submitter"], ack["retention_rule"], ack["retain_until"]),
                         ({"type": "user", "id": "alice@example.com"}, "event:relationship_end+P7Y", None))
        rec = self.svc.reader.signed_record(self.ledger.get_record(ack["record_id"]))
        self.assertEqual(rec.payload, b'{"customer":"Contoso","tier":2}')  # canonical JSON
        self.assertEqual(rec.envelope["origin"]["api_key_id"], self.alice["_key_id"])

        r = self.post(self.alice, {"record_class": "correspondence", "text": "Dear Sir", "content_type": "text/plain"})
        self.assertEqual(r.status_code, 201)
        r = self.post(self.alice, {"record_class": "payroll", "payload_base64": base64.b64encode(b"\x00\x01").decode()})
        self.assertEqual(r.status_code, 201)
        r = self.post(self.alice, {"record_class": "public_relations", "data": None})
        self.assertEqual(r.status_code, 201)

        docs = [{"name": "policy.pdf", "content_type": "application/pdf", "data_base64": base64.b64encode(b"%PDF p").decode()},
                {"name": "rider.pdf", "data_base64": base64.b64encode(b"%PDF r").decode()}]
        r = self.post(self.alice, {"record_class": "insurance", "title": "Policy 42", "documents": docs})
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["manifest"]["title"], "Policy 42")
        row = self.ledger.get_record(r.json()["record_id"])
        self.assertEqual(self.svc.reader.document(row, 1), b"%PDF r")

    def test_validation(self):
        cases = [
            ({"record_class": "correspondence"}, 422, "invalid_record"),
            ({"record_class": "correspondence", "text": "a", "data": 1}, 422, "invalid_record"),
            ({"record_class": "correspondence", "text": "a", "extra": 1}, 422, "invalid_record"),
            ({"record_class": "correspondence", "payload_base64": "***"}, 422, "invalid_record"),
            ({"record_class": "nope", "text": "a"}, 422, "invalid_record_class"),
            ({"text": "a"}, 422, "invalid_record_class"),
            ({"record_class": "correspondence", "text": "x" * 2000}, 413, "record_too_large"),
            ({"record_class": "legal", "documents": [{"name": "../x", "data_base64": ""}]}, 422, "invalid_record"),
            ({"record_class": "correspondence", "data": 2**60}, 422, "invalid_record"),
        ]
        for body, status, code in cases:
            r = self.post(self.alice, body)
            self.assertEqual((r.status_code, r.json()["error"]["code"]), (status, code), body)
        r = self.api.post("/v1/records", content=b"{not json", headers=self.h(self.alice))
        self.assertEqual(r.json()["error"]["code"], "invalid_json")
        r = self.api.post("/v1/records", content=b"x" * 300_000, headers=self.h(self.alice))
        self.assertEqual(r.status_code, 413)

    def test_permissions(self):
        r = self.post(self.bob, {"record_class": "payroll", "text": "x"})
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (403, "class_not_allowed"))
        self.assertEqual(self.post(self.bob, {"record_class": "sales_invoices", "text": "x"}).status_code, 201)
        r = self.post(self.bob, {"record_class": "sales_invoices", "text": "x", "source_type": "windows_event"})
        self.assertEqual(r.json()["error"]["code"], "source_not_allowed")
        r = self.post(self.bob, {"record_class": "sales_invoices", "text": "x", "attributes": {"permanent": True}})
        self.assertEqual(r.json()["error"]["code"], "attribute_not_allowed")
        r = self.post(self.alice, {"record_class": "employee", "text": "x", "attributes": {"permanent": True}})
        self.assertEqual(r.json()["retention_rule"], "indefinite")
        r = self.post(self.agent, {"record_class": "sales_invoices", "text": "x"})
        self.assertEqual(r.json()["error"]["code"], "source_not_allowed")
        r = self.post(self.agent, {"source_type": "windows_event", "data": {"EventID": 4624}, "attributes": {"security": True}})
        self.assertEqual((r.status_code, r.json()["record_class"], r.json()["submitter"]["type"]), (201, "device_logs", "device"))

    def test_idempotency_header(self):
        body = {"record_class": "correspondence", "text": "once"}
        a = self.post(self.alice, body, **{"Idempotency-Key": "k-1"})
        b = self.post(self.alice, body, **{"Idempotency-Key": "k-1"})
        self.assertEqual((a.status_code, b.status_code), (201, 200))
        self.assertEqual(b.headers["idempotent-replayed"], "true")
        self.assertEqual(a.json()["record_id"], b.json()["record_id"])
        c = self.post(self.alice, {"record_class": "correspondence", "text": "twice"}, **{"Idempotency-Key": "k-1"})
        self.assertEqual(c.status_code, 409)
        d = self.post(self.bob, {"record_class": "sales_invoices", "text": "once"}, **{"Idempotency-Key": "k-1"})
        self.assertEqual(d.status_code, 201)  # keys are scoped to the API key

    def test_forwarded_for_only_from_trusted_proxy(self):
        r = self.post(self.alice, {"record_class": "correspondence", "text": "x"}, **{"X-Forwarded-For": "203.0.113.9"})
        rec = self.svc.reader.signed_record(self.ledger.get_record(r.json()["record_id"]))
        self.assertEqual(rec.envelope["origin"]["ip"], "testclient")  # TestClient's peer is not a trusted proxy

    # -- batch -----------------------------------------------------------------------------

    def test_batch(self):
        items = [{"record_class": "correspondence", "text": f"m{i}", "idempotency_key": f"b{i}"} for i in range(45)]
        items[3] = {"record_class": "correspondence"}
        items[7] = {"record_class": "payroll", "text": "x"}
        items[9] = {"record_class": "correspondence", "text": "x" * 2000}
        r = self.api.post("/v1/records:batch", json={"records": items}, headers=self.h(self.alice))
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual((body["accepted"], body["rejected"]), (43, 2))
        self.assertEqual([x["index"] for x in body["results"]], list(range(45)))
        self.assertEqual(body["results"][3]["error"]["code"], "invalid_record")
        self.assertEqual(body["results"][9]["status"], 413)
        again = self.api.post("/v1/records:batch", json={"records": items[:5]}, headers=self.h(self.alice)).json()
        self.assertEqual([x["status"] for x in again["results"]], [200, 200, 200, 422, 200])
        r = self.api.post("/v1/records:batch", json={"records": items + items}, headers=self.h(self.alice))
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (413, "batch_too_large"))
        r = self.api.post("/v1/records:batch", json={"records": []}, headers=self.h(self.alice))
        self.assertEqual(r.status_code, 422)

    # -- reading ----------------------------------------------------------------------------

    def test_record_status_access(self):
        rid = self.post(self.alice, {"record_class": "correspondence", "text": "x"}).json()["record_id"]
        r = self.api.get(f"/v1/records/{rid}", headers=self.h(self.alice))
        self.assertEqual((r.status_code, r.json()["status"], r.json()["block_id"]), (200, "committed", None))
        self.assertEqual(self.api.get(f"/v1/records/{rid}", headers=self.h(self.bob)).status_code, 404)
        self.assertEqual(self.api.get(f"/v1/records/{rid}", headers=self.h(self.auditor)).status_code, 200)
        self.assertEqual(self.api.get("/v1/records/not-a-uuid", headers=self.h(self.alice)).status_code, 404)

    def test_receipt_lifecycle_end_to_end(self):
        rid = self.post(self.alice, {"record_class": "sales_invoices", "data": {"invoice": 1}}).json()["record_id"]
        dev_rid = self.post(self.agent, {"source_type": "windows_event", "text": "evt"}).json()["record_id"]
        r = self.api.get(f"/v1/records/{rid}/receipt", headers=self.h(self.alice))
        self.assertEqual((r.status_code, r.headers["retry-after"], r.json()["status"]), (202, "60", "committed"))
        r = self.api.get(f"/v1/records/{dev_rid}/receipt", headers=self.h(self.agent))
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (404, "no_receipt"))
        self.assertEqual(self.api.get("/v1/blocks/latest", headers=self.h(self.auditor)).status_code, 404)

        # What the Phase 3 sealer will do:
        iv = self.ledger.freeze_open_interval(utcnow())
        rows = self.ledger.interval_records(iv.interval_id)
        oi = OpenInterval(iv.opened_at, iv.closed_at)
        for row in rows:
            oi.add(self.svc.reader.signed_record(row))
        clock = Clock(utcnow() + timedelta(seconds=1))
        dev, client = dev_tsa(clock)
        block = seal(oi, block_id=0, prev=None, provider=provider(), tsa=client, created_at=clock.t)
        self.ledger.store_block(block.header, block.hash, iv.interval_id, [(x["record_id"], i) for i, x in enumerate(rows)],
                                block.token, block.timestamp.tsa.name, block.timestamp.info.gen_time)
        for k, v in receipts_for(block, provider()).items():
            self.ledger.store_receipt(k, 0, v, utcnow())

        r = self.api.get(f"/v1/records/{rid}/receipt", headers=self.h(self.alice))
        self.assertEqual(r.status_code, 200)
        keys = self.api.get("/.well-known/log-keys.json").json()
        from polarys.keys import KeyRing

        rep = verify_receipt(r.json(), KeyRing.from_document(keys), [dev.ca_cert])
        self.assertTrue(rep.ok, rep.to_dict())
        self.assertEqual(rep.warnings, [])
        self.assertEqual(self.api.get(f"/v1/records/{rid}", headers=self.h(self.alice)).json()["status"], "receipted")

        self.assertEqual(self.api.get("/v1/blocks/latest", headers=self.h(self.alice)).status_code, 403)
        b = self.api.get("/v1/blocks/latest", headers=self.h(self.auditor)).json()
        self.assertEqual((b["block_id"], b["state"], b["block_hash"]), (0, "anchored", block.hash.hex()))
        self.assertEqual(self.api.get("/v1/blocks/0", headers=self.h(self.auditor)).json()["header"], block.header)
        self.assertEqual(self.api.get("/v1/blocks/9", headers=self.h(self.auditor)).status_code, 404)

    def test_verify_chain_endpoint(self):
        from polarys.sealer import Sealer

        clock = Clock(utcnow())
        dev, client = dev_tsa(clock)
        self.svc.tsa_trust_roots = [dev.ca_cert]
        sealer = Sealer(self.ledger, self.svc.store, provider(), client, self.svc.reader, clock=clock)
        for _ in range(3):
            self.post(self.alice, {"record_class": "correspondence", "text": "x"})
            clock.t += timedelta(minutes=5)
            sealer.run_cycle()
        r = self.api.post("/v1/audit/verify-chain", json={}, headers=self.h(self.auditor))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["ok"], r.json()["blocks_checked"]), (True, 3))
        r = self.api.post("/v1/audit/verify-chain", json={"from": 1, "to": 2}, headers=self.h(self.auditor))
        self.assertEqual((r.json()["ok"], [b["block_id"] for b in r.json()["blocks"]]), (True, [1, 2]))
        self.assertEqual(self.api.post("/v1/audit/verify-chain", json={}, headers=self.h(self.alice)).status_code, 403)
        self.assertEqual(self.api.post("/v1/audit/verify-chain", json={"from": -1}, headers=self.h(self.auditor)).status_code, 422)
        # Tamper with a stored header: the audit reports it.
        b1 = self.ledger.get_block(1)
        forged = dict(b1["header"], entry_count=2)
        with self.ledger.db.transaction() as tx:
            tx.execute(f"UPDATE blocks SET header = {self.ledger.J} WHERE block_id = 1", (__import__("json").dumps(forged),))
        body = self.api.post("/v1/audit/verify-chain", json={}, headers=self.h(self.auditor)).json()
        self.assertFalse(body["ok"])
        self.assertIn("sealer signature does not verify", body["blocks"][1]["errors"])

    def test_health(self):
        self.assertEqual(self.api.get("/healthz").json()["status"], "ok")
        r = self.api.get("/readyz").json()
        self.assertEqual((r["status"], r["spool_pending"]), ("ready", 0))
        doc = self.api.get("/.well-known/log-keys.json").json()
        self.assertEqual({k["use"] for k in doc["keys"]}, {"record", "block"})


class SQLiteApi(ApiContract, unittest.TestCase):
    backend = "sqlite"


if "postgres" in backend_names():

    class PostgresApi(ApiContract, unittest.TestCase):
        backend = "postgres"


if __name__ == "__main__":
    unittest.main()
