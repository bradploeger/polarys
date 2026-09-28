import json
import tempfile
import unittest
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag

from polarys import cipher
from polarys.classes import MAX_RETENTION_YEARS, ClassRegistry, Retention, RetentionError, add_years
from polarys.keys import KeyRing, LocalKeyProvider
from polarys.manifest import Document, build_manifest, check_manifest, verify_document
from polarys.records import IdentityError, SignedRecord, Submitter, new_record, sign_record, verify_record

from helpers import DEVICE, T0, USER, provider

EXPECTED_CLASSES = {
    "device_logs": "Device Logs",
    "sales_invoices": "Sales Receipts / Invoices",
    "expense_docs": "Expense Documentation",
    "payroll": "Payroll Records",
    "employee": "Employee Records",
    "customer_data": "Customer Data",
    "corporate": "Corporate Records",
    "tax_returns": "Tax Returns",
    "tax_support": "Tax Return Supporting Documentation",
    "insurance": "Insurance",
    "accounts_payable": "Accounts Payable",
    "ppe": "Plant/Property/Equipment Records",
    "legal": "Legal Matters",
    "correspondence": "Correspondence",
    "workplace_safety": "Workplace Safety",
    "public_relations": "Public Relations",
}


class KeyTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp() + "/ks"
        self.p = LocalKeyProvider.create(self.dir, "pw")

    def test_reload_and_wrong_passphrase(self):
        again = LocalKeyProvider(self.dir, "pw")
        self.assertEqual(again.active_key_id("record"), self.p.active_key_id("record"))
        with self.assertRaises(Exception):
            LocalKeyProvider(self.dir, "wrong")

    def test_record_and_block_keys_are_separate(self):
        self.assertNotEqual(self.p.active_key_id("record"), self.p.active_key_id("block"))
        ring = self.p.keyring()
        sig = self.p.sign(self.p.active_key_id("record"), b"x")
        self.assertTrue(ring.verify(self.p.active_key_id("record"), sig, b"x", use="record"))
        self.assertFalse(ring.verify(self.p.active_key_id("record"), sig, b"x", use="block"))

    def test_rotation_keeps_old_signatures_verifiable(self):
        old = self.p.active_key_id("record")
        sig = self.p.sign(old, b"data")
        new = self.p.rotate("record")
        self.assertNotEqual(old, new)
        with self.assertRaises(PermissionError):
            self.p.sign(old, b"more")
        ring = KeyRing.from_document(json.loads(json.dumps(self.p.keyring().to_document())))
        self.assertTrue(ring.verify(old, sig, b"data"))
        self.assertEqual(ring.get(old).status, "retired")

    def test_kek_rotation_keeps_old_deks(self):
        wrapped = self.p.wrap_dek(b"k" * 32)
        self.p.rotate("kek")
        self.assertNotEqual(self.p.wrap_dek(b"k" * 32).kek_id, wrapped.kek_id)
        self.assertEqual(LocalKeyProvider(self.dir, "pw").unwrap_dek(wrapped), b"k" * 32)

    def test_keyring_rejects_mismatched_key_id(self):
        doc = self.p.keyring().to_document()
        doc["keys"][0]["key_id"] = doc["keys"][1]["key_id"]
        with self.assertRaises(ValueError):
            KeyRing.from_document(doc)


class CipherTests(unittest.TestCase):
    def test_roundtrip_and_binding(self):
        dek = cipher.DataKey.generate(provider(), "20260926T1900Z", "payroll")
        aad = cipher.record_aad("rec-1", b"\x01" * 32)
        obj = cipher.encrypt(dek, b"secret", aad)
        again = cipher.DataKey.unwrap(provider(), dek.dek_id, dek.wrapped)
        self.assertEqual(cipher.decrypt(again, obj, aad), b"secret")
        with self.assertRaises(InvalidTag):
            cipher.decrypt(dek, obj, cipher.record_aad("rec-2", b"\x01" * 32))
        with self.assertRaises(InvalidTag):
            cipher.decrypt(dek, obj, cipher.record_aad("rec-1", b"\x02" * 32))
        other = cipher.DataKey.generate(provider(), "20260926T1900Z", "legal")
        with self.assertRaises(ValueError):
            cipher.decrypt(other, obj, aad)


class IdentityTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(Submitter("device", "FW01.Example.COM.", "mtls").id, "fw01.example.com")
        self.assertEqual(Submitter("user", "Jane.Doe@Contoso.com", "oidc").id, "jane.doe@contoso.com")

    def test_invalid(self):
        for typ, ident in [("device", "fw01"), ("device", "-bad.example.com"), ("device", "10.0.0.1"), ("device", "host.123"),
                           ("user", "jane"), ("user", "jane@localhost"), ("user", "a b@example.com"), ("robot", "x.example.com")]:
            with self.assertRaises(IdentityError, msg=ident):
                Submitter(typ, ident, "x")


class RecordTests(unittest.TestCase):
    def test_sign_verify_and_tamper(self):
        env = new_record(ClassRegistry(), source_type="api", submitter=USER, payload=b"hello", content_type="text/plain",
                         received_at=T0, requested_class="correspondence")
        rec = sign_record(env, provider())
        ring = provider().keyring()
        self.assertEqual(verify_record(rec, ring), [])
        self.assertEqual(SignedRecord.from_dict(json.loads(rec.plaintext())).leaf_hash, rec.leaf_hash)
        for field, value in [("record_class", "legal"), ("retain_until", None), ("submitter", {**USER.to_dict(), "id": "mallory@example.com"})]:
            forged = SignedRecord(dict(rec.envelope, **{field: value}), rec.signature)
            self.assertTrue(verify_record(forged, ring), field)
            self.assertNotEqual(forged.leaf_hash, rec.leaf_hash)
        with self.assertRaises(ValueError):
            sign_record(rec.envelope, provider())

    def test_envelope_fields(self):
        env = new_record(ClassRegistry(), source_type="syslog", submitter=DEVICE, payload=b"<14>msg", content_type="text/syslog",
                         received_at=T0, attributes={"severity": 3})
        self.assertEqual(env["record_class"], "device_logs")
        self.assertEqual(env["retain_until"], "2027-09-26T19:00:30.000000Z")
        self.assertEqual(env["received_at"], "2026-09-26T19:00:30.000000Z")
        self.assertEqual(env["record_id"][14], "7")  # UUIDv7


class ClassTests(unittest.TestCase):
    def setUp(self):
        self.reg = ClassRegistry()

    def test_initial_classes(self):
        self.assertEqual({c.id: c.name for c in self.reg}, EXPECTED_CLASSES)

    def test_device_log_retention(self):
        dl = self.reg.get("device_logs")
        self.assertEqual(dl.retention_for({"severity": 5}).rule, "P90D")
        self.assertEqual(dl.retention_for({"severity": 7}).rule, "P90D")
        self.assertEqual(dl.retention_for({"severity": 4}).rule, "P1Y")
        self.assertEqual(dl.retention_for({"severity": 0}).rule, "P1Y")
        self.assertEqual(dl.retention_for({"severity": 6, "security": True}).rule, "P7Y")
        self.assertEqual(dl.retention_for({}).rule, "P90D")

    def test_event_and_indefinite(self):
        emp = self.reg.get("employee")
        self.assertEqual(self.reg.resolve(emp, {}, T0), {"retention_rule": "event:separation+P7Y", "retain_until": None})
        self.assertEqual(self.reg.resolve(emp, {"permanent": True}, T0)["retention_rule"], "indefinite")
        self.assertTrue(self.reg.get("tax_returns").requires_exception)
        self.assertFalse(self.reg.get("payroll").requires_exception)
        self.assertEqual(self.reg.get("workplace_safety").retention_for({"exposure_record": True}).rule, "P30Y")

    def test_maximum(self):
        self.assertFalse(Retention(f"P{MAX_RETENTION_YEARS}Y").exceeds_maximum)
        self.assertTrue(Retention(f"P{MAX_RETENTION_YEARS + 1}Y").exceeds_maximum)
        with self.assertRaises(RetentionError):
            Retention("P7M")

    def test_classify(self):
        self.assertEqual(self.reg.classify("windows_event").id, "device_logs")
        self.assertEqual(self.reg.classify("upload", "tax_returns").id, "tax_returns")
        with self.assertRaises(RetentionError):
            self.reg.classify("api")
        with self.assertRaises(RetentionError):
            self.reg.classify("api", "tax_returns")  # uploads only

    def test_leap_day(self):
        self.assertEqual(add_years(datetime(2028, 2, 29, tzinfo=timezone.utc), 7).day, 28)


class ManifestTests(unittest.TestCase):
    def test_manifest(self):
        docs = [Document("a.pdf", "application/pdf", b"A"), Document("b.pdf", "application/pdf", b"BB")]
        m = build_manifest("Q3", "expense_docs", docs)
        self.assertEqual(check_manifest(m), [])
        self.assertEqual(verify_document(m, b"BB")["index"], 1)
        self.assertIsNone(verify_document(m, b"B"))
        self.assertIsNone(verify_document(m, b"BB", index=0))
        m2 = json.loads(json.dumps(m))
        m2["documents"].reverse()
        self.assertTrue(check_manifest(m2))


if __name__ == "__main__":
    unittest.main()
