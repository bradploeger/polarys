import copy
import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from polarys.blocks import GENESIS_PREV_HASH, sign_header, verify_chain
from polarys.cli import main
from polarys.keys import LocalKeyProvider
from polarys.receipts import verify_receipt
from polarys.sealing import DirectoryStore, OpenInterval, interval_bounds, receipts_for
from polarys.util import b64e, parse_rfc3339

from helpers import build_chain, provider


def as_pairs(blocks):
    return [(copy.deepcopy(b.header), b.token) for b in blocks]


class ChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocks, cls.dev = build_chain(4, 3)
        cls.ring = provider().keyring()
        cls.roots = [cls.dev.ca_cert]

    def check(self, pairs, **kw):
        return verify_chain(pairs, self.ring, self.roots, **kw)

    def test_valid_chain(self):
        rep = self.check(as_pairs(self.blocks), leaves_by_block={b.block_id: b.tree.levels[0] for b in self.blocks})
        self.assertTrue(rep.ok, [b.errors for b in rep.blocks])
        self.assertEqual(self.blocks[0].header["prev_block_hash"], GENESIS_PREV_HASH)
        self.assertEqual(self.blocks[2].header["prev_timestamp_token"], b64e(self.blocks[1].token))

    def test_header_field_tamper(self):
        for field, value in [("entry_count", 4), ("merkle_root", "00" * 32), ("created_at", "2026-01-01T00:00:00.000000Z")]:
            pairs = as_pairs(self.blocks)
            pairs[1][0][field] = value
            rep = self.check(pairs)
            self.assertFalse(rep.ok, field)
            self.assertIn("sealer signature does not verify", rep.blocks[1].errors)
            self.assertTrue(any("prev_block_hash" in e for e in rep.blocks[2].errors), field)

    def test_resigned_with_attackers_key_is_rejected(self):
        attacker = LocalKeyProvider.create(tempfile.mkdtemp() + "/ks", "x")
        pairs = as_pairs(self.blocks)
        pairs[1] = (sign_header(dict(pairs[1][0], entry_count=3), attacker), pairs[1][1])
        rep = self.check(pairs)
        self.assertIn("sealer signature does not verify", rep.blocks[1].errors)

    def test_operator_rebuild_breaks_timestamp(self):
        """Even the real sealing key cannot rewrite a block: the TSA token no longer matches."""
        pairs = as_pairs(self.blocks)
        forged = sign_header(dict(pairs[1][0], merkle_root="11" * 32), provider())
        pairs[1] = (forged, pairs[1][1])
        rep = self.check(pairs)
        self.assertTrue(any("timestamp token" in e for e in rep.blocks[1].errors))

    def test_deleted_block(self):
        pairs = as_pairs(self.blocks)
        del pairs[2]
        rep = self.check(pairs)
        self.assertTrue(any("does not follow" in e for e in rep.blocks[2].errors))

    def test_swapped_tokens(self):
        pairs = as_pairs(self.blocks)
        pairs[1], pairs[2] = (pairs[1][0], pairs[2][1]), (pairs[2][0], pairs[1][1])
        self.assertFalse(self.check(pairs).ok)

    def test_altered_leaf_detected_from_stored_tree(self):
        leaves = {b.block_id: list(b.tree.levels[0]) for b in self.blocks}
        leaves[0][1] = bytes(32)
        rep = self.check(as_pairs(self.blocks), leaves_by_block=leaves)
        self.assertIn("Merkle root recomputed from the stored leaves does not match", rep.blocks[0].errors)

    def test_range_without_genesis(self):
        pairs = as_pairs(self.blocks)[1:]
        self.assertFalse(self.check(pairs).ok)
        self.assertTrue(self.check(pairs, expect_genesis=False).ok)


class ReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocks, cls.dev = build_chain(2, 5)
        cls.receipts = receipts_for(cls.blocks[1], provider())
        cls.receipt = next(iter(cls.receipts.values()))

    def verify(self, r, **kw):
        return verify_receipt(r, provider().keyring(), [self.dev.ca_cert], **kw)

    def test_only_api_and_upload_get_receipts(self):
        sources = {r.envelope["source_type"] for r in self.blocks[1].records if r.record_id in self.receipts}
        self.assertEqual(sources, {"api"})
        self.assertEqual(len(self.receipts), 3)

    def test_valid(self):
        rep = self.verify(self.receipt)
        self.assertTrue(rep.ok, rep.to_dict())
        self.assertEqual(rep.warnings, [])

    def test_tampering(self):
        cases = {
            "payload": lambda r: r["signed_record"]["envelope"].__setitem__("payload", b64e(b"changed")),
            "proof": lambda r: r["inclusion_proof"]["audit_path"].__setitem__(0, "00" * 32),
            "index": lambda r: r["inclusion_proof"].__setitem__("leaf_index", (r["inclusion_proof"]["leaf_index"] + 1) % 5),
            "header": lambda r: r["block_header"].__setitem__("entry_count", 6),
            "token": lambda r: r["timestamp"].__setitem__("token", b64e(self.blocks[0].token)),
            "receipt": lambda r: r.__setitem__("issued_at", "2020-01-01T00:00:00.000000Z"),
        }
        for name, mutate in cases.items():
            r = copy.deepcopy(self.receipt)
            mutate(r)
            self.assertFalse(self.verify(r).ok, name)

    def test_unpinned_keys_warn(self):
        rep = verify_receipt(self.receipt)
        self.assertTrue(rep.ok)
        self.assertEqual(len(rep.warnings), 2)

    def test_garbage_does_not_crash(self):
        self.assertFalse(verify_receipt({"version": 1}).ok)
        self.assertFalse(verify_receipt({"version": 99}).ok)


class StoreAndCliTests(unittest.TestCase):
    def test_store_roundtrip(self):
        blocks, dev = build_chain(1, 4)
        root = Path(tempfile.mkdtemp())
        store = DirectoryStore(root, provider())
        b = blocks[0]
        start, end = interval_bounds(parse_rfc3339(b.header["interval"]["start"]))
        store.write_block(b, OpenInterval(start, end, b.records))
        files = sorted(root.glob("records/**/*.bin"))
        self.assertEqual(len(files), 4)
        for f in files:
            rec = store.read_record(f)
            self.assertIn(rec.leaf_hash, b.tree.levels[0])
        obj = json.loads(files[0].read_text())
        obj["record_id"] = "someone-else"
        files[0].write_text(json.dumps(obj))
        with self.assertRaises(Exception):
            store.read_record(files[0])

    def test_cli_demo_chain_receipt(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            r = runner.invoke(main, ["demo", "d"])
            self.assertEqual(r.exit_code, 0, r.output)
            r = runner.invoke(main, ["chain", "d/store", "--keys", "d/log-keys.json", "--tsa-ca", "d/dev-tsa-root.pem"])
            self.assertEqual(r.exit_code, 0, r.output)
            self.assertIn("VALID: 3 block(s)", r.output)
            receipts = sorted(Path("d/store/receipts").glob("*.json"))
            upload = [p for p in receipts if "tax_returns" in p.read_text()][0]
            docs = sorted(Path("d/documents").iterdir())
            args = ["receipt", str(upload), "--keys", "d/log-keys.json", "--tsa-ca", "d/dev-tsa-root.pem"]
            for d in docs:
                args += ["--document", str(d)]
            r = runner.invoke(main, args)
            self.assertEqual(r.exit_code, 0, r.output)
            self.assertIn("VALID", r.output)
            Path("fake.pdf").write_bytes(b"%PDF forged")
            r = runner.invoke(main, args[:6] + ["--document", "fake.pdf"])
            self.assertEqual(r.exit_code, 1)
            # tamper a stored block and the chain check fails
            b1 = Path("d/store/blocks/1.json")
            h = json.loads(b1.read_text())
            h["entry_count"] += 1
            b1.write_text(json.dumps(h))
            r = runner.invoke(main, ["chain", "d/store", "--keys", "d/log-keys.json", "--json"])
            self.assertEqual(r.exit_code, 1)
            self.assertFalse(json.loads(r.output)["ok"])


if __name__ == "__main__":
    unittest.main()
