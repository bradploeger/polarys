import math
import random
import unittest

from polarys.jcs import CanonicalizationError, canonicalize
from polarys.merkle import (
    CompactRange,
    InclusionProof,
    MerkleTree,
    leaf_hash,
    mth,
    reference_path,
    root_from_inclusion,
    verify_inclusion,
)

# Certificate Transparency reference vectors (RFC 6962 implementation test data)
CT_LEAVES = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43", bytes(range(0x50, 0x58)), bytes(range(0x60, 0x70))]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


class JCSTests(unittest.TestCase):
    def test_rfc8785_numbers(self):
        out = canonicalize([333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001, -0.0, 1e21, 1e-7, 123e-20, 5e-324])
        self.assertEqual(out, b"[333333333.3333333,1e+30,4.5,0.002,1e-27,0,1e+21,1e-7,1.23e-18,5e-324]")

    def test_rfc8785_key_order_utf16(self):
        obj = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh", "1": "One",
               "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"}
        keys = list(__import__("json").loads(canonicalize(obj)))
        self.assertEqual(keys, ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"])

    def test_string_escaping(self):
        self.assertEqual(canonicalize("€$\u000f\nA'B\"\\/"), '"€$\\u000f\\nA\'B\\"\\\\/"'.encode())

    def test_rejects(self):
        for bad in (2**53, math.nan, math.inf, {1: "x"}, b"bytes"):
            with self.assertRaises(CanonicalizationError):
                canonicalize(bad)


class MerkleTests(unittest.TestCase):
    def test_ct_vectors(self):
        for n in range(1, 9):
            leaves = [leaf_hash(d) for d in CT_LEAVES[:n]]
            self.assertEqual(MerkleTree(leaves).root.hex(), CT_ROOTS[n - 1])
            self.assertEqual(mth(CT_LEAVES[:n]).hex(), CT_ROOTS[n - 1])

    def test_proofs_match_reference_and_verify(self):
        rng = random.Random(7)
        for n in list(range(1, 70)) + [127, 128, 129, 1000]:
            data = [rng.randbytes(8) for _ in range(n)]
            leaves = [leaf_hash(d) for d in data]
            tree = MerkleTree(leaves)
            cr = CompactRange()
            for h in leaves:
                cr.append(h)
            self.assertEqual(cr.root(), tree.root)
            for i in ([0, n - 1, n // 2] if n > 70 else range(n)):
                p = tree.proof(i)
                if n <= 70:
                    self.assertEqual(list(p.audit_path), reference_path(i, data))
                self.assertTrue(verify_inclusion(leaves[i], p, tree.root))

    def test_bad_proofs_rejected(self):
        leaves = [leaf_hash(bytes([i])) for i in range(11)]
        tree = MerkleTree(leaves)
        p = tree.proof(5)
        self.assertFalse(verify_inclusion(leaves[6], p, tree.root))
        self.assertFalse(verify_inclusion(leaves[5], InclusionProof(4, 11, p.audit_path), tree.root))
        # A different tree size is rejected when it changes the path shape.  (Sizes with the same
        # shape, e.g. 11 and 12 for leaf 5, are not distinguishable by the hashes alone, so the
        # verifier must also check tree_size against the block's entry_count, as receipts do.)
        self.assertFalse(verify_inclusion(leaves[5], InclusionProof(5, 7, p.audit_path), tree.root))
        self.assertFalse(verify_inclusion(leaves[5], InclusionProof(5, 11, p.audit_path[:-1]), tree.root))
        self.assertFalse(verify_inclusion(leaves[5], InclusionProof(5, 11, p.audit_path + (b"\0" * 32,)), tree.root))
        with self.assertRaises(ValueError):
            root_from_inclusion(leaves[0], InclusionProof(11, 11, ()))

    def test_leaf_and_node_domain_separation(self):
        a, b = leaf_hash(b"a"), leaf_hash(b"b")
        two = MerkleTree([a, b]).root
        # A leaf whose data is the concatenation of two child hashes must not collide with their parent.
        self.assertNotEqual(leaf_hash(a + b), two)

    def test_serialization(self):
        tree = MerkleTree([leaf_hash(bytes([i])) for i in range(13)])
        data = tree.to_bytes()
        self.assertEqual(MerkleTree.from_bytes(data).root, tree.root)
        bad = bytearray(data)
        bad[-1] ^= 1
        with self.assertRaises(ValueError):
            MerkleTree.from_bytes(bytes(bad))

    def test_proof_dict_roundtrip(self):
        tree = MerkleTree([leaf_hash(bytes([i])) for i in range(9)])
        p = tree.proof(8)
        self.assertEqual(InclusionProof.from_dict(p.to_dict()), p)


if __name__ == "__main__":
    unittest.main()
