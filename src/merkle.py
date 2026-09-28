"""RFC 6962 / RFC 9162 Merkle trees.

    leaf  = SHA-256(0x00 || leaf_data)
    node  = SHA-256(0x01 || left || right)

Unbalanced trees split at the largest power of two smaller than n, so no
leaf is ever duplicated.  ``MerkleTree`` stores every level (an odd node at
the end of a level is carried up unchanged, which yields exactly the RFC 6962
tree) and serves inclusion proofs; ``CompactRange`` gives the root of a
growing tree in O(log n) memory, for the sealer's in-memory state.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

HASH_LEN = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()
_MAGIC = b"PLMT\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def mth(leaf_data: list[bytes]) -> bytes:
    """Reference recursive Merkle Tree Hash from RFC 6962 section 2.1 (for tests)."""
    n = len(leaf_data)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hash(leaf_data[0])
    k = 1 << (n - 1).bit_length() - 1
    return node_hash(mth(leaf_data[:k]), mth(leaf_data[k:]))


def reference_path(m: int, leaf_data: list[bytes]) -> list[bytes]:
    """Reference recursive PATH(m, D[n]) from RFC 6962 section 2.1.1 (for tests)."""
    n = len(leaf_data)
    if n <= 1:
        return []
    k = 1 << (n - 1).bit_length() - 1
    if m < k:
        return reference_path(m, leaf_data[:k]) + [mth(leaf_data[k:])]
    return reference_path(m - k, leaf_data[k:]) + [mth(leaf_data[:k])]


@dataclass(frozen=True)
class InclusionProof:
    leaf_index: int
    tree_size: int
    audit_path: tuple[bytes, ...]

    def to_dict(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "audit_path": [h.hex() for h in self.audit_path],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InclusionProof":
        path = tuple(bytes.fromhex(h) for h in d["audit_path"])
        if any(len(h) != HASH_LEN for h in path):
            raise ValueError("audit path entries must be 32-byte hashes")
        return cls(int(d["leaf_index"]), int(d["tree_size"]), path)


def root_from_inclusion(leaf: bytes, proof: InclusionProof) -> bytes:
    """RFC 9162 section 2.1.3.2: recompute the root from a leaf hash and audit path."""
    index, size = proof.leaf_index, proof.tree_size
    if not 0 <= index < size:
        raise ValueError("leaf_index out of range")
    fn, sn = index, size - 1
    r = leaf
    for p in proof.audit_path:
        if sn == 0:
            raise ValueError("audit path too long")
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("audit path too short")
    return r


def verify_inclusion(leaf: bytes, proof: InclusionProof, root: bytes) -> bool:
    """True when the proof leads from ``leaf`` to ``root``.

    The hashes alone do not authenticate ``proof.tree_size`` (sizes that give
    the same path shape verify equally), so callers must also check the size
    against the signed ``entry_count`` of the block.
    """
    try:
        return root_from_inclusion(leaf, proof) == root
    except ValueError:
        return False


class MerkleTree:
    """An immutable tree over a fixed list of leaf hashes, with all levels kept."""

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("a tree needs at least one leaf")
        if any(len(h) != HASH_LEN for h in leaves):
            raise ValueError("leaves must be 32-byte leaf hashes")
        levels = [list(leaves)]
        while len(levels[-1]) > 1:
            cur = levels[-1]
            nxt = [node_hash(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
            if len(cur) % 2:
                nxt.append(cur[-1])
            levels.append(nxt)
        self.levels = levels

    @property
    def size(self) -> int:
        return len(self.levels[0])

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def leaf(self, index: int) -> bytes:
        return self.levels[0][index]

    def proof(self, index: int) -> InclusionProof:
        if not 0 <= index < self.size:
            raise IndexError("leaf index out of range")
        path, idx = [], index
        for level in self.levels[:-1]:
            sib = idx ^ 1
            if sib < len(level):
                path.append(level[sib])
            idx >>= 1
        return InclusionProof(index, self.size, tuple(path))

    # -- persistence: trees/{block_id}.bin ------------------------------------

    def to_bytes(self) -> bytes:
        out = [_MAGIC, struct.pack(">Q", self.size)]
        for level in self.levels:
            out.extend(level)
        return b"".join(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> "MerkleTree":
        if data[:5] != _MAGIC:
            raise ValueError("not a POLARYS tree file")
        (n,) = struct.unpack(">Q", data[5:13])
        leaves = [data[13 + i * HASH_LEN : 13 + (i + 1) * HASH_LEN] for i in range(n)]
        tree = cls(leaves)
        if tree.to_bytes() != data:
            raise ValueError("tree file is corrupt: interior nodes do not match the leaves")
        return tree


class CompactRange:
    """Root of a growing tree in O(log n) memory (perfect subtrees on a stack)."""

    def __init__(self) -> None:
        self._stack: list[tuple[int, bytes]] = []  # (height, hash), heights strictly decreasing
        self.size = 0

    def append(self, leaf: bytes) -> None:
        h, node = 0, leaf
        while self._stack and self._stack[-1][0] == h:
            _, left = self._stack.pop()
            node = node_hash(left, node)
            h += 1
        self._stack.append((h, node))
        self.size += 1

    def root(self) -> bytes:
        if not self._stack:
            return EMPTY_ROOT
        acc = self._stack[-1][1]
        for _, left in reversed(self._stack[:-1]):
            acc = node_hash(left, acc)
        return acc
