"""Block headers, sealing signatures, block hashes and chain verification.

    block_hash = SHA-256(JCS(header))        (header includes sealer_signature)
    sealer_signature = Ed25519(block key, JCS(header without sealer_signature))

Each block embeds the previous block's hash and its full RFC 3161 token, so
rewriting any block would require forging a TSA signature on every later
block, not only recomputing hashes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cryptography import x509

from .jcs import canonicalize
from .keys import KeyProvider, KeyRing
from .merkle import MerkleTree
from .tsa import TimestampError, TimestampInfo, verify_token
from .util import b64d, b64e, parse_rfc3339, rfc3339, uuid7

HEADER_VERSION = 1
GENESIS_PREV_HASH = "00" * 32
MAX_TOKEN_SKEW = timedelta(minutes=5)


def summarize_submitters(entries: list[tuple[int, dict]]) -> list[dict]:
    """Per-submitter summary for the header from ``(sequence, submitter dict)`` pairs."""
    by_key: dict[tuple[str, str], dict] = {}
    for seq, sub in entries:
        key = (sub["type"], sub["id"])
        s = by_key.get(key)
        if s is None:
            s = by_key[key] = {"type": sub["type"], "id": sub["id"], "record_count": 0, "first_seq": seq, "last_seq": seq}
            if sub.get("display_name"):
                s["display_name"] = sub["display_name"]
        s["record_count"] += 1
        s["first_seq"] = min(s["first_seq"], seq)
        s["last_seq"] = max(s["last_seq"], seq)
    return sorted(by_key.values(), key=lambda s: (s["first_seq"], s["type"], s["id"]))


def build_header(
    *,
    block_id: int,
    interval_start: datetime,
    interval_end: datetime,
    created_at: datetime,
    prev_block_hash: str,
    prev_timestamp_token: bytes | None,
    merkle_root: bytes,
    entry_count: int,
    submitters: list[dict],
) -> dict:
    if block_id == 0:
        if prev_block_hash != GENESIS_PREV_HASH or prev_timestamp_token is not None:
            raise ValueError("the genesis block has no predecessor")
    elif prev_timestamp_token is None:
        raise ValueError("a block cannot be sealed until its predecessor has a timestamp token")
    if entry_count < 1:
        raise ValueError("empty intervals are not sealed")
    return {
        "version": HEADER_VERSION,
        "block_id": block_id,
        "block_uuid": uuid7(int(created_at.timestamp() * 1000)),
        "created_at": rfc3339(created_at),
        "interval": {"start": rfc3339(interval_start), "end": rfc3339(interval_end)},
        "prev_block_hash": prev_block_hash,
        "prev_timestamp_token": b64e(prev_timestamp_token) if prev_timestamp_token else None,
        "merkle_root": merkle_root.hex(),
        "entry_count": entry_count,
        "submitters": submitters,
        "hash_alg": "sha256",
    }


def _unsigned(header: dict) -> dict:
    return {k: v for k, v in header.items() if k != "sealer_signature"}


def sign_header(header: dict, provider: KeyProvider) -> dict:
    h = dict(_unsigned(header), signing_key_id=provider.active_key_id("block"))
    sig = provider.sign(h["signing_key_id"], canonicalize(h))
    return dict(h, sealer_signature=b64e(sig))


def block_hash(header: dict) -> bytes:
    if "sealer_signature" not in header:
        raise ValueError("block header is not signed")
    return hashlib.sha256(canonicalize(header)).digest()


def verify_header_signature(header: dict, keyring: KeyRing) -> bool:
    try:
        sig = b64d(header["sealer_signature"])
    except (KeyError, ValueError):
        return False
    return keyring.verify(header.get("signing_key_id", ""), sig, canonicalize(_unsigned(header)), use="block")


# --------------------------------------------------------------------------
# Chain verification
# --------------------------------------------------------------------------


@dataclass
class BlockCheck:
    block_id: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    gen_time: datetime | None = None
    tsa: str | None = None


@dataclass
class ChainReport:
    blocks: list[BlockCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and all(not b.errors for b in self.blocks)


def verify_block(
    header: dict,
    token: bytes | None,
    keyring: KeyRing,
    trust_roots: list[x509.Certificate] | None = None,
    leaves: list[bytes] | None = None,
) -> tuple[BlockCheck, TimestampInfo | None]:
    chk = BlockCheck(header.get("block_id", -1))
    if header.get("version") != HEADER_VERSION:
        chk.errors.append(f"unsupported header version {header.get('version')}")
    if not verify_header_signature(header, keyring):
        chk.errors.append("sealer signature does not verify")
    subs = header.get("submitters", [])
    if sum(s.get("record_count", 0) for s in subs) != header.get("entry_count"):
        chk.errors.append("submitter record counts do not add up to entry_count")
    if leaves is not None:
        if len(leaves) != header.get("entry_count"):
            chk.errors.append(f"{len(leaves)} leaves supplied but entry_count is {header.get('entry_count')}")
        elif MerkleTree(leaves).root.hex() != header.get("merkle_root"):
            chk.errors.append("Merkle root recomputed from the stored leaves does not match")
    info = None
    try:
        bh = block_hash(header)
    except ValueError as e:
        chk.errors.append(str(e))
        return chk, None
    if token is None:
        chk.errors.append("block has no timestamp token")
    else:
        try:
            info = verify_token(token, bh, trust_roots=trust_roots)
            chk.gen_time, chk.tsa = info.gen_time, info.tsa_name
            chk.warnings += info.warnings
            if not trust_roots:
                chk.warnings.append("TSA certificate chain not checked (no trust roots given)")
            created = parse_rfc3339(header["created_at"])
            if abs(info.gen_time - created) > MAX_TOKEN_SKEW:
                chk.errors.append("TSA genTime is more than 5 minutes from created_at")
        except TimestampError as e:
            chk.errors.append(f"timestamp token: {e}")
    return chk, info


def _accuracy(info: TimestampInfo) -> timedelta:
    """A token's stated accuracy; one second when the TSA does not state it."""
    return timedelta(seconds=info.accuracy_seconds if info.accuracy_seconds is not None else 1)


def verify_chain(
    blocks: list[tuple[dict, bytes | None]],
    keyring: KeyRing,
    trust_roots: list[x509.Certificate] | None = None,
    leaves_by_block: dict[int, list[bytes]] | None = None,
    expect_genesis: bool = True,
) -> ChainReport:
    """Verify consecutive blocks ``[(header, token), ...]`` ordered by block_id."""
    report = ChainReport()
    if not blocks:
        report.errors.append("no blocks to verify")
        return report
    prev_header, prev_token, prev_info = None, None, None
    for header, token in blocks:
        chk, info = verify_block(header, token, keyring, trust_roots, (leaves_by_block or {}).get(header.get("block_id")))
        bid = header.get("block_id")
        if prev_header is None:
            if expect_genesis and bid != 0:
                chk.errors.append("chain does not start at the genesis block (use --from to verify a range)")
            if bid == 0 and (header.get("prev_block_hash") != GENESIS_PREV_HASH or header.get("prev_timestamp_token") is not None):
                chk.errors.append("genesis block must have a zero prev_block_hash and no prev_timestamp_token")
        else:
            if bid != prev_header.get("block_id", -2) + 1:
                chk.errors.append(f"block_id {bid} does not follow {prev_header.get('block_id')}")
            try:
                if header.get("prev_block_hash") != block_hash(prev_header).hex():
                    chk.errors.append("prev_block_hash does not match the previous block")
            except ValueError:
                chk.errors.append("previous block header is not signed")
            if prev_token is None or header.get("prev_timestamp_token") != b64e(prev_token):
                chk.errors.append("prev_timestamp_token does not match the previous block's token")
            if info and prev_info and info.gen_time < prev_info.gen_time - _accuracy(prev_info) - _accuracy(info):
                # The hash chain fixes the order; genTimes only need to agree with it within the TSAs'
                # stated accuracy (two blocks anchored in the same second are legitimate).
                chk.errors.append("TSA genTime is earlier than the previous block's, beyond the TSAs' stated accuracy")
            if parse_rfc3339(header["interval"]["start"]) < parse_rfc3339(prev_header["interval"]["end"]):
                chk.errors.append("interval overlaps the previous block's interval")
        report.blocks.append(chk)
        prev_header, prev_token, prev_info = header, token, info
    return report
