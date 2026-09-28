"""Submitter receipts.

A receipt is everything a submitter needs to prove, offline and without
trusting the operator, that their record existed unaltered no later than the
TSA's genTime:

    signed_record -> leaf_hash -> inclusion_proof -> merkle_root (in block_header)
    block_header -> block_hash -> RFC 3161 timestamp_token

``receipt_signature`` (block key) makes the bundle itself tamper-evident but
proves nothing on its own; the proof is the chain above.  The public keys
are embedded for convenience; a verifier should pin them against the
published ``/.well-known/log-keys.json`` or a known fingerprint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from cryptography import x509

from .blocks import block_hash, verify_header_signature
from .jcs import canonicalize
from .keys import KeyProvider, KeyRing
from .manifest import MANIFEST_CONTENT_TYPE, check_manifest, verify_document
from .merkle import InclusionProof, root_from_inclusion
from .records import SignedRecord, verify_record
from .tsa import TimestampError, verify_token
from .util import b64d, b64e, rfc3339, utcnow

RECEIPT_VERSION = 1


def build_receipt(
    record: SignedRecord,
    proof: InclusionProof,
    header: dict,
    token: bytes,
    tsa_name: str,
    provider: KeyProvider,
) -> dict:
    ring = provider.keyring()
    keys = [ring.get(record.key_id).to_dict(), ring.get(header["signing_key_id"]).to_dict()]
    receipt = {
        "version": RECEIPT_VERSION,
        "issued_at": rfc3339(utcnow()),
        "record_id": record.record_id,
        "signed_record": record.to_dict(),
        "leaf_hash": record.leaf_hash.hex(),
        "inclusion_proof": proof.to_dict(),
        "block_header": header,
        "block_hash": block_hash(header).hex(),
        "timestamp": {"tsa": tsa_name, "token": b64e(token)},
        "server_keys": keys,
        "receipt_key_id": provider.active_key_id("block"),
    }
    receipt["receipt_signature"] = b64e(provider.sign(receipt["receipt_key_id"], canonicalize(receipt)))
    return receipt


@dataclass
class Step:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class ReceiptReport:
    steps: list[Step] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    gen_time: str | None = None

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.steps.append(Step(name, ok, detail))
        return ok

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "timestamp": self.gen_time,
            "steps": [s.__dict__ for s in self.steps],
            "warnings": self.warnings,
        }


def verify_receipt(
    receipt: dict,
    keyring: KeyRing | None = None,
    trust_roots: list[x509.Certificate] | None = None,
    documents: list[tuple[str, bytes]] | None = None,
) -> ReceiptReport:
    """Verify every link of a receipt. Never raises on bad input; failures are reported as steps."""
    rep = ReceiptReport()
    try:
        _verify(receipt, keyring, trust_roots, documents, rep)
    except (KeyError, TypeError, ValueError) as e:
        rep.add("receipt structure", False, f"malformed receipt: {type(e).__name__}: {e}")
    return rep


def _verify(receipt, keyring, trust_roots, documents, rep: ReceiptReport) -> None:
    if receipt.get("version") != RECEIPT_VERSION:
        rep.add("receipt version", False, f"unsupported version {receipt.get('version')}")
        return

    embedded = KeyRing.from_document({"keys": receipt["server_keys"]}, source="receipt")
    if keyring is None:
        keyring = embedded
        rep.warnings.append(
            "server keys were taken from the receipt itself; pin them with --keys (the published log-keys.json) "
            "for independent assurance"
        )
    else:
        for e in embedded.entries():
            if e.key_id not in keyring:
                rep.warnings.append(f"receipt key {e.key_id} is not in the supplied key ring")

    record = SignedRecord.from_dict(receipt["signed_record"])
    header = receipt["block_header"]

    problems = verify_record(record, keyring)
    rep.add("1. record signature", not problems, "; ".join(problems) or f"Ed25519 key {record.key_id}")

    leaf = record.leaf_hash
    rep.add("2. leaf hash", leaf.hex() == receipt["leaf_hash"], leaf.hex())

    proof = InclusionProof.from_dict(receipt["inclusion_proof"])
    try:
        root = root_from_inclusion(leaf, proof)
        ok = root.hex() == header["merkle_root"] and proof.tree_size == header["entry_count"]
        rep.add(
            "3. Merkle inclusion",
            ok,
            f"leaf {proof.leaf_index} of {proof.tree_size}, root {root.hex()}"
            + ("" if ok else f" (block root {header['merkle_root']}, entry_count {header['entry_count']})"),
        )
    except ValueError as e:
        rep.add("3. Merkle inclusion", False, str(e))

    bh = block_hash(header)
    sig_ok = verify_header_signature(header, keyring)
    rep.add(
        "4. block hash and sealer signature",
        sig_ok and bh.hex() == receipt["block_hash"],
        f"block {header['block_id']}, hash {bh.hex()}" + ("" if sig_ok else ", signature INVALID"),
    )

    try:
        info = verify_token(b64d(receipt["timestamp"]["token"]), bh, trust_roots=trust_roots)
        rep.gen_time = info.gen_time.isoformat().replace("+00:00", "Z")
        detail = f"{info.tsa_name} at {rep.gen_time}"
        if trust_roots:
            detail += ", chain to trusted root verified"
        else:
            rep.warnings.append("TSA certificate chain not checked; pass --tsa-ca with the TSA's root certificate")
        rep.warnings += [f"timestamp: {w}" for w in info.warnings]
        rep.add("5. RFC 3161 timestamp", True, detail)
    except TimestampError as e:
        rep.add("5. RFC 3161 timestamp", False, str(e))

    unsigned = {k: v for k, v in receipt.items() if k != "receipt_signature"}
    rep.add(
        "6. receipt signature",
        keyring.verify(receipt.get("receipt_key_id", ""), b64d(receipt["receipt_signature"]), canonicalize(unsigned), use="block"),
        f"key {receipt.get('receipt_key_id')}",
    )

    env = record.envelope
    if env.get("content_type") == MANIFEST_CONTENT_TYPE:
        manifest = json.loads(record.payload)
        issues = check_manifest(manifest)
        rep.add("7. document manifest", not issues, "; ".join(issues) or f"{manifest['document_count']} document(s)")
        for name, data in documents or []:
            entry = verify_document(manifest, data)
            rep.add(
                f"   document {name}",
                entry is not None,
                f"matches entry {entry['index']} ({entry['name']})" if entry else "not listed in the manifest (hash differs)",
            )
    elif documents:
        for name, data in documents:
            ok = data == record.payload
            rep.add(f"   file {name}", ok, "matches the record payload" if ok else "does not match the record payload")
