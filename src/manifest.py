"""Business-document submissions: one complete submission is one record.

The record's payload is a manifest listing every document (name, type, size,
SHA-256) in upload order plus ``submission_sha256``, the SHA-256 over the
concatenated raw document hashes.  Only the manifest is signed and put in the
Merkle tree; each document is encrypted and stored as its own object and is
bound to the record through its hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .jcs import canonicalize

MANIFEST_CONTENT_TYPE = "application/vnd.polarys.manifest+json"


@dataclass(frozen=True)
class Document:
    name: str
    content_type: str
    data: bytes


def build_manifest(title: str, category: str, documents: list[Document]) -> dict:
    if not documents:
        raise ValueError("a submission needs at least one document")
    entries = []
    digests = []
    for i, doc in enumerate(documents):
        d = hashlib.sha256(doc.data).digest()
        digests.append(d)
        entries.append(
            {"index": i, "name": doc.name, "content_type": doc.content_type, "size": len(doc.data), "sha256": d.hex()}
        )
    return {
        "version": 1,
        "title": title,
        "category": category,
        "document_count": len(entries),
        "documents": entries,
        "submission_sha256": hashlib.sha256(b"".join(digests)).hexdigest(),
    }


def manifest_payload(manifest: dict) -> bytes:
    return canonicalize(manifest)


def check_manifest(manifest: dict) -> list[str]:
    """Internal consistency problems (empty list when consistent)."""
    problems = []
    docs = manifest.get("documents", [])
    if manifest.get("document_count") != len(docs):
        problems.append("document_count does not match the document list")
    if [d.get("index") for d in docs] != list(range(len(docs))):
        problems.append("document indexes are not 0..n-1 in order")
    try:
        combined = hashlib.sha256(b"".join(bytes.fromhex(d["sha256"]) for d in docs)).hexdigest()
    except (KeyError, ValueError):
        return problems + ["a document hash is missing or malformed"]
    if combined != manifest.get("submission_sha256"):
        problems.append("submission_sha256 does not match the document hashes")
    return problems


def verify_document(manifest: dict, data: bytes, index: int | None = None, name: str | None = None) -> dict | None:
    """Return the manifest entry that ``data`` matches (by index, name or hash), else None."""
    digest = hashlib.sha256(data).hexdigest()
    for entry in manifest.get("documents", []):
        if index is not None and entry["index"] != index:
            continue
        if name is not None and entry["name"] != name:
            continue
        if entry["sha256"] == digest and entry["size"] == len(data):
            return entry
    return None
