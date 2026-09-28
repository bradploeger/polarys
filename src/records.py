"""Record envelopes, submitter identity, signing and leaf hashes.

    canonical = JCS(envelope)
    signature = Ed25519(record key, canonical)
    leaf_hash = SHA-256(0x00 || canonical || signature)

The envelope carries ``signing_key_id`` so the signature covers which key
made it.  Submitter identity is always a device FQDN (``type = device``) or a
user principal name (``type = user``).
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime

from .classes import ClassRegistry
from .jcs import canonicalize
from .keys import KeyProvider, KeyRing
from .merkle import leaf_hash as _leaf_hash
from .util import b64d, b64e, rfc3339, uuid7

SOURCE_TYPES = ("syslog", "windows_event", "upload", "api", "audit", "retention_event")
ENVELOPE_VERSION = 1

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_FQDN = re.compile(rf"^(?=.{{1,253}}\.?$)(?:{_LABEL}\.)+(?=[A-Za-z0-9-]*[A-Za-z]){_LABEL}\.?$")  # TLD has a letter: no bare IPs
_UPN = re.compile(rf"^[A-Za-z0-9!#$%&'*+/=?^_`{{|}}~.-]{{1,64}}@(?:{_LABEL}\.)+{_LABEL}$")


class IdentityError(ValueError):
    pass


@dataclass(frozen=True)
class Submitter:
    type: str  # "device" | "user"
    id: str  # device FQDN or user UPN, lower-cased
    auth_method: str  # e.g. "mtls", "tls-syslog", "udp-syslog", "oidc", "api-key", "oauth2-client"
    display_name: str | None = None

    def __post_init__(self) -> None:
        if self.type == "device":
            if not _FQDN.match(self.id):
                raise IdentityError(f"device identity must be a fully qualified domain name: {self.id!r}")
            object.__setattr__(self, "id", self.id.rstrip(".").lower())
        elif self.type == "user":
            if not _UPN.match(self.id):
                raise IdentityError(f"user identity must be a user principal name (name@domain): {self.id!r}")
            object.__setattr__(self, "id", self.id.lower())
        else:
            raise IdentityError("submitter type must be 'device' or 'user'")

    def to_dict(self) -> dict:
        d = {"type": self.type, "id": self.id, "auth_method": self.auth_method}
        if self.display_name:
            d["display_name"] = self.display_name
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Submitter":
        return cls(d["type"], d["id"], d["auth_method"], d.get("display_name"))


def build_envelope(
    *,
    source_type: str,
    submitter: Submitter,
    payload: bytes,
    content_type: str,
    record_class: str,
    retention: dict,
    origin: dict | None = None,
    received_at: datetime,
    record_id: str | None = None,
    attributes: dict | None = None,
) -> dict:
    """The unsigned record envelope (see FORMATS.md).  ``signing_key_id`` is added by ``sign_record``."""
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"unknown source_type {source_type!r}")
    env = {
        "version": ENVELOPE_VERSION,
        "record_id": record_id or uuid7(int(received_at.timestamp() * 1000)),
        "received_at": rfc3339(received_at),
        "source_type": source_type,
        "submitter": submitter.to_dict(),
        "origin": origin or {},
        "record_class": record_class,
        "retention_rule": retention["retention_rule"],
        "retain_until": retention["retain_until"],
        "content_type": content_type,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload": b64e(payload),
    }
    if attributes:
        env["attributes"] = attributes
    return env


def new_record(
    registry: ClassRegistry,
    *,
    source_type: str,
    submitter: Submitter,
    payload: bytes,
    content_type: str,
    received_at: datetime,
    requested_class: str | None = None,
    attributes: dict | None = None,
    origin: dict | None = None,
) -> dict:
    """Classify, resolve retention and build the envelope in one step."""
    cls = registry.classify(source_type, requested_class)
    retention = registry.resolve(cls, attributes or {}, received_at)
    return build_envelope(
        source_type=source_type,
        submitter=submitter,
        payload=payload,
        content_type=content_type,
        record_class=cls.id,
        retention=retention,
        origin=origin,
        received_at=received_at,
        attributes=attributes,
    )


@dataclass(frozen=True)
class SignedRecord:
    envelope: dict
    signature: bytes

    @property
    def canonical(self) -> bytes:
        return canonicalize(self.envelope)

    @property
    def key_id(self) -> str:
        return self.envelope["signing_key_id"]

    @property
    def record_id(self) -> str:
        return self.envelope["record_id"]

    @property
    def leaf_hash(self) -> bytes:
        return record_leaf_hash(self.canonical, self.signature)

    @property
    def payload(self) -> bytes:
        return base64.b64decode(self.envelope["payload"])

    def to_dict(self) -> dict:
        return {"envelope": self.envelope, "signature": b64e(self.signature), "key_id": self.key_id}

    @classmethod
    def from_dict(cls, d: dict) -> "SignedRecord":
        rec = cls(d["envelope"], b64d(d["signature"]))
        if d.get("key_id") not in (None, rec.key_id):
            raise ValueError("key_id outside the envelope does not match the signed signing_key_id")
        return rec

    def plaintext(self) -> bytes:
        """Bytes that are encrypted for storage."""
        return canonicalize(self.to_dict())


def record_leaf_hash(canonical: bytes, signature: bytes) -> bytes:
    return _leaf_hash(canonical + signature)


def sign_record(envelope: dict, provider: KeyProvider) -> SignedRecord:
    if "signing_key_id" in envelope:
        raise ValueError("envelope is already signed")
    env = dict(envelope, signing_key_id=provider.active_key_id("record"))
    sig = provider.sign(env["signing_key_id"], canonicalize(env))
    return SignedRecord(env, sig)


def verify_record(record: SignedRecord, keyring: KeyRing) -> list[str]:
    """Problems with the record (empty list when it verifies)."""
    problems = []
    env = record.envelope
    if not keyring.verify(record.key_id, record.signature, record.canonical, use="record"):
        problems.append(f"record signature does not verify with key {record.key_id}")
    try:
        payload = b64d(env["payload"])
        if hashlib.sha256(payload).hexdigest() != env["payload_sha256"]:
            problems.append("payload_sha256 does not match the payload")
    except (KeyError, ValueError):
        problems.append("payload is missing or not valid base64")
    return problems
