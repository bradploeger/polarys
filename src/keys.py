"""Key custody.

``KeyProvider`` is the only interface the rest of POLARYS uses for private-key
operations, so moving from local key files to AWS KMS, HashiCorp Vault or a
PKCS#11 HSM means writing one new provider class.

Keys and purposes
-----------------
* ``record``  Ed25519, signs every record envelope
* ``block``   Ed25519, signs block headers and receipts (kept separate from ``record``)
* KEK        AES-256, wraps the per-interval / per-class data keys (RFC 3394 AES key wrap)

Key identifiers are ``ed25519:<first 16 bytes of SHA-256(raw public key), hex>``
and ``kek:<16 random bytes, hex>``; they are embedded in every signed object so
keys can be rotated while old signatures stay verifiable.
"""

from __future__ import annotations

import hashlib
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from .util import b64d, b64e, rfc3339, utcnow

PURPOSES = ("record", "block")


def ed25519_key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).digest()[:16].hex()


def raw_public(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass(frozen=True)
class WrappedKey:
    kek_id: str
    blob: bytes  # RFC 3394 wrapped key

    def to_dict(self) -> dict:
        return {"kek_id": self.kek_id, "wrapped": b64e(self.blob)}

    @classmethod
    def from_dict(cls, d: dict) -> "WrappedKey":
        return cls(d["kek_id"], b64d(d["wrapped"]))


class KeyProvider(ABC):
    """Private-key operations. Implementations must never expose private key material."""

    @abstractmethod
    def active_key_id(self, purpose: str) -> str: ...

    @abstractmethod
    def sign(self, key_id: str, data: bytes) -> bytes: ...

    @abstractmethod
    def public_key(self, key_id: str) -> Ed25519PublicKey: ...

    @abstractmethod
    def wrap_dek(self, dek: bytes) -> WrappedKey: ...

    @abstractmethod
    def unwrap_dek(self, wrapped: WrappedKey) -> bytes: ...

    def keyring(self) -> "KeyRing":
        """Public keys for verification (all purposes, including retired keys)."""
        raise NotImplementedError


# --------------------------------------------------------------------------
# Public key ring (verifier side; also the /.well-known/log-keys.json document)
# --------------------------------------------------------------------------


@dataclass
class PublicKeyEntry:
    key_id: str
    use: str
    public_key: Ed25519PublicKey
    status: str = "active"
    created: str | None = None

    def to_dict(self) -> dict:
        d = {
            "key_id": self.key_id,
            "alg": "Ed25519",
            "use": self.use,
            "public_key": b64e(raw_public(self.public_key)),
            "status": self.status,
        }
        if self.created:
            d["created"] = self.created
        return d


class KeyRing:
    def __init__(self, entries: list[PublicKeyEntry] | None = None, source: str = "unspecified"):
        self._by_id: dict[str, PublicKeyEntry] = {}
        self.source = source
        for e in entries or []:
            self.add(e)

    def add(self, entry: PublicKeyEntry) -> None:
        if ed25519_key_id(entry.public_key) != entry.key_id:
            raise ValueError(f"key_id {entry.key_id} does not match its public key")
        self._by_id[entry.key_id] = entry

    def get(self, key_id: str) -> PublicKeyEntry:
        try:
            return self._by_id[key_id]
        except KeyError:
            raise KeyError(f"unknown key_id {key_id}") from None

    def __contains__(self, key_id: str) -> bool:
        return key_id in self._by_id

    def entries(self) -> list[PublicKeyEntry]:
        return list(self._by_id.values())

    def verify(self, key_id: str, signature: bytes, data: bytes, use: str | None = None) -> bool:
        try:
            entry = self.get(key_id)
        except KeyError:
            return False
        if use is not None and entry.use != use:
            return False
        try:
            entry.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def to_document(self) -> dict:
        return {"version": 1, "keys": [e.to_dict() for e in self._by_id.values()]}

    @classmethod
    def from_document(cls, doc: dict, source: str = "document") -> "KeyRing":
        ring = cls(source=source)
        for k in doc.get("keys", []):
            if k.get("alg") != "Ed25519":
                continue
            pub = Ed25519PublicKey.from_public_bytes(b64d(k["public_key"]))
            ring.add(PublicKeyEntry(k["key_id"], k["use"], pub, k.get("status", "active"), k.get("created")))
        return ring

    @classmethod
    def load(cls, path: str | os.PathLike) -> "KeyRing":
        return cls.from_document(json.loads(Path(path).read_text()), source=str(path))


# --------------------------------------------------------------------------
# Local provider: encrypted key files on disk
# --------------------------------------------------------------------------

_SCRYPT = {"n": 2**15, "r": 8, "p": 1}


def _derive(passphrase: bytes, salt: bytes, params: dict) -> bytes:
    return Scrypt(salt=salt, length=32, n=params["n"], r=params["r"], p=params["p"]).derive(passphrase)


class LocalKeyProvider(KeyProvider):
    """Keys stored as passphrase-encrypted files in one directory.

    Layout::

        keystore.json            active key ids, retired keys, KEK metadata
        ed25519-<hex>.pem        PKCS#8, encrypted with the passphrase
        kek-<hex>.json           AES-256 KEK, AES-GCM encrypted under a scrypt-derived key
    """

    def __init__(self, directory: str | os.PathLike, passphrase: str | bytes):
        self.dir = Path(directory)
        self._pass = passphrase.encode() if isinstance(passphrase, str) else passphrase
        self._meta = json.loads((self.dir / "keystore.json").read_text())
        self._signing: dict[str, Ed25519PrivateKey] = {}
        self._keks: dict[str, bytes] = {}
        for key_id in self._meta["signing_keys"]:
            pem = (self.dir / _pem_name(key_id)).read_bytes()
            priv = serialization.load_pem_private_key(pem, password=self._pass)
            if not isinstance(priv, Ed25519PrivateKey) or ed25519_key_id(priv.public_key()) != key_id:
                raise ValueError(f"key file for {key_id} is invalid")
            self._signing[key_id] = priv
        for kek_id in self._meta["keks"]:
            self._keks[kek_id] = self._load_kek(kek_id)

    # -- creation / rotation -------------------------------------------------

    @classmethod
    def create(cls, directory: str | os.PathLike, passphrase: str | bytes) -> "LocalKeyProvider":
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        if (d / "keystore.json").exists():
            raise FileExistsError(f"{d} already contains a keystore")
        pw = passphrase.encode() if isinstance(passphrase, str) else passphrase
        meta = {"version": 1, "active": {}, "signing_keys": {}, "keks": {}, "active_kek": None}
        for purpose in PURPOSES:
            _new_signing_key(d, pw, meta, purpose)
        _new_kek(d, pw, meta)
        _write_meta(d, meta)
        return cls(d, pw)

    def rotate(self, purpose: str) -> str:
        """Create a new active key for ``purpose``; the old one is kept as retired."""
        if purpose == "kek":
            kek_id = _new_kek(self.dir, self._pass, self._meta)
            self._keks[kek_id] = self._load_kek(kek_id)
            _write_meta(self.dir, self._meta)
            return kek_id
        old = self._meta["active"][purpose]
        self._meta["signing_keys"][old]["status"] = "retired"
        key_id = _new_signing_key(self.dir, self._pass, self._meta, purpose)
        pem = (self.dir / _pem_name(key_id)).read_bytes()
        self._signing[key_id] = serialization.load_pem_private_key(pem, password=self._pass)
        _write_meta(self.dir, self._meta)
        return key_id

    # -- KeyProvider ---------------------------------------------------------

    def active_key_id(self, purpose: str) -> str:
        return self._meta["active"][purpose]

    def sign(self, key_id: str, data: bytes) -> bytes:
        if self._meta["signing_keys"][key_id]["status"] != "active":
            raise PermissionError(f"key {key_id} is retired and cannot sign")
        return self._signing[key_id].sign(data)

    def public_key(self, key_id: str) -> Ed25519PublicKey:
        return self._signing[key_id].public_key()

    def wrap_dek(self, dek: bytes) -> WrappedKey:
        kek_id = self._meta["active_kek"]
        return WrappedKey(kek_id, aes_key_wrap(self._keks[kek_id], dek))

    def unwrap_dek(self, wrapped: WrappedKey) -> bytes:
        return aes_key_unwrap(self._keks[wrapped.kek_id], wrapped.blob)

    def keyring(self) -> KeyRing:
        ring = KeyRing(source=f"keystore {self.dir}")
        for key_id, info in self._meta["signing_keys"].items():
            ring.add(PublicKeyEntry(key_id, info["use"], self.public_key(key_id), info["status"], info["created"]))
        return ring

    # -- internals -------------------------------------------------------------

    def _load_kek(self, kek_id: str) -> bytes:
        doc = json.loads((self.dir / f"kek-{kek_id.split(':', 1)[1]}.json").read_text())
        key = _derive(self._pass, b64d(doc["salt"]), doc["scrypt"])
        return AESGCM(key).decrypt(b64d(doc["nonce"]), b64d(doc["ciphertext"]), kek_id.encode())


def _pem_name(key_id: str) -> str:
    return "ed25519-" + key_id.split(":", 1)[1] + ".pem"


def _new_signing_key(d: Path, pw: bytes, meta: dict, purpose: str) -> str:
    priv = Ed25519PrivateKey.generate()
    key_id = ed25519_key_id(priv.public_key())
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(pw),
    )
    path = d / _pem_name(key_id)
    path.write_bytes(pem)
    os.chmod(path, 0o600)
    meta["signing_keys"][key_id] = {"use": purpose, "status": "active", "created": rfc3339(utcnow())}
    meta["active"][purpose] = key_id
    return key_id


def _new_kek(d: Path, pw: bytes, meta: dict) -> str:
    kek = AESGCM.generate_key(256)
    kek_id = "kek:" + os.urandom(16).hex()
    salt, nonce = os.urandom(16), os.urandom(12)
    enc = AESGCM(_derive(pw, salt, _SCRYPT)).encrypt(nonce, kek, kek_id.encode())
    doc = {"kek_id": kek_id, "scrypt": _SCRYPT, "salt": b64e(salt), "nonce": b64e(nonce), "ciphertext": b64e(enc)}
    path = d / f"kek-{kek_id.split(':', 1)[1]}.json"
    path.write_text(json.dumps(doc, indent=2))
    os.chmod(path, 0o600)
    if meta.get("active_kek"):
        meta["keks"][meta["active_kek"]]["status"] = "retired"
    meta["keks"][kek_id] = {"status": "active", "created": rfc3339(utcnow())}
    meta["active_kek"] = kek_id
    return kek_id


def _write_meta(d: Path, meta: dict) -> None:
    tmp = d / "keystore.json.tmp"
    tmp.write_text(json.dumps(meta, indent=2))
    tmp.replace(d / "keystore.json")
