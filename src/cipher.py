"""AES-256-GCM encryption of signed records.

Each 5-minute interval gets one data encryption key (DEK) per record class.
Destroying a DEK crypto-shreds exactly that class's plaintext for that
interval, while leaf hashes, blocks and every other record's proofs remain
valid.

The additional authenticated data binds the ciphertext to its record:
``AAD = record_id (UTF-8) || leaf_hash (32 bytes)``, so a ciphertext cannot be
moved to a different record or leaf without detection.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keys import KeyProvider, WrappedKey
from .util import b64d, b64e


def dek_id(interval_id: str, record_class: str) -> str:
    return f"{interval_id}/{record_class}"


@dataclass
class DataKey:
    dek_id: str
    key: bytes
    wrapped: WrappedKey

    @classmethod
    def generate(cls, provider: KeyProvider, interval_id: str, record_class: str) -> "DataKey":
        key = AESGCM.generate_key(256)
        return cls(dek_id(interval_id, record_class), key, provider.wrap_dek(key))

    @classmethod
    def unwrap(cls, provider: KeyProvider, dek_id_: str, wrapped: WrappedKey) -> "DataKey":
        return cls(dek_id_, provider.unwrap_dek(wrapped), wrapped)

    def wrapped_document(self) -> dict:
        return {"dek_id": self.dek_id, **self.wrapped.to_dict()}


def record_aad(record_id: str, leaf_hash: bytes) -> bytes:
    return record_id.encode("utf-8") + leaf_hash


def encrypt(dek: DataKey, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(dek.key).encrypt(nonce, plaintext, aad)
    return {"v": 1, "alg": "A256GCM", "dek_id": dek.dek_id, "nonce": b64e(nonce), "ciphertext": b64e(ct)}


def decrypt(dek: DataKey, obj: dict, aad: bytes) -> bytes:
    if obj.get("alg") != "A256GCM" or obj.get("dek_id") != dek.dek_id:
        raise ValueError("object was not encrypted with this data key")
    return AESGCM(dek.key).decrypt(b64d(obj["nonce"]), b64d(obj["ciphertext"]), aad)
