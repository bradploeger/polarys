"""Small helpers: UUIDv7, RFC 3339 times, base64/hex codecs."""

from __future__ import annotations

import base64
import os
import time
import uuid
from datetime import datetime, timezone


def uuid7(ts_ms: int | None = None) -> str:
    """RFC 9562 UUID version 7 (time-ordered)."""
    if ts_ms is None:
        ts_ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    rand_a = rand >> 62 & 0xFFF
    rand_b = rand & ((1 << 62) - 1)
    value = (ts_ms & ((1 << 48) - 1)) << 80 | 0x7 << 76 | rand_a << 64 | 0b10 << 62 | rand_b
    return str(uuid.UUID(int=value))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def rfc3339(dt: datetime) -> str:
    """UTC RFC 3339 timestamp with microseconds, e.g. 2026-09-26T19:40:00.000000Z."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_rfc3339(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def hexd(s: str, length: int | None = None) -> bytes:
    b = bytes.fromhex(s)
    if length is not None and len(b) != length:
        raise ValueError(f"expected {length} bytes, got {len(b)}")
    return b
