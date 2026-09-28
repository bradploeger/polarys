"""Object storage for encrypted records, trees, blocks, tokens and receipts.

Every object is written once and never overwritten.  Backends:

* ``LocalFSStore``   a directory tree (development, single host)
* ``S3Store``        any S3-compatible service (AWS S3, MinIO, Ceph, Wasabi), with
                     Object Lock retention in compliance mode or legal holds
* ``SpoolingStore``  wraps a primary store; if the primary is unreachable, objects are
                     written to a local spool and uploaded later by ``drain()``
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


class StoreError(Exception):
    pass


class ObjectExists(StoreError):
    pass


class ObjectNotFound(StoreError):
    pass


class StoreUnavailable(StoreError):
    """The backend could not be reached or failed transiently; safe to spool and retry."""


@dataclass(frozen=True)
class Retention:
    """WORM protection requested for an object.

    ``retain_until`` sets Object Lock compliance-mode retention.  ``legal_hold``
    is used for event-based and indefinite retention, which have no end date yet.
    """

    retain_until: datetime | None = None
    legal_hold: bool = False

    @classmethod
    def for_record(cls, retain_until: datetime | None, retention_rule: str) -> "Retention":
        if retain_until is not None:
            return cls(retain_until=retain_until)
        return cls(legal_hold=True)  # event-based ("event:…") or "indefinite"


class ObjectStore(ABC):
    name = "store"

    @abstractmethod
    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream", retention: Retention | None = None) -> None:
        """Write a new object. Raises ObjectExists if the key is taken, StoreUnavailable on transient failure."""

    @abstractmethod
    def get(self, key: str) -> bytes: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    def put_many(self, items: list[tuple[str, bytes, str, Retention | None]]) -> None:
        for key, data, ctype, ret in items:
            self.put(key, data, ctype, ret)


def validate_key(key: str) -> str:
    if not key or key.startswith("/") or "\\" in key or any(p in ("", ".", "..") for p in key.split("/")):
        raise StoreError(f"invalid object key {key!r}")
    return key


def open_store(settings) -> ObjectStore:
    """Build the configured store (see ``polarys.config.Settings``)."""
    from .local import LocalFSStore
    from .s3 import S3Store
    from .spool import SpoolingStore

    if settings.store == "local":
        primary = LocalFSStore(settings.local_store_dir)
    elif settings.store == "s3":
        primary = S3Store.from_settings(settings)
    else:
        raise ValueError(f"unknown store {settings.store!r}")
    if settings.spool_dir:
        return SpoolingStore(primary, settings.spool_dir)
    return primary
