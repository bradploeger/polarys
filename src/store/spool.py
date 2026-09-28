"""Local spool for object-store outages.

If the primary store raises ``StoreUnavailable``, the (already encrypted)
object is written durably to the spool directory instead and ``put`` reports
that it was spooled, so the record can still be acknowledged.  ``drain()``
uploads spooled objects once the primary is back and tells the caller which
keys have landed, so the ledger can mark those records ``stored``.

Spool entries are ``<spool>/<url-quoted key>.obj`` with a ``.meta`` JSON file
holding the content type and retention.  Both are fsynced before ``put``
returns.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import quote, unquote

from ..util import parse_rfc3339, rfc3339
from . import ObjectExists, ObjectStore, Retention, StoreUnavailable, validate_key


class SpoolingStore(ObjectStore):
    def __init__(self, primary: ObjectStore, spool_dir: str | os.PathLike):
        self.primary = primary
        self.name = f"{primary.name}+spool"
        self.dir = Path(spool_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.spooled_last: bool = False  # whether the most recent put() was spooled (per-thread use only)

    def _paths(self, key: str) -> tuple[Path, Path]:
        base = self.dir / quote(validate_key(key), safe="")
        return base.with_name(base.name + ".obj"), base.with_name(base.name + ".meta")

    def put(self, key, data, content_type="application/octet-stream", retention: Retention | None = None) -> None:
        self.put_or_spool(key, data, content_type, retention)

    def put_or_spool(self, key, data, content_type="application/octet-stream", retention: Retention | None = None) -> bool:
        """Returns True if the object was spooled rather than stored."""
        try:
            self.primary.put(key, data, content_type, retention)
            return False
        except StoreUnavailable:
            pass
        obj, meta = self._paths(key)
        if obj.exists():
            raise ObjectExists(key)
        meta_doc = {
            "key": key,
            "content_type": content_type,
            "retain_until": rfc3339(retention.retain_until) if retention and retention.retain_until else None,
            "legal_hold": bool(retention and retention.legal_hold),
        }
        for path, payload in ((meta, json.dumps(meta_doc).encode()), (obj, data)):
            tmp = path.with_name(path.name + ".tmp")
            with open(tmp, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        fd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return True

    def get(self, key: str) -> bytes:
        obj, _ = self._paths(key)
        if obj.exists():
            return obj.read_bytes()
        return self.primary.get(key)

    def exists(self, key: str) -> bool:
        obj, _ = self._paths(key)
        return obj.exists() or self.primary.exists(key)

    def pending(self) -> list[str]:
        return sorted(unquote(p.name[:-4]) for p in self.dir.glob("*.obj"))

    def drain(self, limit: int | None = None) -> tuple[list[str], list[str]]:
        """Upload spooled objects. Returns (uploaded keys, keys still pending)."""
        done: list[str] = []
        for key in self.pending()[:limit]:
            obj, meta = self._paths(key)
            m = json.loads(meta.read_text())
            ret = Retention(parse_rfc3339(m["retain_until"]) if m["retain_until"] else None, m["legal_hold"])
            try:
                self.primary.put(key, obj.read_bytes(), m["content_type"], ret)
            except ObjectExists:
                # Uploaded earlier but the spool copy was not removed (crash between the two steps).
                if self.primary.get(key) != obj.read_bytes():
                    raise
            except StoreUnavailable:
                break
            obj.unlink()
            meta.unlink()
            done.append(key)
        return done, self.pending()
