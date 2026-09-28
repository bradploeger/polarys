"""Local filesystem object store.

Objects are written atomically (temp file, fsync, hard-link into place) so a
key can never be overwritten, and made read-only.  Retention is recorded in a
sidecar under ``.retention/`` but cannot be enforced against the host's
administrator; use S3 Object Lock where WORM guarantees are required.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ..util import rfc3339
from . import ObjectExists, ObjectNotFound, ObjectStore, Retention, StoreUnavailable, validate_key


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class LocalFSStore(ObjectStore):
    name = "local"

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.root / validate_key(key)

    def put(self, key, data, content_type="application/octet-stream", retention: Retention | None = None) -> None:
        path = self._path(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(tmp, 0o444)
                try:
                    os.link(tmp, path)
                except FileExistsError:
                    raise ObjectExists(key) from None
            finally:
                os.unlink(tmp)
            _fsync_dir(path.parent)
            if retention and (retention.retain_until or retention.legal_hold):
                side = self.root / ".retention" / (key + ".json")
                side.parent.mkdir(parents=True, exist_ok=True)
                side.write_text(json.dumps({
                    "retain_until": rfc3339(retention.retain_until) if retention.retain_until else None,
                    "legal_hold": retention.legal_hold,
                }))
        except ObjectExists:
            raise
        except OSError as e:
            raise StoreUnavailable(f"local store write failed for {key}: {e}") from e

    def get(self, key: str) -> bytes:
        try:
            return self._path(key).read_bytes()
        except FileNotFoundError:
            raise ObjectNotFound(key) from None

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()
