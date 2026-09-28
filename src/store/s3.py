"""S3-compatible object store (AWS S3, MinIO, Ceph RGW, Wasabi) using Signature V4.

Writes use ``If-None-Match: *`` so an existing key is never overwritten, a
``Content-MD5`` header (required by S3 when Object Lock headers are sent), and
Object Lock in COMPLIANCE mode with the record's ``retain_until`` date, or a
legal hold for event-based and indefinite retention.  The bucket must be
created with Object Lock enabled for those headers to be accepted.

Transient failures (network errors, HTTP 5xx, 429, 409 conditional conflicts)
are retried with backoff and then raised as ``StoreUnavailable`` so the
spooling wrapper can take over.  Authorization and configuration errors (400,
403) are raised as ``StoreError`` and are not spooled, so they surface at once.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from . import ObjectExists, ObjectNotFound, ObjectStore, Retention, StoreError, StoreUnavailable, validate_key

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_UNSIGNED_HEADERS = {"authorization", "user-agent", "content-length", "accept-encoding", "connection", "expect"}


def _uri_encode(s: str, keep_slash: bool) -> str:
    return quote(s, safe="-_.~" + ("/" if keep_slash else ""))


def sigv4_headers(
    method: str,
    host: str,
    path: str,
    query: dict[str, str],
    headers: dict[str, str],
    payload_sha256: str,
    *,
    access_key: str,
    secret_key: str,
    region: str,
    amz_date: str,
    session_token: str | None = None,
    service: str = "s3",
) -> dict[str, str]:
    """Return ``headers`` plus ``Host``, ``x-amz-date``, ``x-amz-content-sha256`` and ``Authorization``.

    ``path`` is the raw (unencoded) object path, e.g. ``/bucket/records/…``.
    """
    h = {k: v for k, v in headers.items()}
    h["host"] = host
    h["x-amz-date"] = amz_date
    h["x-amz-content-sha256"] = payload_sha256
    if session_token:
        h["x-amz-security-token"] = session_token
    canon = {k.lower(): " ".join(str(v).strip().split()) for k, v in h.items() if k.lower() not in _UNSIGNED_HEADERS}
    signed = ";".join(sorted(canon))
    canonical_headers = "".join(f"{k}:{canon[k]}\n" for k in sorted(canon))
    canonical_query = "&".join(
        f"{_uri_encode(k, False)}={_uri_encode(v, False)}" for k, v in sorted(query.items())
    )
    canonical_request = "\n".join(
        [method, _uri_encode(path, True), canonical_query, canonical_headers, signed, payload_sha256]
    )
    date = amz_date[:8]
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()])
    k = ("AWS4" + secret_key).encode()
    for part in (date, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {k2: v for k2, v in h.items()}
    out["Authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope},SignedHeaders={signed},Signature={signature}"
    return out


class S3Store(ObjectStore):
    name = "s3"

    def __init__(
        self,
        bucket: str,
        *,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        session_token: str | None = None,
        prefix: str = "",
        path_style: bool | None = None,
        object_lock: bool = True,
        if_none_match: bool = True,
        attempts: int = 4,
        timeout: float = 30.0,
        http: httpx.Client | None = None,
        clock=None,
    ):
        self.bucket = bucket
        self.region = region
        self.access_key = access_key or os.environ.get("AWS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self.session_token = session_token or os.environ.get("AWS_SESSION_TOKEN")
        if not (self.access_key and self.secret_key):
            raise StoreError("S3 credentials are not configured (POLARYS_S3_ACCESS_KEY_ID / AWS_ACCESS_KEY_ID)")
        self.prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""
        if endpoint_url:
            self.base = endpoint_url.rstrip("/")
            self.path_style = True if path_style is None else path_style
        else:
            self.base = f"https://s3.{region}.amazonaws.com"
            self.path_style = False if path_style is None else path_style
        scheme, _, rest = self.base.partition("://")
        self.scheme = scheme
        self.endpoint_host = rest.split("/", 1)[0]
        self.object_lock = object_lock
        self.if_none_match = if_none_match
        self.attempts = attempts
        self.http = http or httpx.Client(timeout=timeout)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @classmethod
    def from_settings(cls, s) -> "S3Store":
        return cls(
            s.s3_bucket,
            region=s.s3_region,
            endpoint_url=s.s3_endpoint_url,
            access_key=s.s3_access_key_id,
            secret_key=s.s3_secret_access_key.get_secret_value() if s.s3_secret_access_key else None,
            session_token=s.s3_session_token,
            prefix=s.s3_prefix,
            path_style=s.s3_path_style,
            object_lock=s.s3_object_lock,
        )

    def _target(self, key: str) -> tuple[str, str, str]:
        """(host, path for signing, full URL)."""
        full_key = self.prefix + validate_key(key)
        if self.path_style:
            host = self.endpoint_host
            path = f"/{self.bucket}/{full_key}"
        else:
            host = f"{self.bucket}.{self.endpoint_host}"
            path = f"/{full_key}"
        return host, path, f"{self.scheme}://{host}{_uri_encode(path, True)}"

    def _request(self, method: str, key: str, body: bytes = b"", headers: dict | None = None) -> httpx.Response:
        host, path, url = self._target(key)
        payload_hash = hashlib.sha256(body).hexdigest() if body else EMPTY_SHA256
        last: Exception | None = None
        for attempt in range(self.attempts):
            amz_date = self.clock().strftime("%Y%m%dT%H%M%SZ")
            signed = sigv4_headers(
                method, host, path, {}, headers or {}, payload_hash,
                access_key=self.access_key, secret_key=self.secret_key, region=self.region,
                amz_date=amz_date, session_token=self.session_token,
            )
            try:
                resp = self.http.request(method, url, content=body if body else None, headers=signed)
            except httpx.HTTPError as e:
                last = e
            else:
                if resp.status_code < 500 and resp.status_code not in (409, 429):
                    return resp
                last = StoreUnavailable(f"S3 {method} {key}: HTTP {resp.status_code} {_s3_error(resp)}")
            if attempt < self.attempts - 1:
                time.sleep(min(0.2 * 2**attempt, 2.0))
        raise StoreUnavailable(f"S3 {method} {key} failed after {self.attempts} attempts: {last}")

    def put(self, key, data, content_type="application/octet-stream", retention: Retention | None = None) -> None:
        headers = {
            "Content-Type": content_type,
            "Content-MD5": base64.b64encode(hashlib.md5(data).digest()).decode(),
        }
        if self.if_none_match:
            headers["If-None-Match"] = "*"
        if self.object_lock and retention:
            if retention.retain_until:
                headers["x-amz-object-lock-mode"] = "COMPLIANCE"
                headers["x-amz-object-lock-retain-until-date"] = retention.retain_until.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                )
            if retention.legal_hold:
                headers["x-amz-object-lock-legal-hold"] = "ON"
        resp = self._request("PUT", key, data, headers)
        if resp.status_code == 412:
            raise ObjectExists(key)
        if resp.status_code != 200:
            raise StoreError(f"S3 PUT {key}: HTTP {resp.status_code} {_s3_error(resp)}")

    def get(self, key: str) -> bytes:
        resp = self._request("GET", key)
        if resp.status_code == 404:
            raise ObjectNotFound(key)
        if resp.status_code != 200:
            raise StoreError(f"S3 GET {key}: HTTP {resp.status_code} {_s3_error(resp)}")
        return resp.content

    def exists(self, key: str) -> bool:
        resp = self._request("HEAD", key)
        if resp.status_code == 404:
            return False
        if resp.status_code != 200:
            raise StoreError(f"S3 HEAD {key}: HTTP {resp.status_code}")
        return True


def _s3_error(resp: httpx.Response) -> str:
    """The S3 error code and message from an XML error body, if any."""
    text = resp.text if resp.content else ""
    parts = []
    for tag in ("Code", "Message"):
        start, end = text.find(f"<{tag}>"), text.find(f"</{tag}>")
        if 0 <= start < end:
            parts.append(text[start + len(tag) + 2 : end])
    return ": ".join(parts)[:200]
