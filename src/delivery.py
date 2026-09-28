"""Webhook delivery of receipts.

When a receipt is issued for a record whose API key has a webhook URL, the
receipt is POSTed there as canonical JSON with these headers:

    Content-Type:         application/json
    X-Polarys-Event:      receipt.ready
    X-Polarys-Delivery:   <record_id>
    X-Polarys-Timestamp:  <unix seconds>
    X-Polarys-Signature:  v1=<hex HMAC-SHA256(webhook secret, "<timestamp>." + body)>

Any 2xx response counts as delivered.  Failures are retried with exponential
backoff (1, 2, 4 … minutes, at most hourly) for 24 hours after the receipt was
issued, then given up; the receipt stays available from
``GET /v1/records/{id}/receipt`` either way.  Receivers should check the
signature with ``verify_signature`` (or its equivalent) and reject timestamps
more than five minutes old.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from datetime import timedelta

import httpx

from . import __version__
from .jcs import canonicalize
from .ledger import Ledger
from .util import utcnow

log = logging.getLogger("polarys.delivery")


def sign_payload(secret: str, timestamp: int, body: bytes) -> str:
    return "v1=" + hmac.new(secret.encode(), str(timestamp).encode() + b"." + body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, timestamp: str, body: bytes, signature: str, tolerance: int = 300, now: float | None = None) -> bool:
    """Receiver-side check of ``X-Polarys-Signature`` and ``X-Polarys-Timestamp``."""
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now if now is not None else time.time()) - ts) > tolerance:
        return False
    return hmac.compare_digest(sign_payload(secret, ts, body), signature)


def check_webhook_url(url: str, allow_http: bool = False) -> None:
    u = httpx.URL(url)
    if u.scheme not in ("https", "http") or not u.host:
        raise ValueError("webhook URL must be an absolute http(s) URL")
    if u.scheme == "http" and not allow_http:
        raise ValueError("webhook URL must use https (set POLARYS_ALLOW_HTTP_WEBHOOKS=true for development)")


@dataclass
class DeliveryReport:
    attempted: int = 0
    delivered: int = 0
    failed: int = 0
    gave_up: int = 0


class Deliverer:
    def __init__(
        self,
        ledger: Ledger,
        *,
        http: httpx.Client | None = None,
        timeout: float = 10.0,
        retry_window: timedelta = timedelta(hours=24),
        allow_http: bool = False,
        clock=utcnow,
        batch: int = 100,
    ):
        self.ledger = ledger
        self.http = http or httpx.Client(timeout=timeout, follow_redirects=False)
        self.retry_window = retry_window
        self.allow_http = allow_http
        self.clock = clock
        self.batch = batch

    @staticmethod
    def backoff(attempts: int) -> timedelta:
        """Delay after the ``attempts``-th failure: 1, 2, 4 … minutes, capped at one hour."""
        return timedelta(seconds=min(60 * 2 ** max(attempts - 1, 0), 3600))

    def run_once(self) -> DeliveryReport:
        rep = DeliveryReport()
        while True:
            due = self.ledger.due_deliveries(self.clock(), self.batch)
            if not due:
                return rep
            for d in due:
                rep.attempted += 1
                ok, error = self._post(d)
                now = self.clock()
                if ok:
                    self.ledger.mark_delivered(d["record_id"], now)
                    rep.delivered += 1
                    continue
                attempts = d["attempts"] + 1
                nxt = now + self.backoff(attempts)
                if nxt > d["created_at"] + self.retry_window:
                    self.ledger.mark_delivery_failed(d["record_id"], error, None)
                    rep.gave_up += 1
                    log.warning("gave up delivering receipt %s to %s: %s", d["record_id"], d["url"], error)
                else:
                    self.ledger.mark_delivery_failed(d["record_id"], error, nxt)
                    rep.failed += 1
            if len(due) < self.batch:
                return rep

    def _post(self, d: dict) -> tuple[bool, str]:
        if not d.get("secret"):
            return False, "API key has a webhook URL but no webhook secret"
        try:
            check_webhook_url(d["url"], self.allow_http)
        except ValueError as e:
            return False, str(e)
        body = canonicalize(d["receipt"])
        ts = int(self.clock().timestamp())
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"polarys/{__version__}",
            "X-Polarys-Event": "receipt.ready",
            "X-Polarys-Delivery": d["record_id"],
            "X-Polarys-Timestamp": str(ts),
            "X-Polarys-Signature": sign_payload(d["secret"], ts, body),
        }
        try:
            r = self.http.post(d["url"], content=body, headers=headers)
        except httpx.HTTPError as e:
            return False, f"{type(e).__name__}: {e}"
        if 200 <= r.status_code < 300:
            return True, ""
        return False, f"HTTP {r.status_code}"
