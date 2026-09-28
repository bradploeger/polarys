"""Shared fixtures for the unittest suite (no third-party test runner needed)."""

from __future__ import annotations

import functools
import tempfile
from datetime import datetime, timedelta, timezone

import httpx

from polarys.classes import ClassRegistry
from polarys.devtsa import DevTSA
from polarys.keys import LocalKeyProvider
from polarys.records import Submitter, new_record, sign_record
from polarys.sealing import OpenInterval, interval_bounds, seal
from polarys.tsa import TSAClient

T0 = datetime(2026, 9, 26, 19, 0, 30, tzinfo=timezone.utc)
DEVICE = Submitter("device", "fw01.example.com", "tls-syslog")
USER = Submitter("user", "alice@example.com", "oidc", "Alice")


@functools.lru_cache(maxsize=None)
def provider() -> LocalKeyProvider:
    return LocalKeyProvider.create(tempfile.mkdtemp() + "/ks", "test-passphrase")


class Clock:
    def __init__(self, t: datetime):
        self.t = t

    def __call__(self) -> datetime:
        return self.t


def dev_tsa(clock=None) -> tuple[DevTSA, TSAClient]:
    dev = DevTSA.create(clock=clock)
    return dev, TSAClient([dev.endpoint()], http=httpx.Client(transport=dev.transport()), retry_delay=0)


def make_record(i: int, when: datetime, *, user: bool = False, prov=None):
    reg = ClassRegistry()
    env = new_record(
        reg,
        source_type="api" if user else "syslog",
        submitter=USER if user else DEVICE,
        payload=f"record {i}".encode(),
        content_type="text/plain",
        received_at=when,
        requested_class="correspondence" if user else None,
        attributes={} if user else {"severity": 6},
    )
    return sign_record(env, prov or provider())


def build_chain(n_blocks: int = 3, per_block: int = 3, prov=None):
    """Seal ``n_blocks`` consecutive blocks; returns (blocks, dev_tsa)."""
    prov = prov or provider()
    clock = Clock(T0)
    dev, client = dev_tsa(clock)
    blocks, prev = [], None
    for b in range(n_blocks):
        t = T0 + timedelta(minutes=5 * b)
        start, end = interval_bounds(t)
        iv = OpenInterval(start, end)
        for i in range(per_block):
            iv.add(make_record(i, t + timedelta(seconds=i), user=(i % 2 == 0), prov=prov))
        clock.t = end + timedelta(seconds=2)
        prev = seal(iv, block_id=b, prev=prev, provider=prov, tsa=client, created_at=end + timedelta(seconds=1))
        blocks.append(prev)
    return blocks, dev
