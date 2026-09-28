"""The long-running sealer service: leader election, the wall-clock schedule and webhook delivery."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

from .blocks import ChainReport, verify_chain
from .config import Settings
from .delivery import Deliverer
from .keys import KeyRing
from .leader import LeaderLock
from .ledger import Ledger
from .sealer import Sealer
from .tsa import DEFAULT_TSAS, TSAClient, TSAEndpoint, load_certificates
from .util import utcnow

log = logging.getLogger("polarys.service")


def next_boundary(now: datetime, seconds: int) -> datetime:
    """The next wall-clock boundary after ``now`` (multiples of ``seconds`` since midnight UTC)."""
    now = now.astimezone(timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elapsed = (now - midnight).total_seconds()
    return midnight + timedelta(seconds=(int(elapsed // seconds) + 1) * seconds)


def trust_roots(settings: Settings):
    if settings.tsa_trust_roots:
        return load_certificates(settings.tsa_trust_roots.read_bytes())
    return None


def build_tsa_client(settings: Settings, clock=None) -> TSAClient:
    roots = trust_roots(settings)
    if settings.tsa_mode == "dev":
        from .devtsa import DevTSA

        dev = DevTSA.load_or_create(settings.dev_tsa_dir, clock=clock)
        log.warning("using the DEVELOPMENT TSA in %s: its timestamps prove nothing to third parties", settings.dev_tsa_dir)
        return TSAClient([dev.endpoint()], http=httpx.Client(transport=dev.transport()), retry_delay=0,
                         trust_roots=roots or [dev.ca_cert])
    if settings.tsa_urls:
        tsas = []
        for entry in settings.tsa_urls:
            name, sep, url = entry.partition("=")
            tsas.append(TSAEndpoint(name.strip(), url.strip()) if sep else TSAEndpoint(entry, entry))
    else:
        tsas = list(DEFAULT_TSAS)
    return TSAClient(tsas, attempts_per_tsa=settings.tsa_attempts_per_tsa, timeout=settings.tsa_timeout_seconds,
                     trust_roots=roots)


@dataclass
class LedgerChainReport:
    report: ChainReport
    unanchored: list[int]
    checked: int

    @property
    def ok(self) -> bool:
        return self.report.ok if self.checked else not self.report.errors

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "blocks_checked": self.checked,
            "unanchored_blocks": self.unanchored,
            "errors": self.report.errors,
            "blocks": [
                {"block_id": b.block_id, "ok": not b.errors, "errors": b.errors, "warnings": b.warnings,
                 "gen_time": b.gen_time.isoformat().replace("+00:00", "Z") if b.gen_time else None, "tsa": b.tsa}
                for b in self.report.blocks
            ],
        }


def verify_ledger_chain(ledger: Ledger, keyring: KeyRing, roots=None, first: int | None = None, last: int | None = None,
                        check_leaves: bool = True) -> LedgerChainReport:
    """Verify anchored blocks straight from the ledger, recomputing each Merkle root from the ledger's leaf hashes."""
    blocks = ledger.blocks_range(first, last)
    unanchored = [b["block_id"] for b in blocks if b["state"] != "anchored"]
    anchored = [b for b in blocks if b["state"] == "anchored"]
    leaves = {b["block_id"]: [r["leaf_hash"] for r in ledger.block_records(b["block_id"])] for b in anchored} if check_leaves else None
    if not anchored:
        rep = ChainReport()
        if not blocks:
            rep.errors.append("no blocks in range")
        return LedgerChainReport(rep, unanchored, 0)
    rep = verify_chain([(b["header"], b["token"]) for b in anchored], keyring, roots, leaves,
                       expect_genesis=first in (None, 0))
    return LedgerChainReport(rep, unanchored, len(anchored))


def build_sealer_service(settings: Settings) -> tuple["SealerService", Ledger]:
    from .api import build_services
    from .delivery import Deliverer

    svc = build_services(settings)
    sealer = Sealer(
        svc.ledger, svc.store, svc.provider, build_tsa_client(settings), svc.reader,
        restamp_after=timedelta(seconds=settings.restamp_after_seconds),
        max_clock_skew=timedelta(seconds=settings.max_clock_skew_seconds),
    )
    deliverer = Deliverer(svc.ledger, timeout=settings.webhook_timeout_seconds,
                          retry_window=timedelta(hours=settings.webhook_retry_hours), allow_http=settings.allow_http_webhooks)
    lock = LeaderLock.for_database(svc.ledger.db)
    return SealerService(sealer, deliverer, lock, interval_seconds=settings.seal_interval_seconds), svc.ledger


class SealerService:
    """Runs ``Sealer.run_cycle`` at each boundary while holding the leader lock; delivers webhooks in between."""

    def __init__(
        self,
        sealer: Sealer,
        deliverer: Deliverer | None,
        lock: LeaderLock,
        *,
        interval_seconds: int = 300,
        delivery_every: float = 15.0,
        standby_poll: float = 10.0,
        clock=utcnow,
        sleep=time.sleep,
    ):
        self.sealer, self.deliverer, self.lock = sealer, deliverer, lock
        self.interval = interval_seconds
        self.delivery_every = delivery_every
        self.standby_poll = standby_poll
        self.clock, self.sleep = clock, sleep
        self.stop = threading.Event()
        self.is_leader = False
        self.cycles = 0

    def run(self) -> None:
        log.info("sealer service starting (interval %ss)", self.interval)
        try:
            while not self.stop.is_set():
                if not self.lock.acquire():
                    if self.is_leader:
                        log.error("lost the sealer lock; standing by")
                    self.is_leader = False
                    self._wait(self.standby_poll)
                    continue
                if not self.is_leader:
                    self.is_leader = True
                    log.info("acquired the sealer lock; finishing any interrupted work")
                    self._cycle(freeze=False)
                boundary = next_boundary(self.clock(), self.interval)
                while not self.stop.is_set():
                    remaining = (boundary - self.clock()).total_seconds()
                    if remaining <= 0:
                        break
                    self._deliver()
                    self._wait(min(remaining, self.delivery_every))
                if self.stop.is_set():
                    break
                if not self.lock.still_held():
                    continue
                self._cycle(freeze=True)
                self._deliver()
        finally:
            self.lock.release()
            log.info("sealer service stopped")

    def _cycle(self, freeze: bool) -> None:
        try:
            rep = self.sealer.run_cycle(freeze=freeze)
            self.cycles += 1
            level = logging.WARNING if rep.errors or rep.freeze_skipped else logging.INFO
            log.log(level, "cycle: %s", rep.to_dict())
        except Exception:
            log.exception("sealing cycle failed; it will be retried at the next boundary")

    def _deliver(self) -> None:
        if self.deliverer is None:
            return
        try:
            r = self.deliverer.run_once()
            if r.attempted:
                log.info("webhooks: %s", r.__dict__)
        except Exception:
            log.exception("webhook delivery failed")

    def _wait(self, seconds: float) -> None:
        if self.sleep is time.sleep:
            self.stop.wait(seconds)
        else:
            self.sleep(seconds)
