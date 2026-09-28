"""Generate a small sample ledger for trying ``logverify``.

Creates a keystore, a development TSA, and three sealed blocks containing
syslog device logs, an API-submitted invoice and a multi-document tax-return
upload, laid out like the object store, with receipts for the API and upload
submitters.  Everything is timestamped by the development TSA, so the output
demonstrates the formats but proves nothing to a third party.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from .classes import ClassRegistry
from .devtsa import DevTSA
from .keys import LocalKeyProvider
from .manifest import MANIFEST_CONTENT_TYPE, Document, build_manifest, manifest_payload
from .records import Submitter, new_record, sign_record
from .sealing import DirectoryStore, OpenInterval, interval_bounds, receipts_for, seal
from .tsa import TSAClient


def build_demo(out: str | Path, passphrase: str = "demo-passphrase") -> dict:
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} is not empty")
    out.mkdir(parents=True, exist_ok=True)

    provider = LocalKeyProvider.create(out / "keystore", passphrase)
    registry = ClassRegistry()
    base = datetime.now(timezone.utc) - timedelta(minutes=16)
    clock = {"now": base}
    dev = DevTSA.create(clock=lambda: clock["now"])
    tsa = TSAClient([dev.endpoint()], http=httpx.Client(transport=dev.transport()), retry_delay=0)
    store = DirectoryStore(out / "store", provider)

    router = Submitter("device", "core-rtr-01.nyc.example.com", "tls-syslog")
    dc = Submitter("device", "dc01.corp.example.com", "mtls")
    ap_bot = Submitter("user", "ap-integration@example.com", "oauth2-client", "AP integration")
    brad = Submitter("user", "controller@example.com", "oidc", "Controller")

    docs = [
        Document("form-1120-2025.pdf", "application/pdf", b"%PDF-1.7 sample corporate return 2025\n"),
        Document("schedule-l.pdf", "application/pdf", b"%PDF-1.7 sample schedule L\n"),
        Document("signature-page.pdf", "application/pdf", b"%PDF-1.7 sample signature page\n"),
    ]
    manifest = build_manifest("2025 corporate income tax return", "tax_returns", docs)

    plan = [
        [
            ("syslog", router, b"<189>1 2026-09-26T19:00:01Z core-rtr-01 sshd - - - Accepted publickey for netops", "text/syslog", None, {"severity": 5}),
            ("syslog", router, b"<180>1 2026-09-26T19:00:04Z core-rtr-01 kernel - - - link eth2 down", "text/syslog", None, {"severity": 4}),
            ("windows_event", dc, json.dumps({"Channel": "Security", "EventID": 4625, "Computer": "dc01"}).encode(), "application/json", None, {"security": True}),
        ],
        [
            ("api", ap_bot, json.dumps({"invoice": "INV-10442", "customer": "Contoso", "amount": "1250.00", "currency": "USD"}).encode(), "application/json", "sales_invoices", {}),
            ("syslog", router, b"<190>1 2026-09-26T19:05:30Z core-rtr-01 ntpd - - - clock synchronised", "text/syslog", None, {"severity": 6}),
        ],
        [
            ("upload", brad, manifest_payload(manifest), MANIFEST_CONTENT_TYPE, "tax_returns", {}),
        ],
    ]

    prev = None
    summary = {"blocks": [], "receipts": []}
    for block_id, items in enumerate(plan):
        t = base + timedelta(minutes=5 * block_id, seconds=30)
        start, end = interval_bounds(t)
        interval = OpenInterval(start, end)
        for i, (src, sub, payload, ctype, cls, attrs) in enumerate(items):
            env = new_record(
                registry,
                source_type=src,
                submitter=sub,
                payload=payload,
                content_type=ctype,
                received_at=t + timedelta(seconds=i),
                requested_class=cls,
                attributes=attrs,
                origin={"host": sub.id} if sub.type == "device" else {"client": sub.id},
            )
            interval.add(sign_record(env, provider))
        clock["now"] = end + timedelta(seconds=2)
        block = seal(interval, block_id=block_id, prev=prev, provider=provider, tsa=tsa, created_at=end + timedelta(seconds=1))
        store.write_block(block, interval)
        receipts = receipts_for(block, provider)
        store.write_receipts(receipts)
        summary["blocks"].append({"block_id": block_id, "entries": block.header["entry_count"], "hash": block.hash.hex()})
        summary["receipts"] += [f"store/receipts/{rid}.json" for rid in receipts]
        prev = block

    (out / "log-keys.json").write_text(json.dumps(provider.keyring().to_document(), indent=2))
    (out / "dev-tsa-root.pem").write_bytes(dev.ca_pem())
    doc_dir = out / "documents"
    doc_dir.mkdir()
    for d in docs:
        (doc_dir / d.name).write_bytes(d.data)
    (out / "README.txt").write_text(
        "POLARYS demo ledger (development TSA; not evidence of anything).\n\n"
        "Verify the chain:\n  logverify chain store --keys log-keys.json --tsa-ca dev-tsa-root.pem\n\n"
        "Verify a receipt (the tax-return upload, with its documents):\n"
        f"  logverify receipt {summary['receipts'][-1]} --keys log-keys.json --tsa-ca dev-tsa-root.pem \\\n"
        "      --document documents/form-1120-2025.pdf --document documents/schedule-l.pdf --document documents/signature-page.pdf\n\n"
        f"Keystore passphrase: {passphrase}\n"
    )
    return summary
