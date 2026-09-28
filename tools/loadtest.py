"""Load test for a running POLARYS API.

    python tools/loadtest.py --url http://127.0.0.1:8080 --token plk_… --rate 100 --seconds 20 --concurrency 16
    python tools/loadtest.py … --batch 500 --batches 10

Sends records at a fixed rate (open-loop, so slow responses do not hide
latency) and reports achieved throughput and latency percentiles.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time

import httpx


def pct(values: list[float], p: float) -> float:
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))]


async def single(args) -> None:
    headers = {"Authorization": f"Bearer {args.token}"}
    lat, errors, sent = [], 0, 0
    sem = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(base_url=args.url, headers=headers, timeout=30) as client:

        async def one(i: int):
            nonlocal errors
            body = {"record_class": args.record_class, "data": {"seq": i, "msg": "load test " + "x" * args.size}}
            async with sem:
                t0 = time.perf_counter()
                r = await client.post("/v1/records", json=body)
                lat.append((time.perf_counter() - t0) * 1000)
                if r.status_code != 201:
                    errors += 1

        tasks, start = [], time.perf_counter()
        interval = 1 / args.rate
        while time.perf_counter() - start < args.seconds:
            tasks.append(asyncio.create_task(one(sent)))
            sent += 1
            await asyncio.sleep(max(0, start + sent * interval - time.perf_counter()))
        await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start
    report(f"single records at {args.rate}/s target", sent, errors, elapsed, lat)


async def batches(args) -> None:
    headers = {"Authorization": f"Bearer {args.token}"}
    lat, errors, total = [], 0, 0
    async with httpx.AsyncClient(base_url=args.url, headers=headers, timeout=120) as client:
        start = time.perf_counter()
        for b in range(args.batches):
            recs = [{"record_class": args.record_class, "text": f"batch {b} item {i} " + "x" * args.size} for i in range(args.batch)]
            t0 = time.perf_counter()
            r = await client.post("/v1/records:batch", json={"records": recs})
            lat.append((time.perf_counter() - t0) * 1000)
            body = r.json()
            errors += body.get("rejected", len(recs)) if r.status_code == 200 else len(recs)
            total += len(recs)
        elapsed = time.perf_counter() - start
    report(f"batches of {args.batch}", total, errors, elapsed, lat, per="batch")


def report(title, n, errors, elapsed, lat, per="request"):
    print(json.dumps({
        "test": title,
        "records": n,
        "errors": errors,
        "seconds": round(elapsed, 2),
        "records_per_second": round(n / elapsed, 1),
        f"latency_ms_per_{per}": {
            "p50": round(statistics.median(lat), 1),
            "p95": round(pct(lat, 95), 1),
            "p99": round(pct(lat, 99), 1),
            "max": round(max(lat), 1),
        },
    }, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--token", required=True)
    ap.add_argument("--record-class", default="correspondence")
    ap.add_argument("--rate", type=float, default=50)
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--size", type=int, default=200, help="extra payload bytes per record")
    ap.add_argument("--batch", type=int, default=0)
    ap.add_argument("--batches", type=int, default=10)
    args = ap.parse_args()
    asyncio.run(batches(args) if args.batch else single(args))


if __name__ == "__main__":
    main()
