#!/usr/bin/env python3
"""ingest load test: sustained batches against /v1/events/batch, stdlib only

usage:
  python scripts/loadtest.py --endpoint http://127.0.0.1:8001 --key nrk_... \
      --batches 200 --events-per-batch 25 --concurrency 8 [--apps 5]

reports throughput (events/s), latency percentiles, and the error count.
every event is unique (uuid trace/span), spread over --apps applications so
the per-app derived-state fold is exercised the way production traffic would.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import statistics
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime


def make_batch(args: argparse.Namespace, batch_index: int) -> bytes:
    events = []
    app_name = f"loadtest-app-{batch_index % args.apps}"
    for _ in range(args.events_per_batch):
        uid = uuid.uuid4().hex
        events.append(
            {
                "type": "model.call",
                "schema_version": "2026-01",
                "trace_id": f"trc_{uid}",
                "span_id": f"spn_{uid}",
                "timestamp": datetime.now(UTC).isoformat(),
                "service": "loadtest",
                "environment": "prod",
                "project": "loadtest",
                "status": "success",
                "attributes": {
                    "provider": "openai",
                    "model": "gpt-4o",
                    "operation": "chat",
                    "usage": {"input_tokens": 120, "output_tokens": 350},
                    "prompt": {"type": "str", "hash": f"sha256:{uid}", "size": 512},
                    "response": {"type": "str", "hash": f"sha256:{uid[::-1]}", "size": 2048},
                    "metadata": {
                        "tenant_id": args.tenant,
                        "application_name": app_name,
                        "workflow_name": "wf-load",
                    },
                },
            }
        )
    return json.dumps({"events": events}).encode("utf-8")


def post_batch(args: argparse.Namespace, body: bytes) -> tuple[float, int]:
    request = urllib.request.Request(
        f"{args.endpoint.rstrip('/')}/v1/events/batch",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {args.key}"},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
            return time.perf_counter() - started, response.status
    except urllib.error.HTTPError as error:
        error.read()
        return time.perf_counter() - started, error.code
    except Exception:
        return time.perf_counter() - started, 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8001")
    parser.add_argument("--key", required=True, help="ingestion key (nrk_...)")
    parser.add_argument("--tenant", required=True, help="tenant id the key belongs to")
    parser.add_argument("--batches", type=int, default=200)
    parser.add_argument("--events-per-batch", type=int, default=25)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--apps", type=int, default=5)
    args = parser.parse_args()

    bodies = [make_batch(args, index) for index in range(args.batches)]
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(lambda body: post_batch(args, body), bodies))
    wall = time.perf_counter() - started

    latencies = sorted(duration for duration, _ in results)
    errors = sum(1 for _, status in results if status != 200)
    total_events = args.batches * args.events_per_batch

    def pct(p: float) -> float:
        return latencies[min(len(latencies) - 1, int(p * len(latencies)))] * 1000

    print(f"batches={args.batches} events={total_events} concurrency={args.concurrency} apps={args.apps}")
    print(f"wall={wall:.1f}s throughput={total_events / wall:.0f} events/s ({args.batches / wall:.1f} batches/s)")
    print(
        f"batch latency ms: p50={pct(0.50):.0f} p90={pct(0.90):.0f} p99={pct(0.99):.0f} "
        f"max={latencies[-1] * 1000:.0f} mean={statistics.mean(latencies) * 1000:.0f}"
    )
    print(f"errors={errors}")
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
