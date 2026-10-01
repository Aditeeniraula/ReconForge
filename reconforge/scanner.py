"""Asynchronous TCP connect scanner.

Uses asyncio to fan out non-blocking connect() attempts with a bounded
concurrency semaphore, so scanning a wide port range stays fast without
exhausting file descriptors. Distinguishes closed (refused) from filtered
(timed out) the way a connect-scan realistically can.
"""

from __future__ import annotations

import asyncio
import time

# Compact, high-signal default set — the ports worth looking at first.
DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
    587, 631, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000,
    5432, 5601, 5900, 5985, 6379, 7001, 8000, 8080, 8081, 8443, 8888,
    9000, 9200, 11211, 27017,
]


async def _probe_port(
    ip: str, port: int, timeout: float, sem: asyncio.Semaphore
) -> tuple[int, str, float | None]:
    async with sem:
        start = time.perf_counter()
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            return port, "filtered", None
        except (ConnectionRefusedError, OSError):
            return port, "closed", None
        latency = (time.perf_counter() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return port, "open", latency


async def scan_ports(
    ip: str,
    ports: list[int] | None = None,
    *,
    concurrency: int = 200,
    timeout: float = 1.5,
) -> list[tuple[int, str, float | None]]:
    """Scan ``ports`` on ``ip``; returns (port, state, latency_ms) tuples.

    Only open/filtered results are returned — closed ports are dropped to keep
    the result set focused on what matters.
    """
    ports = ports or DEFAULT_PORTS
    sem = asyncio.Semaphore(concurrency)
    tasks = [_probe_port(ip, p, timeout, sem) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(
        (r for r in results if r[1] != "closed"),
        key=lambda r: r[0],
    )
