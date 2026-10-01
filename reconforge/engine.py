"""Scan orchestration — ties the scope gate, scanner, probes, and vuln engine
together into a single async pipeline that produces a HostReport."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from .authorization import ScopePolicy
from .fingerprint import grab_banner, identify
from .http_probe import probe_http
from .models import HostReport, PortResult
from .scanner import scan_ports
from .tls_probe import probe_tls
from .vulndb import VulnDB

_TLS_PORTS = {443, 465, 993, 995, 8443}
_HTTP_PORTS = {80, 3000, 5000, 8000, 8080, 8081, 8888, 9200}


async def _enrich(ip: str, port: int, state: str, latency: float | None) -> PortResult:
    result = PortResult(port=port, state=state, latency_ms=latency)
    if state != "open":
        return result

    banner = await grab_banner(ip, port)
    result.banner = banner
    result.service, result.product, result.version = identify(port, banner)

    if port in _TLS_PORTS:
        result.tls = await probe_tls(ip, port)
        if result.tls:
            result.service = result.service or "https"
            result.http = await probe_http(ip, port, use_tls=True)
    elif port in _HTTP_PORTS or (result.service == "http"):
        result.http = await probe_http(ip, port, use_tls=False)
        if result.http and not result.product and result.http.get("server"):
            result.product = result.http["server"].split("/")[0]

    return result


async def assess_host(
    target: str,
    policy: ScopePolicy,
    *,
    ports: list[int] | None = None,
    concurrency: int = 200,
    timeout: float = 1.5,
    vulndb: VulnDB | None = None,
) -> HostReport:
    """Run the full pipeline against one target. Raises AuthorizationError if
    the target is out of scope — nothing is sent until the gate passes."""
    ip = policy.check(target)                       # scope gate first, always.
    vulndb = vulndb or VulnDB()

    scanned = await scan_ports(ip, ports, concurrency=concurrency, timeout=timeout)
    enriched = await asyncio.gather(
        *(_enrich(ip, port, state, latency) for port, state, latency in scanned)
    )

    report = HostReport(
        target=target,
        resolved_ip=ip,
        scanned_at=datetime.now(timezone.utc),
        ports=list(enriched),
    )
    for port in report.open_ports:
        report.findings.extend(vulndb.evaluate(port))
    report.findings.sort(key=lambda f: -f.severity.rank)
    return report
