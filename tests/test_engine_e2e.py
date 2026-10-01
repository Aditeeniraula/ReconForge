"""End-to-end: stand up throwaway loopback servers, scan them, assert findings."""

import asyncio

import pytest

from reconforge.authorization import ScopePolicy
from reconforge.engine import assess_host
from reconforge.models import Severity


async def _serve(port: int, immediate: bytes, reply: bytes):
    async def handler(reader, writer):
        if immediate:
            writer.write(immediate)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            if data and reply:
                writer.write(reply)
                await writer.drain()
        except (asyncio.TimeoutError, OSError):
            pass
        writer.close()
    return await asyncio.start_server(handler, "127.0.0.1", port)


@pytest.mark.asyncio
async def test_scan_detects_old_openssh_and_redis():
    ssh = await _serve(2223, b"SSH-2.0-OpenSSH_7.4\r\n", b"")
    redis = await _serve(6381, b"", b"-ERR wrong number of arguments\r\n")
    async with ssh, redis:
        policy = ScopePolicy(allowed=[], authorized=False)
        report = await assess_host(
            "127.0.0.1", policy, ports=[2223, 6381], timeout=1.0
        )

    open_ports = {p.port for p in report.open_ports}
    assert {2223, 6381} <= open_ports

    ssh_port = next(p for p in report.ports if p.port == 2223)
    assert ssh_port.product == "OpenSSH"
    assert ssh_port.version == "7.4"

    titles = {f.title for f in report.findings}
    assert any("OpenSSH" in t for t in titles)
    assert any("Redis" in t for t in titles)
    assert report.max_severity.rank >= Severity.HIGH.rank


@pytest.mark.asyncio
async def test_closed_ports_produce_no_findings():
    policy = ScopePolicy(allowed=[], authorized=False)
    report = await assess_host("127.0.0.1", policy, ports=[59999], timeout=0.5)
    assert report.open_ports == []
    assert report.findings == []
