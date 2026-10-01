"""TLS certificate and protocol inspection.

Completes a handshake, then reports the negotiated protocol version, cipher,
and certificate details — including whether the cert is expired or expiring
soon, which the vuln engine turns into findings.
"""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone


def _parse_cert_time(value: str) -> datetime | None:
    # OpenSSL format, e.g. "Aug  7 12:00:00 2027 GMT"
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


async def probe_tls(ip: str, port: int, *, timeout: float = 4.0) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None

    ssl_obj = writer.get_extra_info("ssl_object")
    result: dict = {}
    if ssl_obj is not None:
        result["protocol"] = ssl_obj.version()
        cipher = ssl_obj.cipher()
        result["cipher"] = cipher[0] if cipher else None
        cert = ssl_obj.getpeercert()
        if cert:
            result.update(_summarize_cert(cert))
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ssl.SSLError):
        pass
    return result or None


def _summarize_cert(cert: dict) -> dict:
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_after = _parse_cert_time(cert.get("notAfter", ""))
    days_left = None
    if not_after:
        days_left = (not_after - datetime.now(timezone.utc)).days
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    return {
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "not_after": cert.get("notAfter"),
        "days_until_expiry": days_left,
        "self_signed": subject == issuer,
        "san": sans[:10],
    }
