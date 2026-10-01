"""HTTP(S) application-layer fingerprinting.

Pulls the server header, page title, obvious tech tells, and — importantly for
a security assessment — which hardening response headers are *missing*.
"""

from __future__ import annotations

import asyncio
import re
import ssl

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

# Response headers whose absence is itself a finding.
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

# Cheap tech tells keyed off headers / body.
_TECH_TELLS = [
    ("x-powered-by", "PHP", re.compile(r"php", re.I)),
    ("x-powered-by", "Express", re.compile(r"express", re.I)),
    ("x-powered-by", "ASP.NET", re.compile(r"asp\.net", re.I)),
    ("set-cookie", "PHP", re.compile(r"PHPSESSID", re.I)),
    ("set-cookie", "Java", re.compile(r"JSESSIONID", re.I)),
    ("set-cookie", "Django", re.compile(r"csrftoken|sessionid", re.I)),
]


async def probe_http(ip: str, port: int, *, use_tls: bool, timeout: float = 4.0) -> dict | None:
    """Fetch ``GET /`` and summarize server, title, tech, and header hygiene."""
    ssl_ctx = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    try:
        request = (
            f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
            "User-Agent: ReconForge/1.0\r\nConnection: close\r\n\r\n"
        ).encode()
        writer.write(request)
        await writer.drain()
        chunks = []
        while len(b"".join(chunks)) < 65536:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass

    if not raw:
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = _parse_headers(head)

    title_match = _TITLE_RE.search(body)
    title = title_match.group(1).decode("latin-1", "replace").strip() if title_match else None

    tech = set()
    for header, name, pattern in _TECH_TELLS:
        if header in headers and pattern.search(headers[header]):
            tech.add(name)
    if headers.get("server"):
        tech.add(headers["server"].split("/")[0])

    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if not use_tls:
        # HSTS is meaningless over plaintext; don't flag it there.
        missing = [h for h in missing if h != "strict-transport-security"]

    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    return {
        "status": status_line,
        "server": headers.get("server"),
        "title": title[:120] if title else None,
        "tech": sorted(tech),
        "missing_security_headers": missing,
        "powered_by": headers.get("x-powered-by"),
    }


def _parse_headers(head: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return headers
