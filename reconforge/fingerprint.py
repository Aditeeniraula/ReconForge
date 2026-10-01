"""Service identification from banners and probe responses.

Grabs a banner (many services announce themselves on connect, or after a tiny
nudge) and maps it to a service/product/version triple using regex signatures.
"""

from __future__ import annotations

import asyncio
import re

# Ports that expect the client to speak first — we send a minimal, harmless
# nudge to elicit a banner instead of waiting forever.
_NUDGE = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"",   # TLS handled by the dedicated probe; no plaintext nudge.
}

_PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

# (compiled regex, service, product, version-group-name)
_SIGNATURES: list[tuple[re.Pattern, str, str, str | None]] = [
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-](?P<v>[\w.]+)", re.I), "ssh", "OpenSSH", "v"),
    (re.compile(r"SSH-[\d.]+-(?P<p>[\w.]+)", re.I), "ssh", None, None),
    (re.compile(r"Server:\s*nginx/?(?P<v>[\d.]+)?", re.I), "http", "nginx", "v"),
    (re.compile(r"Server:\s*Apache/?(?P<v>[\d.]+)?", re.I), "http", "Apache", "v"),
    (re.compile(r"Server:\s*Microsoft-IIS/?(?P<v>[\d.]+)?", re.I), "http", "IIS", "v"),
    (re.compile(r"Server:\s*Werkzeug/?(?P<v>[\d.]+)?", re.I), "http", "Werkzeug", "v"),
    (re.compile(r"220[- ].*(?P<p>Postfix|Exim|Sendmail)", re.I), "smtp", None, None),
    (re.compile(r"^\+OK.*POP3", re.I), "pop3", None, None),
    (re.compile(r"-ERR wrong number of arguments|redis_version:(?P<v>[\d.]+)", re.I),
     "redis", "Redis", "v"),
    (re.compile(r"MongoDB", re.I), "mongodb", "MongoDB", None),
    (re.compile(r"(?P<v>\d+\.\d+\.\d+).*mysql|mysql_native_password", re.I),
     "mysql", "MySQL", "v"),
]


async def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return None
    data = b""
    try:
        # Many services (SSH, SMTP, FTP) announce themselves on connect. Give
        # them a brief chance before we say anything.
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=0.4)
        except asyncio.TimeoutError:
            data = b""
        # Silent so far? Nudge it — a protocol-specific probe if we have one,
        # otherwise a harmless newline that elicits an error banner from
        # line-oriented services (Redis, Memcached, etc.).
        if not data:
            nudge = _NUDGE.get(port, b"\r\n")
            if nudge:
                writer.write(nudge)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    if not data:
        return None
    return data.decode("latin-1", errors="replace").strip()


def identify(port: int, banner: str | None) -> tuple[str | None, str | None, str | None]:
    """Return (service, product, version) from a banner, falling back to the
    well-known port mapping when the banner is silent."""
    service = _PORT_SERVICE.get(port)
    product = version = None
    if banner:
        for pattern, svc, prod, vgroup in _SIGNATURES:
            m = pattern.search(banner)
            if not m:
                continue
            service = svc or service
            product = prod or (m.groupdict().get("p") if "p" in m.groupdict() else None)
            if vgroup and m.groupdict().get(vgroup):
                version = m.group(vgroup)
            break
    return service, product, version
