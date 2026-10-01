"""A harmless local target so you can watch ReconForge work end-to-end.

It binds a few loopback ports and serves canned banners that trip the
detectors: an old OpenSSH string, an unauthenticated-Redis reply, and an HTTP
server missing its security headers. Nothing here is a real service.

    python demo_target.py            # runs until Ctrl-C
"""

from __future__ import annotations

import asyncio

# port -> (immediate banner bytes, reply-to-any-input bytes)
BANNERS: dict[int, tuple[bytes, bytes]] = {
    2222: (b"SSH-2.0-OpenSSH_7.4\r\n", b""),
    6380: (b"", b"-ERR wrong number of arguments for 'get' command\r\n"),
}

HTTP_PORT = 8088
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.18.0\r\n"
    b"Content-Type: text/html\r\n"
    b"X-Powered-By: PHP/7.2.1\r\n"
    b"Connection: close\r\n\r\n"
    b"<html><head><title>Acme Intranet Portal</title></head>"
    b"<body><h1>Internal</h1></body></html>"
)


def _make_banner_handler(port: int):
    immediate, reply = BANNERS[port]

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
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

    return handler


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        await asyncio.wait_for(reader.read(2048), timeout=1.0)
    except (asyncio.TimeoutError, OSError):
        pass
    writer.write(HTTP_RESPONSE)
    await writer.drain()
    writer.close()


async def main() -> None:
    servers = []
    for port in BANNERS:
        srv = await asyncio.start_server(_make_banner_handler(port), "127.0.0.1", port)
        servers.append(srv)
        print(f"[demo] listening on 127.0.0.1:{port}")
    http_srv = await asyncio.start_server(_http_handler, "127.0.0.1", HTTP_PORT)
    servers.append(http_srv)
    print(f"[demo] listening on 127.0.0.1:{HTTP_PORT} (http)")
    print("[demo] scan me:  python -m reconforge 127.0.0.1 "
          "--ports 2222,6380,8088 --html report.html")
    async with asyncio.TaskGroup() as tg:
        for srv in servers:
            tg.create_task(srv.serve_forever())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[demo] stopped")
