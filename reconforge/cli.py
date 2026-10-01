"""Command-line entry point.

    python -m reconforge <target> [options]

Examples
--------
    python -m reconforge 127.0.0.1 --top --html report.html
    python -m reconforge scanme.example.com --scope scanme.example.com --i-am-authorized
    python -m reconforge 10.0.0.5 --ports 22,80,443,8080 --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .authorization import AuthorizationError, ScopePolicy
from .engine import assess_host
from .report import to_html, to_json, to_text
from .scanner import DEFAULT_PORTS


def _parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconforge",
        description="Authorized network recon & vulnerability assessment.",
    )
    p.add_argument("target", help="hostname or IP to assess")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--ports", type=_parse_ports, help="comma/range list, e.g. 22,80,8000-8100")
    g.add_argument("--top", action="store_true", help="scan the built-in high-signal port set (default)")
    g.add_argument("--all", action="store_true", help="scan all 65535 TCP ports (slow)")
    p.add_argument("--scope", action="append", default=[],
                   help="in-scope host/IP/CIDR (repeatable); required for public targets")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="acknowledge you have written permission to test public targets")
    p.add_argument("--concurrency", type=int, default=200, help="max simultaneous connects")
    p.add_argument("--timeout", type=float, default=1.5, help="per-port connect timeout (s)")
    p.add_argument("--json", metavar="PATH", help="write JSON report to PATH")
    p.add_argument("--html", metavar="PATH", help="write HTML report to PATH")
    return p


async def _run(args: argparse.Namespace) -> int:
    if args.all:
        ports = list(range(1, 65536))
    elif args.ports:
        ports = args.ports
    else:
        ports = DEFAULT_PORTS

    policy = ScopePolicy(allowed=args.scope, authorized=args.i_am_authorized)
    try:
        report = await assess_host(
            args.target, policy,
            ports=ports, concurrency=args.concurrency, timeout=args.timeout,
        )
    except AuthorizationError as exc:
        print(f"[scope] refused: {exc}", file=sys.stderr)
        return 2

    print(to_text(report))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(report))
        print(f"\n[+] JSON report written to {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(report))
        print(f"[+] HTML report written to {args.html}")
    # Non-zero exit if anything high/critical was found — handy in CI pipelines.
    return 1 if report.max_severity.rank >= 3 else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
