"""Scope enforcement — the gate every scan must pass before it runs.

The whole point: make it hard to *accidentally* scan something you are not
allowed to. Public/routable targets are refused unless the operator both
lists them in an explicit scope and passes an authorization acknowledgement.
Private, loopback, and documentation ranges are always allowed because they
are, by definition, your own lab.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


class AuthorizationError(PermissionError):
    """Raised when a target is outside the authorized scope."""


def _resolve(target: str) -> str:
    """Resolve a hostname to an IP; pass through literals unchanged."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


def _is_lab_address(ip: str) -> bool:
    """True for ranges that are inherently your own (RFC1918, loopback, etc.)."""
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        # RFC 5737 documentation ranges — used by the bundled demo.
        or addr in ipaddress.ip_network("192.0.2.0/24")
        or addr in ipaddress.ip_network("198.51.100.0/24")
        or addr in ipaddress.ip_network("203.0.113.0/24")
    )


@dataclass
class ScopePolicy:
    """Decides whether a given target may be scanned.

    Parameters
    ----------
    allowed:
        Explicit allow-list of hostnames / IPs / CIDR blocks the operator has
        written down as in-scope for this engagement.
    authorized:
        The operator's explicit acknowledgement (the ``--i-am-authorized``
        flag) that they have permission to test the listed targets. Required
        before any *public* address will be accepted.
    """

    allowed: list[str]
    authorized: bool = False

    def _in_allow_list(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        for entry in self.allowed:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if addr in net:
                    return True
            except ValueError:
                # Entry was a hostname; resolve and compare.
                try:
                    if _resolve(entry) == ip:
                        return True
                except socket.gaierror:
                    continue
        return False

    def check(self, target: str) -> str:
        """Return the resolved IP if the target is in scope, else raise.

        Lab ranges are always permitted. Everything else must be both in the
        allow-list *and* covered by an authorization acknowledgement.
        """
        try:
            ip = _resolve(target)
        except socket.gaierror as exc:
            raise AuthorizationError(f"cannot resolve target {target!r}") from exc

        if _is_lab_address(ip):
            return ip

        if not self.authorized:
            raise AuthorizationError(
                f"{target} ({ip}) is a public address. Refusing to scan without "
                f"an explicit authorization acknowledgement (--i-am-authorized)."
            )
        if not self._in_allow_list(ip):
            raise AuthorizationError(
                f"{target} ({ip}) is not covered by the authorized scope "
                f"{self.allowed!r}. Add it to --scope to proceed."
            )
        return ip
