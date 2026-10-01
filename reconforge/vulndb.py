"""Vulnerability matching engine.

Turns probe results (versions, exposed services, TLS state, HTTP hygiene) into
Findings using a JSON signature database plus a few built-in heuristics that
don't fit a static rule.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, PortResult, Severity

_DATA = Path(__file__).resolve().parent.parent / "data" / "vuln_signatures.json"


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for chunk in v.split("."):
        num = "".join(c for c in chunk if c.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts)


def _lte(a: str, b: str) -> bool:
    """True if version a <= version b, compared component-wise."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    return ta <= tb


class VulnDB:
    def __init__(self, path: Path | str = _DATA):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.version_rules = data.get("version_rules", [])
        self.service_rules = data.get("service_rules", [])

    def evaluate(self, port: PortResult) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._version_findings(port)
        findings += self._service_findings(port)
        findings += self._tls_findings(port)
        findings += self._http_findings(port)
        return findings

    def _version_findings(self, port: PortResult) -> list[Finding]:
        if not (port.product and port.version):
            return []
        out = []
        for rule in self.version_rules:
            if rule["product"].lower() != port.product.lower():
                continue
            if _lte(port.version, rule["max_version"]):
                out.append(Finding(
                    title=rule["title"],
                    severity=Severity(rule["severity"]),
                    port=port.port,
                    service=port.service or "unknown",
                    evidence=f"{port.product} {port.version} <= {rule['max_version']}",
                    recommendation=rule["recommendation"],
                    references=rule.get("references", []),
                    cve=rule.get("cve"),
                ))
        return out

    def _service_findings(self, port: PortResult) -> list[Finding]:
        out = []
        for rule in self.service_rules:
            if rule["service"] != port.service:
                continue
            # "unauthenticated" rules only fire when the banner shows the
            # tell-tale no-auth response; "exposed" rules fire on presence.
            if rule["condition"] == "unauthenticated":
                banner = (port.banner or "").lower()
                if "noauth" not in banner and "wrong number of arguments" not in banner \
                        and "redis_version" not in banner:
                    continue
            out.append(Finding(
                title=rule["title"],
                severity=Severity(rule["severity"]),
                port=port.port,
                service=port.service,
                evidence=(port.banner or f"{port.service} reachable on port {port.port}")[:160],
                recommendation=rule["recommendation"],
                references=rule.get("references", []),
            ))
        return out

    def _tls_findings(self, port: PortResult) -> list[Finding]:
        if not port.tls:
            return []
        out = []
        proto = port.tls.get("protocol") or ""
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            out.append(Finding(
                title=f"Deprecated TLS protocol {proto} negotiated",
                severity=Severity.MEDIUM,
                port=port.port,
                service=port.service or "tls",
                evidence=f"Negotiated {proto} with cipher {port.tls.get('cipher')}",
                recommendation="Disable TLS < 1.2; require TLS 1.2+ with modern ciphers.",
                references=[],
            ))
        days = port.tls.get("days_until_expiry")
        if days is not None and days < 0:
            out.append(Finding(
                title="Expired TLS certificate",
                severity=Severity.HIGH,
                port=port.port,
                service=port.service or "tls",
                evidence=f"Certificate expired {abs(days)} day(s) ago ({port.tls.get('not_after')})",
                recommendation="Renew the certificate; expired certs break trust and availability.",
                references=[],
            ))
        elif days is not None and days < 21:
            out.append(Finding(
                title="TLS certificate expiring soon",
                severity=Severity.LOW,
                port=port.port,
                service=port.service or "tls",
                evidence=f"Certificate expires in {days} day(s)",
                recommendation="Renew before expiry to avoid an outage.",
                references=[],
            ))
        if port.tls.get("self_signed"):
            out.append(Finding(
                title="Self-signed TLS certificate",
                severity=Severity.LOW,
                port=port.port,
                service=port.service or "tls",
                evidence=f"Subject equals issuer ({port.tls.get('subject_cn')})",
                recommendation="Use a certificate from a trusted CA for anything user-facing.",
                references=[],
            ))
        return out

    def _http_findings(self, port: PortResult) -> list[Finding]:
        if not port.http:
            return []
        missing = port.http.get("missing_security_headers", [])
        if not missing:
            return []
        severity = Severity.LOW if len(missing) < 3 else Severity.MEDIUM
        return [Finding(
            title=f"Missing HTTP security headers ({len(missing)})",
            severity=severity,
            port=port.port,
            service=port.service or "http",
            evidence="Absent: " + ", ".join(missing),
            recommendation="Add the missing hardening headers at the web server or app layer.",
            references=["https://owasp.org/www-project-secure-headers/"],
        )]
