"""Data models shared across the scanner, probes, and reporting layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class PortResult:
    """One TCP port's state plus anything the probes learned about it."""

    port: int
    state: str                       # "open" | "closed" | "filtered"
    service: str | None = None       # e.g. "http", "ssh", "smtp"
    product: str | None = None       # e.g. "OpenSSH", "nginx"
    version: str | None = None       # e.g. "7.4", "1.18.0"
    banner: str | None = None
    tls: dict | None = None          # certificate / protocol details
    http: dict | None = None         # server header, title, tech, security headers
    latency_ms: float | None = None


@dataclass
class Finding:
    """A potential weakness surfaced by the vuln-matching engine."""

    title: str
    severity: Severity
    port: int
    service: str
    evidence: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    cve: str | None = None


@dataclass
class HostReport:
    target: str
    resolved_ip: str
    scanned_at: datetime
    ports: list[PortResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
