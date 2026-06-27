"""Data models for scanned networks and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        order = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return order[self.value]


@dataclass
class Finding:
    """A single security observation about a network."""

    severity: Severity
    title: str
    detail: str


@dataclass
class AccessPoint:
    """A single BSSID (radio) belonging to a network."""

    bssid: str
    signal_pct: int | None = None
    radio_type: str | None = None
    band: str | None = None
    channel: int | None = None


@dataclass
class Network:
    """A wireless network (SSID) and the access points advertising it."""

    ssid: str
    authentication: str = ""
    encryption: str = ""
    network_type: str = ""
    access_points: list[AccessPoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_hidden(self) -> bool:
        return self.ssid.strip() == ""

    @property
    def display_ssid(self) -> str:
        return self.ssid if not self.is_hidden else "<hidden>"

    @property
    def best_signal(self) -> int | None:
        signals = [ap.signal_pct for ap in self.access_points if ap.signal_pct is not None]
        return max(signals) if signals else None

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
