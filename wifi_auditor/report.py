"""Render audit results as plain text or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .models import Network, Severity

_BARS = {
    Severity.INFO: "·",
    Severity.LOW: "▪",
    Severity.MEDIUM: "▴",
    Severity.HIGH: "✖",
    Severity.CRITICAL: "‼",
}


def _signal_bar(pct: int | None) -> str:
    if pct is None:
        return "   ?"
    filled = round(pct / 25)
    return "▁▂▄█"[: max(filled, 1)].ljust(4)


def to_text(networks: list[Network]) -> str:
    if not networks:
        return "No networks found in range."

    ordered = sorted(
        networks,
        key=lambda n: (-n.worst_severity.rank, -(n.best_signal or 0)),
    )

    lines: list[str] = []
    lines.append(f"Found {len(networks)} network(s). Sorted by risk, then signal.\n")

    for net in ordered:
        sev = net.worst_severity
        sig = net.best_signal
        sig_str = f"{sig:>3}%" if sig is not None else "  ?%"
        lines.append(
            f"{_BARS[sev]} [{sev.value:<8}] {net.display_ssid}   "
            f"signal {sig_str}  auth {net.authentication or '?'}/"
            f"{net.encryption or '?'}"
        )
        bands = sorted({ap.band for ap in net.access_points if ap.band})
        if bands:
            lines.append(f"      bands: {', '.join(bands)}  "
                         f"({len(net.access_points)} radio(s))")
        for f in sorted(net.findings, key=lambda x: -x.severity.rank):
            lines.append(f"      - [{f.severity.value}] {f.title}: {f.detail}")
        lines.append("")

    # Summary
    counts: dict[str, int] = {}
    for net in networks:
        for f in net.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    summary = "  ".join(
        f"{sev.value}={counts.get(sev.value, 0)}"
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFO]
    )
    lines.append(f"Findings summary: {summary}")
    return "\n".join(lines)


def to_json(networks: list[Network]) -> str:
    payload = []
    for net in networks:
        d = asdict(net)
        d["display_ssid"] = net.display_ssid
        d["best_signal"] = net.best_signal
        d["worst_severity"] = net.worst_severity.value
        payload.append(d)
    return json.dumps(payload, indent=2, default=str)
