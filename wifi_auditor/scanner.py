"""
Passive network scanner.

Uses the operating system's built-in wireless utilities to enumerate
networks that are already being broadcast in range. This is the same
information any device sees when you open the WiFi menu — no connection
or authentication is performed.

Currently supports Windows (netsh). Linux/macOS parsers can be added the
same way; each returns a list[Network].
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess

from .models import AccessPoint, Network


class ScannerError(RuntimeError):
    pass


def _run(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"scan timed out: {' '.join(cmd)}") from exc
    if proc.returncode != 0 and not proc.stdout:
        raise ScannerError(proc.stderr.strip() or f"{cmd[0]} failed")
    return proc.stdout


def _parse_int(value: str) -> int | None:
    m = re.search(r"-?\d+", value)
    return int(m.group()) if m else None


def _band_from_channel(channel: int | None) -> str | None:
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    return None


def parse_netsh(output: str) -> list[Network]:
    """Parse the output of `netsh wlan show networks mode=bssid`."""
    networks: list[Network] = []
    current: Network | None = None
    current_ap: AccessPoint | None = None

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue

        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_match:
            current = Network(ssid=ssid_match.group(1).strip())
            current_ap = None
            networks.append(current)
            continue

        if current is None:
            continue

        if line.startswith("Network type"):
            current.network_type = line.split(":", 1)[1].strip()
        elif line.startswith("Authentication"):
            current.authentication = line.split(":", 1)[1].strip()
        elif line.startswith("Encryption"):
            current.encryption = line.split(":", 1)[1].strip()
        elif line.startswith("BSSID"):
            bssid = line.split(":", 1)[1].strip()
            current_ap = AccessPoint(bssid=bssid)
            current.access_points.append(current_ap)
        elif current_ap is not None and line.startswith("Signal"):
            current_ap.signal_pct = _parse_int(line.split(":", 1)[1])
        elif current_ap is not None and line.startswith("Radio type"):
            current_ap.radio_type = line.split(":", 1)[1].strip()
        elif current_ap is not None and line.startswith("Channel"):
            current_ap.channel = _parse_int(line.split(":", 1)[1])
            current_ap.band = _band_from_channel(current_ap.channel)

    return networks


def scan() -> list[Network]:
    """Scan for nearby networks on the current platform."""
    system = platform.system()
    if system == "Windows":
        if not shutil.which("netsh"):
            raise ScannerError("netsh not found on PATH")
        output = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
        nets = parse_netsh(output)
        if not nets and "no wireless interface" in output.lower():
            raise ScannerError("no wireless interface available")
        return nets

    raise ScannerError(
        f"platform '{system}' not yet supported by the scanner. "
        "Windows is currently implemented; contributions welcome."
    )
