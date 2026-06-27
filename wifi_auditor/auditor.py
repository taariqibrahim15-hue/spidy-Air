"""
Security assessment logic.

Given a scanned Network, produce Findings describing its security posture.
All checks are based on advertised, observable properties (authentication
method, encryption cipher, network type). Nothing here connects to or
attacks a network.
"""

from __future__ import annotations

from .models import Finding, Network, Severity


def _norm(s: str) -> str:
    return s.strip().lower().replace("-", "").replace(" ", "")


def assess(network: Network) -> list[Finding]:
    """Return a list of Findings for a single network."""
    findings: list[Finding] = []
    auth = _norm(network.authentication)
    enc = _norm(network.encryption)

    # --- Encryption / authentication strength ---
    if auth in {"open", ""} and enc in {"none", ""}:
        findings.append(
            Finding(
                Severity.CRITICAL,
                "Open network (no encryption)",
                "Traffic is unencrypted. Anyone in range can passively read "
                "data sent over this network.",
            )
        )
    elif "wep" in auth or "wep" in enc:
        findings.append(
            Finding(
                Severity.CRITICAL,
                "WEP encryption",
                "WEP is fundamentally broken and recoverable in minutes. "
                "Should be replaced with WPA2 or WPA3.",
            )
        )
    elif "wpa3" in auth:
        findings.append(
            Finding(
                Severity.INFO,
                "WPA3 in use",
                "Strongest current standard. Good configuration.",
            )
        )
    elif "wpa2" in auth:
        if "tkip" in enc:
            findings.append(
                Finding(
                    Severity.MEDIUM,
                    "WPA2 with TKIP cipher",
                    "TKIP is deprecated and weaker than CCMP/AES. "
                    "Configure the AP to use AES (CCMP) only.",
                )
            )
        else:
            findings.append(
                Finding(
                    Severity.LOW,
                    "WPA2-Personal",
                    "Acceptable, but consider WPA3 where supported. "
                    "Strength depends heavily on passphrase quality.",
                )
            )
    elif auth.startswith("wpa") and "wpa2" not in auth and "wpa3" not in auth:
        findings.append(
            Finding(
                Severity.HIGH,
                "Legacy WPA (v1)",
                "Original WPA is outdated and weaker than WPA2/WPA3. "
                "Upgrade the access point configuration.",
            )
        )

    # --- Open + ad-hoc style network type ---
    if _norm(network.network_type) == "adhoc":
        findings.append(
            Finding(
                Severity.LOW,
                "Ad-hoc network",
                "Ad-hoc (peer-to-peer) networks bypass typical AP controls "
                "and are easy to misconfigure.",
            )
        )

    # --- Hidden SSID (informational; not a real security control) ---
    if network.is_hidden:
        findings.append(
            Finding(
                Severity.INFO,
                "Hidden SSID",
                "A hidden network name is trivially discoverable and is not "
                "a meaningful security measure.",
            )
        )

    if not findings:
        findings.append(
            Finding(
                Severity.INFO,
                "No obvious weaknesses observed",
                "Based on advertised properties only. This is not a guarantee "
                "of security.",
            )
        )

    return findings


def audit(networks: list[Network]) -> list[Network]:
    """Assess every network in place and return the same list."""
    for net in networks:
        net.findings = assess(net)
    return networks
