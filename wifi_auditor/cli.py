"""Command-line entry point for wifi-auditor."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .auditor import audit
from .report import to_json, to_text
from .scanner import ScannerError, parse_netsh, scan

DISCLAIMER = (
    "wifi-auditor is a passive, read-only security assessment tool. "
    "Use it only on networks you own or are explicitly authorized to assess. "
    "It does not connect to, authenticate against, or crack any network."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifi-auditor",
        description="Passively scan and audit nearby WiFi networks. " + DISCLAIMER,
    )
    p.add_argument("--version", action="version", version=f"wifi-auditor {__version__}")
    p.add_argument(
        "--json",
        action="store_true",
        help="output machine-readable JSON instead of a text report",
    )
    p.add_argument(
        "--from-file",
        metavar="PATH",
        help="parse saved `netsh wlan show networks mode=bssid` output "
        "instead of scanning live (useful for testing / offline analysis)",
    )
    p.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="INFO",
        help="only show networks with at least this risk level (text mode)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.from_file:
            with open(args.from_file, "r", encoding="utf-8", errors="replace") as fh:
                networks = parse_netsh(fh.read())
        else:
            networks = scan()
    except ScannerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: could not read file: {exc}", file=sys.stderr)
        return 2

    audit(networks)

    if args.json:
        print(to_json(networks))
        return 0

    from .models import Severity

    threshold = Severity[args.min_severity].rank
    filtered = [n for n in networks if n.worst_severity.rank >= threshold]
    print(to_text(filtered))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
