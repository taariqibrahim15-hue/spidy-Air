"""
Local web UI for wifi-auditor.

Serves a single-page dashboard and a small JSON API that wraps the same
passive scanner/auditor used by the CLI. Runs only on localhost by default.

    python -m wifi_auditor.web        # then open http://127.0.0.1:8787

This UI is a viewer for the assessment results — it has no attack features.
"""

from __future__ import annotations

import argparse
import json
import webbrowser
from dataclasses import asdict
from threading import Timer

from flask import Flask, jsonify, render_template, request

from . import __version__
from .auditor import audit
from .models import Network, Severity
from .scanner import ScannerError, parse_netsh, scan

app = Flask(__name__)


def _serialize(networks: list[Network]) -> list[dict]:
    out: list[dict] = []
    for net in networks:
        d = asdict(net)
        d["display_ssid"] = net.display_ssid
        d["best_signal"] = net.best_signal
        d["worst_severity"] = net.worst_severity.value
        d["is_hidden"] = net.is_hidden
        out.append(d)
    return out


def _summary(networks: list[Network]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for net in networks:
        counts[net.worst_severity.value] += 1
    return {
        "total": len(networks),
        "by_severity": counts,
    }


@app.get("/")
def index():
    return render_template("index.html", version=__version__)


@app.get("/api/scan")
def api_scan():
    try:
        networks = scan()
    except ScannerError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 200
    audit(networks)
    return jsonify(
        {"ok": True, "networks": _serialize(networks), "summary": _summary(networks)}
    )


@app.post("/api/scan-file")
def api_scan_file():
    """Audit pasted/uploaded `netsh wlan show networks mode=bssid` text."""
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    if not text.strip():
        return jsonify({"ok": False, "error": "no scan text provided"}), 200
    networks = parse_netsh(text)
    audit(networks)
    return jsonify(
        {"ok": True, "networks": _serialize(networks), "summary": _summary(networks)}
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="wifi-auditor-web")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--no-browser", action="store_true",
                   help="do not auto-open the browser")
    args = p.parse_args(argv)

    url = f"http://{args.host}:{args.port}"
    print(f"wifi-auditor {__version__} — UI at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        Timer(0.8, lambda: webbrowser.open(url)).start()
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
