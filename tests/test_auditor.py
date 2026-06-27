"""Tests for the parser and assessment logic."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_auditor.auditor import assess  # noqa: E402
from wifi_auditor.models import Network, Severity  # noqa: E402
from wifi_auditor.scanner import parse_netsh  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), "sample_netsh.txt")


def _load():
    with open(FIXTURE, encoding="utf-8") as fh:
        return parse_netsh(fh.read())


def test_parses_all_networks():
    nets = _load()
    assert len(nets) == 4


def test_dual_band_radios_grouped():
    nets = {n.ssid: n for n in _load()}
    home = nets["HomeNet"]
    assert len(home.access_points) == 2
    bands = {ap.band for ap in home.access_points}
    assert bands == {"2.4 GHz", "5 GHz"}


def test_open_network_is_critical():
    net = Network(ssid="x", authentication="Open", encryption="None")
    sev = {f.severity for f in assess(net)}
    assert Severity.CRITICAL in sev


def test_wep_is_critical():
    net = Network(ssid="x", authentication="Open", encryption="WEP")
    assert any(f.severity == Severity.CRITICAL and "WEP" in f.title
               for f in assess(net))


def test_wpa3_is_info():
    net = Network(ssid="x", authentication="WPA3-Personal", encryption="CCMP")
    assert assess(net)[0].severity == Severity.INFO


def test_wpa2_tkip_is_medium():
    net = Network(ssid="x", authentication="WPA2-Personal", encryption="TKIP")
    assert any(f.severity == Severity.MEDIUM for f in assess(net))


def test_hidden_ssid_flagged():
    nets = {n.display_ssid: n for n in _load()}
    hidden = nets["<hidden>"]
    assert hidden.is_hidden
    assert any("Hidden" in f.title for f in assess(hidden))


if __name__ == "__main__":
    import traceback

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
