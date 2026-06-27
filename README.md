# wifi-auditor

A passive WiFi **security auditing** tool. It scans for nearby wireless
networks and assesses their security posture — encryption type, authentication
method, cipher, band, and signal — then produces a risk-ranked report.

It is the reconnaissance/assessment phase of a security toolkit, comparable to
a WiFi analyzer. It is **read-only**: it does not connect to, authenticate
against, capture handshakes from, or crack any network.

---

## ⚠️ Disclaimer & intended use

**This tool is for authorized security assessment and education only.**

- Use it **only** on networks you **own** or have **explicit written
  authorization** to assess.
- It reports on *publicly broadcast* information (the same data your device
  shows in its WiFi menu) and does not attempt to gain access to anything.
- Unauthorized access to computer networks is illegal in most jurisdictions
  (e.g. CFAA in the US, the Computer Misuse Act in the UK, and equivalents
  elsewhere). A disclaimer does not grant you authorization — the network
  owner does.
- The authors accept no liability for misuse.

By using this software you agree you are responsible for complying with all
applicable laws.

> **Scope note:** This project deliberately does **not** include password
> cracking, handshake capture, deauthentication, or any attack capability.
> Those belong in dedicated tools used by hand against a target you are
> contractually authorized to test — not in an automated scanner.

---

## What it checks

| Finding | Severity |
|---|---|
| Open network (no encryption) | CRITICAL |
| WEP encryption | CRITICAL |
| Legacy WPA (v1) | HIGH |
| WPA2 with TKIP cipher | MEDIUM |
| WPA2-Personal (consider WPA3) | LOW |
| WPA3 in use | INFO (good) |
| Ad-hoc network | LOW |
| Hidden SSID (not a real control) | INFO |

## Requirements

- Python 3.10+
- **Windows** (uses the built-in `netsh wlan`). Linux/macOS parsers are easy to
  add — see `scanner.py`; contributions welcome.
- A WiFi interface that is enabled.

## Web UI (recommended)

A local dashboard with a risk summary, signal bars, filtering, and an
import-scan tool. Runs on `127.0.0.1` only — nothing is exposed to the network.

```bash
pip install flask          # or: pip install -e ".[ui]"
python -m wifi_auditor.web # opens http://127.0.0.1:8787 in your browser
```

Options: `--port 8787`, `--host 127.0.0.1`, `--no-browser`.

## CLI usage

```bash
# Live scan + text report
python -m wifi_auditor.cli

# Only show networks at MEDIUM risk or higher
python -m wifi_auditor.cli --min-severity MEDIUM

# Machine-readable output
python -m wifi_auditor.cli --json

# Analyze saved scan output offline (no live scan)
#   netsh wlan show networks mode=bssid > scan.txt
python -m wifi_auditor.cli --from-file scan.txt
```

### Example

```
‼ [CRITICAL] OldRouter   signal  80%  auth Open/WEP
      bands: 2.4 GHz  (1 radio(s))
      - [CRITICAL] WEP encryption: WEP is fundamentally broken ...

▪ [LOW     ] HomeNet   signal  90%  auth WPA2-Personal/CCMP
      bands: 2.4 GHz, 5 GHz  (2 radio(s))
      - [LOW] WPA2-Personal: Acceptable, but consider WPA3 ...

Findings summary: CRITICAL=2  HIGH=0  MEDIUM=1  LOW=1  INFO=1
```

## Development

```bash
python tests/test_auditor.py   # run the test suite (no dependencies)
```

## Roadmap (assessment-only)

- Linux (`nmcli` / `iw`) and macOS (`airport -s`) scanner backends
- WPS-enabled detection where the OS exposes it
- HTML report export
- Optional check of *your own* router's admin page for default credentials
  (only against a host you supply and own)

## License

MIT — see [LICENSE](LICENSE).
