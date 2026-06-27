# spidy-Air (native)

A native Windows desktop app — **C** core + **C++ (Win32)** GUI, compiled to a
single `spidy-Air.exe`. 🕷

It passively enumerates nearby wireless networks via the Windows **WLAN API**,
gathers per-radio (BSSID) details, and shows a risk-ranked table. Double-click
any network to open a detailed **vulnerability assessment** (checklist +
per-radio breakdown). Results can be exported to CSV.

It is **read-only**: it does not connect to, authenticate against, capture
from, deauth, or crack any network.

> ⚠ **Assessment-only.** Use only on networks you own or are explicitly
> authorized to assess. Unauthorized access to networks is illegal in most
> jurisdictions. This tool deliberately contains **no** password cracking,
> handshake capture, or deauthentication features.

## Layout

```
native/
  src/
    wifi_scan.h / .c    C core: WLAN enumeration, per-BSSID details, checklist
    main.cpp            C++ Win32 GUI: network table + detail window + CSV export
    resource.h          resource IDs
    app.rc              icon + manifest resource script
    app.manifest        enables themed controls (comctl32 v6) + DPI
    spider.ico          app icon (generated, 16-256 px)
  tools/make_icon.py    regenerates spider.ico (needs Pillow)
  Makefile              MinGW build (make)
  build.bat             MinGW build (no make)
```

## Build

Needs **MinGW-w64** (gcc/g++/windres) on `PATH`.
Install with: `winget install BrechtSanders.WinLibs.POSIX.UCRT`

```bat
cd native
build.bat
:: or, with make:
make
```

Output: `native/build/spidy-Air.exe` — statically linked, no runtime DLLs
required. Double-click it, then press **Scan now**.

## Using it

1. **Scan now** — lists nearby networks, ranked by risk.
2. **Double-click a network** (or select it and press **Details**) — opens a
   vulnerability assessment window with:
   - a findings checklist (severity, finding, detail, recommendation)
   - a per-radio table (BSSID, channel, band, signal in dBm, link quality)
3. **Export CSV** — saves the full report to a file.

## What it reports

| Column | Meaning |
|---|---|
| Network (SSID) | Network name (`<hidden>` if not broadcast) |
| Risk | INFO / LOW / MEDIUM / HIGH / CRITICAL (row is color-coded) |
| Signal | Signal quality 0–100% |
| Authentication | Open / WEP / WPA / WPA2 / WPA3 (-Personal/-Enterprise) |
| Cipher | None / WEP / TKIP / CCMP (AES) / GCMP |
| Radios | Number of BSSIDs advertising the SSID |
| Findings | Count of assessment items (open the detail window to read them) |

### Risk rules

- **CRITICAL** — open (no encryption), or WEP
- **HIGH** — legacy WPA v1
- **MEDIUM** — WPA2 with TKIP
- **LOW** — WPA2 with CCMP (consider WPA3)
- **INFO** — WPA3 / Enhanced Open (good)

## Regenerate the icon

```bash
pip install pillow
python tools/make_icon.py
```

## License

MIT — see ../LICENSE.
