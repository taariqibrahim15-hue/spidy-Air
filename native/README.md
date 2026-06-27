# wifi-auditor (native)

A native Windows desktop build of wifi-auditor — **C** core + **C++ (Win32)**
GUI, compiled to a single `wifi-auditor.exe`. 🕷

It passively enumerates nearby wireless networks via the Windows **WLAN API**
and shows a risk-ranked table of their security posture. It is **read-only**:
it does not connect to, authenticate against, capture from, or crack any
network.

> ⚠ **Assessment-only.** Use only on networks you own or are explicitly
> authorized to assess. Unauthorized access to networks is illegal in most
> jurisdictions. This tool deliberately contains **no** password cracking,
> handshake capture, or deauthentication features.

## Layout

```
native/
  src/
    wifi_scan.h / .c    C core: WLAN enumeration + security assessment
    main.cpp            C++ Win32 GUI (ListView, custom-draw risk colors)
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

Output: `native/build/wifi-auditor.exe` — statically linked, no runtime DLLs
required. Double-click it, then press **Scan now**.

## What it reports

| Column | Meaning |
|---|---|
| Network (SSID) | Network name (`<hidden>` if not broadcast) |
| Risk | INFO / LOW / MEDIUM / HIGH / CRITICAL (row is color-coded) |
| Signal | Signal quality 0–100% |
| Authentication | Open / WEP / WPA / WPA2 / WPA3 (-Personal/-Enterprise) |
| Cipher | None / WEP / TKIP / CCMP (AES) / GCMP |
| Radios | Number of BSSIDs advertising the SSID |
| Finding | Why it got that risk rating |

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
