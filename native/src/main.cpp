/*
 * main.cpp - Win32 GUI for spidy-Air (C++).
 *
 * Presentation layer over the C core in wifi_scan.c. Shows a risk-ranked
 * network table; double-clicking a network opens a detailed, read-only
 * vulnerability assessment (checklist + per-radio breakdown).
 *
 * Assessment-only: no attack features.
 */
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <vector>
#include <algorithm>
#include <string>
#include <cstdio>
#include <cwchar>

extern "C" {
#include "wifi_scan.h"
}
#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")

enum { ID_SCAN = 1, ID_LIST = 2, ID_STATUS = 3, ID_EXPORT = 4, ID_DETAILS = 5 };

static const wchar_t *kClass = L"SpidyAirWnd";
static const wchar_t *kDetailClass = L"SpidyAirDetail";

static HWND   g_list = nullptr, g_status = nullptr;
static HWND   g_scanBtn = nullptr, g_exportBtn = nullptr, g_detailBtn = nullptr;
static HFONT  g_font = nullptr, g_fontBig = nullptr;
static std::vector<wa_network> g_rows;
static HINSTANCE g_inst = nullptr;

/* ---------- severity colors ---------- */
static COLORREF sevBg(wa_severity s) {
    switch (s) {
        case SEV_CRITICAL: return RGB(255, 228, 232);
        case SEV_HIGH:     return RGB(255, 238, 222);
        case SEV_MEDIUM:   return RGB(255, 249, 219);
        case SEV_LOW:      return RGB(224, 244, 255);
        default:           return RGB(226, 248, 238);
    }
}
static COLORREF sevFg(wa_severity s) {
    switch (s) {
        case SEV_CRITICAL: return RGB(170, 20, 50);
        case SEV_HIGH:     return RGB(170, 80, 10);
        case SEV_MEDIUM:   return RGB(140, 110, 0);
        case SEV_LOW:      return RGB(20, 90, 140);
        default:           return RGB(20, 110, 80);
    }
}

static std::wstring widen(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
    return w;
}

static void lvAddCol(HWND lv, int i, const wchar_t *t, int w, int fmt = LVCFMT_LEFT) {
    LVCOLUMNW c{};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
    c.fmt = fmt; c.cx = w; c.iSubItem = i;
    c.pszText = const_cast<wchar_t *>(t);
    ListView_InsertColumn(lv, i, &c);
}
static void lvSet(HWND lv, int row, int col, const std::wstring &s) {
    LVITEMW it{};
    it.mask = LVIF_TEXT; it.iItem = row; it.iSubItem = col;
    it.pszText = const_cast<wchar_t *>(s.c_str());
    if (col == 0) ListView_InsertItem(lv, &it);
    else          ListView_SetItem(lv, &it);
}

/* ================= Detail window ================= */
struct DetailState { wa_network net; HWND checks; HWND radios; };

static void fillDetail(DetailState *d) {
    /* checks */
    for (int i = 0; i < d->net.check_count; i++) {
        const wa_check &c = d->net.checks[i];
        lvSet(d->checks, i, 0, widen(wa_severity_name(c.severity)));
        lvSet(d->checks, i, 1, widen(c.title));
        lvSet(d->checks, i, 2, widen(c.detail));
        lvSet(d->checks, i, 3, widen(c.recommendation));
    }
    /* radios */
    if (d->net.bss_actual == 0) {
        lvSet(d->radios, 0, 0, L"(no per-radio data returned by driver)");
    }
    for (int i = 0; i < d->net.bss_actual; i++) {
        const wa_bss &b = d->net.bss[i];
        wchar_t buf[24];
        lvSet(d->radios, i, 0, widen(b.bssid));
        swprintf(buf, 24, L"%d", b.channel); lvSet(d->radios, i, 1, b.channel ? buf : L"?");
        lvSet(d->radios, i, 2, widen(b.band[0] ? b.band : "?"));
        if (b.rssi) { swprintf(buf, 24, L"%d dBm", b.rssi); lvSet(d->radios, i, 3, buf); }
        else        lvSet(d->radios, i, 3, L"?");
        swprintf(buf, 24, L"%d%%", b.quality); lvSet(d->radios, i, 4, buf);
    }
}

static LRESULT CALLBACK DetailProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    DetailState *d = (DetailState *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lp;
        d = (DetailState *)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)d);

        std::wstring head = (d->net.hidden ? std::wstring(L"<hidden>") : widen(d->net.ssid));
        wchar_t info[256];
        swprintf(info, 256, L"%s     •  Risk: %S  •  %S / %S  •  signal %d%%",
                 head.c_str(), wa_severity_name(d->net.severity),
                 d->net.auth, d->net.cipher,
                 d->net.signal_pct < 0 ? 0 : d->net.signal_pct);
        HWND hHead = CreateWindowExW(0, L"STATIC", info, WS_CHILD | WS_VISIBLE,
                                     14, 10, 760, 26, hwnd, (HMENU)100, g_inst, nullptr);
        SendMessageW(hHead, WM_SETFONT, (WPARAM)g_fontBig, TRUE);

        HWND lbl1 = CreateWindowExW(0, L"STATIC", L"Vulnerability assessment",
                                    WS_CHILD | WS_VISIBLE, 14, 44, 300, 18, hwnd, 0, g_inst, nullptr);
        SendMessageW(lbl1, WM_SETFONT, (WPARAM)g_font, TRUE);

        d->checks = CreateWindowExW(0, WC_LISTVIEWW, L"",
                        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                        14, 64, 760, 220, hwnd, (HMENU)101, g_inst, nullptr);
        ListView_SetExtendedListViewStyle(d->checks,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        SendMessageW(d->checks, WM_SETFONT, (WPARAM)g_font, TRUE);
        lvAddCol(d->checks, 0, L"Severity", 80);
        lvAddCol(d->checks, 1, L"Finding", 200);
        lvAddCol(d->checks, 2, L"Detail", 300);
        lvAddCol(d->checks, 3, L"Recommendation", 300);

        HWND lbl2 = CreateWindowExW(0, L"STATIC", L"Access points (radios)",
                                    WS_CHILD | WS_VISIBLE, 14, 294, 300, 18, hwnd, 0, g_inst, nullptr);
        SendMessageW(lbl2, WM_SETFONT, (WPARAM)g_font, TRUE);

        d->radios = CreateWindowExW(0, WC_LISTVIEWW, L"",
                        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                        14, 314, 760, 150, hwnd, (HMENU)102, g_inst, nullptr);
        ListView_SetExtendedListViewStyle(d->radios,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        SendMessageW(d->radios, WM_SETFONT, (WPARAM)g_font, TRUE);
        lvAddCol(d->radios, 0, L"BSSID", 160);
        lvAddCol(d->radios, 1, L"Channel", 80, LVCFMT_RIGHT);
        lvAddCol(d->radios, 2, L"Band", 90);
        lvAddCol(d->radios, 3, L"Signal", 100, LVCFMT_RIGHT);
        lvAddCol(d->radios, 4, L"Quality", 80, LVCFMT_RIGHT);

        HWND note = CreateWindowExW(0, L"STATIC",
            L"Read-only assessment. spidy-Air does not crack, capture, or attack networks.",
            WS_CHILD | WS_VISIBLE, 14, 474, 600, 18, hwnd, 0, g_inst, nullptr);
        SendMessageW(note, WM_SETFONT, (WPARAM)g_font, TRUE);

        HWND close = CreateWindowExW(0, L"BUTTON", L"Close",
            WS_CHILD | WS_VISIBLE, 660, 470, 114, 28, hwnd, (HMENU)IDOK, g_inst, nullptr);
        SendMessageW(close, WM_SETFONT, (WPARAM)g_font, TRUE);

        fillDetail(d);
        return 0;
    }
    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (d && nh->hwndFrom == d->checks && nh->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lp;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int idx = (int)cd->nmcd.dwItemSpec;
                if (idx >= 0 && idx < d->net.check_count) {
                    cd->clrTextBk = sevBg(d->net.checks[idx].severity);
                    cd->clrText   = sevFg(d->net.checks[idx].severity);
                }
                return CDRF_DODEFAULT;
            }
        }
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) { DestroyWindow(hwnd); return 0; }
        break;
    case WM_DESTROY:
        delete d;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void openDetail(int idx) {
    if (idx < 0 || idx >= (int)g_rows.size()) return;
    DetailState *d = new DetailState();
    d->net = g_rows[idx];
    std::wstring title = L"Vulnerability assessment — " +
        (d->net.hidden ? std::wstring(L"<hidden>") : widen(d->net.ssid));
    HWND parent = GetActiveWindow();
    HWND w = CreateWindowExW(WS_EX_DLGMODALFRAME, kDetailClass, title.c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 806, 548,
        parent, nullptr, g_inst, d);
    if (w) { ShowWindow(w, SW_SHOW); UpdateWindow(w); }
}

/* ================= Main window ================= */
static void populate() {
    ListView_DeleteAllItems(g_list);
    std::sort(g_rows.begin(), g_rows.end(),
              [](const wa_network &a, const wa_network &b) {
                  if (a.severity != b.severity) return a.severity > b.severity;
                  return a.signal_pct > b.signal_pct;
              });
    for (int i = 0; i < (int)g_rows.size(); ++i) {
        const wa_network &n = g_rows[i];
        lvSet(g_list, i, 0, n.hidden ? L"<hidden>" : widen(n.ssid));
        lvSet(g_list, i, 1, widen(wa_severity_name(n.severity)));
        wchar_t s[16];
        if (n.signal_pct < 0) wcscpy(s, L"?"); else swprintf(s, 16, L"%d%%", n.signal_pct);
        lvSet(g_list, i, 2, s);
        lvSet(g_list, i, 3, widen(n.auth));
        lvSet(g_list, i, 4, widen(n.cipher));
        wchar_t bc[16]; swprintf(bc, 16, L"%u", n.bss_count); lvSet(g_list, i, 5, bc);
        wchar_t cc[16]; swprintf(cc, 16, L"%d", n.check_count); lvSet(g_list, i, 6, cc);
    }
}

static void updateStatus() {
    int c[5] = {0,0,0,0,0};
    for (auto &n : g_rows) c[n.severity]++;
    wchar_t buf[256];
    swprintf(buf, 256,
        L"  %d network(s)   |   CRIT %d   HIGH %d   MED %d   LOW %d   INFO %d"
        L"   |   double-click a network for details   |   assessment-only",
        (int)g_rows.size(), c[SEV_CRITICAL], c[SEV_HIGH], c[SEV_MEDIUM],
        c[SEV_LOW], c[SEV_INFO]);
    SetWindowTextW(g_status, buf);
}

static void doScan() {
    EnableWindow(g_scanBtn, FALSE);
    SetWindowTextW(g_status, L"  Scanning…");
    UpdateWindow(g_status);
    wa_result r = wa_scan();
    g_rows.clear();
    if (r.error) MessageBoxA(nullptr, r.error_msg, "spidy-Air", MB_ICONERROR);
    else g_rows.assign(r.items, r.items + r.count);
    wa_free(&r);
    populate();
    updateStatus();
    EnableWindow(g_scanBtn, TRUE);
}

static void exportCsv() {
    if (g_rows.empty()) { MessageBoxW(nullptr, L"Nothing to export. Run a scan first.",
                                      L"spidy-Air", MB_ICONINFORMATION); return; }
    wchar_t path[MAX_PATH] = L"spidy-air-report.csv";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFilter = L"CSV files\0*.csv\0All files\0*.*\0";
    ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;

    FILE *f = _wfopen(path, L"w, ccs=UTF-8");
    if (!f) { MessageBoxW(nullptr, L"Could not write file.", L"spidy-Air", MB_ICONERROR); return; }
    fwprintf(f, L"SSID,Risk,Signal%%,Authentication,Cipher,Radios,Findings\n");
    for (auto &n : g_rows) {
        std::wstring ssid = n.hidden ? L"<hidden>" : widen(n.ssid);
        fwprintf(f, L"\"%s\",%S,%d,%S,%S,%u,%d\n",
                 ssid.c_str(), wa_severity_name(n.severity),
                 n.signal_pct < 0 ? 0 : n.signal_pct,
                 n.auth, n.cipher, n.bss_count, n.check_count);
    }
    fclose(f);
    MessageBoxW(nullptr, L"Report exported.", L"spidy-Air", MB_ICONINFORMATION);
}

static void layout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    const int pad = 10, btnH = 34, statusH = 26;
    MoveWindow(g_scanBtn,   pad,            pad, 130, btnH, TRUE);
    MoveWindow(g_detailBtn, pad + 140,      pad, 130, btnH, TRUE);
    MoveWindow(g_exportBtn, pad + 280,      pad, 130, btnH, TRUE);
    int top = pad + btnH + pad;
    MoveWindow(g_list, pad, top, rc.right - 2*pad, rc.bottom - top - statusH - pad, TRUE);
    MoveWindow(g_status, 0, rc.bottom - statusH, rc.right, statusH, TRUE);
}

static int selectedRow() { return ListView_GetNextItem(g_list, -1, LVNI_SELECTED); }

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_font = CreateFontW(-15,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,
                             CLEARTYPE_QUALITY,0,L"Segoe UI");
        g_fontBig = CreateFontW(-20,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,
                                CLEARTYPE_QUALITY,0,L"Segoe UI");
        g_scanBtn = CreateWindowExW(0,L"BUTTON",L"\U0001F578  Scan now",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,hwnd,(HMENU)ID_SCAN,g_inst,nullptr);
        g_detailBtn = CreateWindowExW(0,L"BUTTON",L"Details",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,hwnd,(HMENU)ID_DETAILS,g_inst,nullptr);
        g_exportBtn = CreateWindowExW(0,L"BUTTON",L"Export CSV",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,hwnd,(HMENU)ID_EXPORT,g_inst,nullptr);
        for (HWND b : {g_scanBtn,g_detailBtn,g_exportBtn})
            SendMessageW(b, WM_SETFONT, (WPARAM)g_font, TRUE);

        g_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,
            0,0,0,0,hwnd,(HMENU)ID_LIST,g_inst,nullptr);
        ListView_SetExtendedListViewStyle(g_list,
            LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER|LVS_EX_HEADERDRAGDROP);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);
        lvAddCol(g_list, 0, L"Network (SSID)", 220);
        lvAddCol(g_list, 1, L"Risk", 90);
        lvAddCol(g_list, 2, L"Signal", 70, LVCFMT_RIGHT);
        lvAddCol(g_list, 3, L"Authentication", 170);
        lvAddCol(g_list, 4, L"Cipher", 110);
        lvAddCol(g_list, 5, L"Radios", 60, LVCFMT_RIGHT);
        lvAddCol(g_list, 6, L"Findings", 70, LVCFMT_RIGHT);

        g_status = CreateWindowExW(0, STATUSCLASSNAMEW,
            L"  Ready — press Scan now.", WS_CHILD|WS_VISIBLE,
            0,0,0,0,hwnd,(HMENU)ID_STATUS,g_inst,nullptr);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
        return 0;
    }
    case WM_SIZE: layout(hwnd); return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_SCAN: doScan(); return 0;
        case ID_EXPORT: exportCsv(); return 0;
        case ID_DETAILS: {
            int s = selectedRow();
            if (s < 0) MessageBoxW(hwnd, L"Select a network first.", L"spidy-Air", MB_ICONINFORMATION);
            else openDetail(s);
            return 0;
        }
        }
        break;
    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == ID_LIST) {
            if (nh->code == NM_DBLCLK) {
                int s = ((LPNMITEMACTIVATE)lp)->iItem;
                if (s >= 0) openDetail(s);
                return 0;
            }
            if (nh->code == NM_CUSTOMDRAW) {
                LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lp;
                if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
                if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                    int idx = (int)cd->nmcd.dwItemSpec;
                    if (idx >= 0 && idx < (int)g_rows.size()) {
                        cd->clrTextBk = sevBg(g_rows[idx].severity);
                        cd->clrText   = sevFg(g_rows[idx].severity);
                    }
                    return CDRF_DODEFAULT;
                }
            }
        }
        break;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO *m = (MINMAXINFO *)lp;
        m->ptMinTrackSize.x = 820; m->ptMinTrackSize.y = 440;
        return 0;
    }
    case WM_DESTROY:
        if (g_font) DeleteObject(g_font);
        if (g_fontBig) DeleteObject(g_fontBig);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    g_inst = hInst;
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);

    HICON icon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APPICON),
                                   IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = WndProc; wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kClass; wc.hIcon = icon; wc.hIconSm = icon;
    RegisterClassExW(&wc);

    WNDCLASSEXW dc{};
    dc.cbSize = sizeof(dc); dc.lpfnWndProc = DetailProc; dc.hInstance = hInst;
    dc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    dc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    dc.lpszClassName = kDetailClass; dc.hIcon = icon; dc.hIconSm = icon;
    RegisterClassExW(&dc);

    HWND hwnd = CreateWindowExW(0, kClass, L"spidy-Air  —  WiFi security console",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1040, 620,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
