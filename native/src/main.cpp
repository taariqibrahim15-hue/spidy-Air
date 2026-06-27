/*
 * main.cpp - Win32 GUI for wifi-auditor (C++).
 *
 * Thin presentation layer over the C core in wifi_scan.c. Shows a risk-ranked
 * table of nearby networks. Assessment-only: no attack features.
 */
#include <windows.h>
#include <commctrl.h>
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

static const wchar_t *kClass = L"WifiAuditorWnd";
static HWND   g_list = nullptr;
static HWND   g_status = nullptr;
static HWND   g_scanBtn = nullptr;
static HFONT  g_font = nullptr;
static std::vector<wa_network> g_rows;

// Severity -> row background tint
static COLORREF sevColor(wa_severity s) {
    switch (s) {
        case SEV_CRITICAL: return RGB(255, 228, 232);
        case SEV_HIGH:     return RGB(255, 238, 222);
        case SEV_MEDIUM:   return RGB(255, 249, 219);
        case SEV_LOW:      return RGB(224, 244, 255);
        default:           return RGB(226, 248, 238);
    }
}
static COLORREF sevTextColor(wa_severity s) {
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

static void addColumn(int idx, const wchar_t *title, int width, int fmt = LVCFMT_LEFT) {
    LVCOLUMNW c{};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
    c.fmt = fmt;
    c.cx = width;
    c.iSubItem = idx;
    c.pszText = const_cast<wchar_t *>(title);
    ListView_InsertColumn(g_list, idx, &c);
}

static void buildColumns() {
    addColumn(0, L"Network (SSID)", 220);
    addColumn(1, L"Risk", 90);
    addColumn(2, L"Signal", 70, LVCFMT_RIGHT);
    addColumn(3, L"Authentication", 170);
    addColumn(4, L"Cipher", 110);
    addColumn(5, L"Radios", 60, LVCFMT_RIGHT);
    addColumn(6, L"Finding", 380);
}

static void setItem(int row, int col, const std::wstring &text) {
    LVITEMW it{};
    it.mask = LVIF_TEXT;
    it.iItem = row;
    it.iSubItem = col;
    it.pszText = const_cast<wchar_t *>(text.c_str());
    if (col == 0) ListView_InsertItem(g_list, &it);
    else          ListView_SetItem(g_list, &it);
}

static void populate() {
    ListView_DeleteAllItems(g_list);
    // Sort: worst severity first, then strongest signal.
    std::sort(g_rows.begin(), g_rows.end(),
              [](const wa_network &a, const wa_network &b) {
                  if (a.severity != b.severity) return a.severity > b.severity;
                  return a.signal_pct > b.signal_pct;
              });
    for (int i = 0; i < (int)g_rows.size(); ++i) {
        const wa_network &n = g_rows[i];
        std::wstring ssid = n.hidden ? L"<hidden>" : widen(n.ssid);
        setItem(i, 0, ssid);
        setItem(i, 1, widen(wa_severity_name(n.severity)));
        wchar_t sig[16];
        if (n.signal_pct < 0) wcscpy(sig, L"?");
        else swprintf(sig, 16, L"%d%%", n.signal_pct);
        setItem(i, 2, sig);
        setItem(i, 3, widen(n.auth));
        setItem(i, 4, widen(n.cipher));
        wchar_t bc[16]; swprintf(bc, 16, L"%u", n.bss_count);
        setItem(i, 5, bc);
        setItem(i, 6, widen(n.finding_title));
    }
}

static void updateStatus() {
    int c[5] = {0, 0, 0, 0, 0};
    for (auto &n : g_rows) c[n.severity]++;
    wchar_t buf[256];
    swprintf(buf, 256,
             L"  %d network(s)   |   CRITICAL %d   HIGH %d   MEDIUM %d   LOW %d   INFO %d"
             L"   |   assessment-only — authorized use only",
             (int)g_rows.size(), c[SEV_CRITICAL], c[SEV_HIGH],
             c[SEV_MEDIUM], c[SEV_LOW], c[SEV_INFO]);
    SetWindowTextW(g_status, buf);
}

static void doScan() {
    EnableWindow(g_scanBtn, FALSE);
    SetWindowTextW(g_status, L"  Scanning…");
    UpdateWindow(g_status);

    wa_result r = wa_scan();
    g_rows.clear();
    if (r.error) {
        MessageBoxA(nullptr, r.error_msg, "wifi-auditor", MB_ICONERROR);
    } else {
        g_rows.assign(r.items, r.items + r.count);
    }
    wa_free(&r);

    populate();
    updateStatus();
    EnableWindow(g_scanBtn, TRUE);
}

static void layout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    const int pad = 10, btnH = 34, btnW = 130, statusH = 26;
    MoveWindow(g_scanBtn, pad, pad, btnW, btnH, TRUE);
    int top = pad + btnH + pad;
    MoveWindow(g_list, pad, top,
               rc.right - 2 * pad,
               rc.bottom - top - statusH - pad, TRUE);
    MoveWindow(g_status, 0, rc.bottom - statusH, rc.right, statusH, TRUE);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                             DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0,
                             L"Segoe UI");
        g_scanBtn = CreateWindowExW(0, L"BUTTON", L"\U0001F578  Scan now",
                                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                    0, 0, 0, 0, hwnd, (HMENU)1,
                                    nullptr, nullptr);
        SendMessageW(g_scanBtn, WM_SETFONT, (WPARAM)g_font, TRUE);

        g_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT |
                                 LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                 0, 0, 0, 0, hwnd, (HMENU)2, nullptr, nullptr);
        ListView_SetExtendedListViewStyle(
            g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                    LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);
        buildColumns();

        g_status = CreateWindowExW(0, STATUSCLASSNAMEW, L"  Ready — press Scan now.",
                                   WS_CHILD | WS_VISIBLE,
                                   0, 0, 0, 0, hwnd, (HMENU)3, nullptr, nullptr);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
        return 0;
    }
    case WM_SIZE:
        layout(hwnd);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wp) == 1) { doScan(); return 0; }
        break;

    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == 2 && nh->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lp;
            switch (cd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT: {
                int idx = (int)cd->nmcd.dwItemSpec;
                if (idx >= 0 && idx < (int)g_rows.size()) {
                    wa_severity s = g_rows[idx].severity;
                    cd->clrTextBk = sevColor(s);
                    cd->clrText = sevTextColor(s);
                }
                return CDRF_DODEFAULT;
            }
            }
        }
        break;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lp;
        mmi->ptMinTrackSize.x = 760;
        mmi->ptMinTrackSize.y = 420;
        return 0;
    }
    case WM_DESTROY:
        if (g_font) DeleteObject(g_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);

    HICON icon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APPICON),
                                   IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kClass;
    wc.hIcon = icon;
    wc.hIconSm = icon;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        0, kClass, L"wifi-auditor  —  WiFi security console",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 600,
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
