/*
 * wifi_scan.h - C core for spidy-Air (assessment only).
 *
 * Passively enumerates visible wireless networks via the Windows WLAN API,
 * gathers per-radio (BSSID) details, and produces a structured, read-only
 * vulnerability assessment for each network.
 *
 * It does NOT connect to, authenticate against, capture from, deauth, or
 * crack any network. Use only on networks you own or are explicitly
 * authorized to assess.
 */
#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#define WA_MAX_SSID   33   /* 32 bytes + NUL */
#define WA_MAX_CHECKS 10   /* assessment items per network */
#define WA_MAX_BSS    16   /* radios tracked per network */

typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} wa_severity;

/* One radio (BSSID) advertising a network. */
typedef struct {
    char bssid[18];     /* "aa:bb:cc:dd:ee:ff" */
    int  rssi;          /* dBm (negative), 0 if unknown */
    int  quality;       /* 0..100 */
    int  channel;       /* derived from center frequency, 0 if unknown */
    char band[8];       /* "2.4 GHz" / "5 GHz" / "6 GHz" */
} wa_bss;

/* One assessment item (a vulnerability check result). */
typedef struct {
    wa_severity severity;
    char title[80];
    char detail[220];
    char recommendation[220];
} wa_check;

typedef struct {
    char  ssid[WA_MAX_SSID]; /* empty string => hidden */
    int   hidden;
    char  auth[48];
    char  cipher[24];
    int   signal_pct;        /* 0..100, -1 if unknown */
    unsigned bss_count;      /* reported number of radios */
    int   secured;

    wa_severity severity;    /* worst check severity */

    wa_check checks[WA_MAX_CHECKS];
    int      check_count;

    wa_bss   bss[WA_MAX_BSS];
    int      bss_actual;     /* number of radios actually gathered */
} wa_network;

typedef struct {
    wa_network *items;
    int         count;
    int         error;
    char        error_msg[160];
} wa_result;

/* Run a passive scan + assessment. Caller must call wa_free(). */
wa_result wa_scan(void);

/* Free memory held by a result. */
void wa_free(wa_result *r);

/* Human-readable severity label. */
const char *wa_severity_name(wa_severity s);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_SCAN_H */
