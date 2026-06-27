/*
 * wifi_scan.h - C core for wifi-auditor (assessment only).
 *
 * Passively enumerates visible wireless networks via the Windows WLAN API
 * and assesses each one's security posture. It does NOT connect to,
 * authenticate against, capture from, or crack any network.
 *
 * Use only on networks you own or are explicitly authorized to assess.
 */
#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#define WA_MAX_SSID 33   /* 32 bytes + NUL */

typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} wa_severity;

typedef struct {
    char  ssid[WA_MAX_SSID]; /* empty string => hidden */
    int   hidden;            /* 1 if SSID is blank */
    char  auth[48];          /* e.g. "WPA2-Personal" */
    char  cipher[24];        /* e.g. "CCMP (AES)" */
    int   signal_pct;        /* 0..100, -1 if unknown */
    unsigned bss_count;      /* number of radios/BSSIDs */
    int   secured;           /* security enabled flag */

    wa_severity severity;    /* worst finding severity */
    char  finding_title[80];
    char  finding_detail[256];
} wa_network;

typedef struct {
    wa_network *items;
    int         count;
    int         error;       /* 0 ok; nonzero = failure */
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
