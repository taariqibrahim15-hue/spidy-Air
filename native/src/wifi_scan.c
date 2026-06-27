/*
 * wifi_scan.c - WLAN enumeration + security assessment (C, assessment-only).
 *
 * Uses WlanOpenHandle / WlanEnumInterfaces / WlanGetAvailableNetworkList.
 * These are read-only enumeration calls: they report networks the radio can
 * already see, exactly like the OS WiFi menu. No association is attempted.
 */
#include "wifi_scan.h"

#include <windows.h>
#include <wlanapi.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Some MinGW SDK headers predate the newest 802.11 auth constants.
 * Define any that are missing so the assessment logic stays complete.
 * (Values per the Windows SDK DOT11_AUTH_ALGORITHM enumeration.) */
#ifndef DOT11_AUTH_ALGO_WPA3
#define DOT11_AUTH_ALGO_WPA3 0x00000008
#endif
#ifndef DOT11_AUTH_ALGO_WPA3_SAE
#define DOT11_AUTH_ALGO_WPA3_SAE 0x00000009
#endif
#ifndef DOT11_AUTH_ALGO_OWE
#define DOT11_AUTH_ALGO_OWE 0x0000000A
#endif

const char *wa_severity_name(wa_severity s) {
    switch (s) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_LOW:      return "LOW";
        default:           return "INFO";
    }
}

static const char *auth_name(DOT11_AUTH_ALGORITHM a) {
    switch (a) {
        case DOT11_AUTH_ALGO_80211_OPEN:       return "Open";
        case DOT11_AUTH_ALGO_80211_SHARED_KEY: return "Shared key (WEP)";
        case DOT11_AUTH_ALGO_WPA:              return "WPA-Enterprise";
        case DOT11_AUTH_ALGO_WPA_PSK:          return "WPA-Personal";
        case DOT11_AUTH_ALGO_WPA_NONE:         return "WPA-None";
        case DOT11_AUTH_ALGO_RSNA:             return "WPA2-Enterprise";
        case DOT11_AUTH_ALGO_RSNA_PSK:         return "WPA2-Personal";
        case DOT11_AUTH_ALGO_WPA3:             return "WPA3-Enterprise";
        case DOT11_AUTH_ALGO_WPA3_SAE:         return "WPA3-Personal (SAE)";
        case DOT11_AUTH_ALGO_OWE:              return "Enhanced Open (OWE)";
        default:                               return "Unknown";
    }
}

static const char *cipher_name(DOT11_CIPHER_ALGORITHM c) {
    switch (c) {
        case DOT11_CIPHER_ALGO_NONE:    return "None";
        case DOT11_CIPHER_ALGO_WEP:     return "WEP";
        case DOT11_CIPHER_ALGO_WEP40:   return "WEP-40";
        case DOT11_CIPHER_ALGO_WEP104:  return "WEP-104";
        case DOT11_CIPHER_ALGO_TKIP:    return "TKIP";
        case DOT11_CIPHER_ALGO_CCMP:    return "CCMP (AES)";
        case DOT11_CIPHER_ALGO_BIP:     return "BIP";
#ifdef DOT11_CIPHER_ALGO_GCMP
        case DOT11_CIPHER_ALGO_GCMP:    return "GCMP";
#endif
#ifdef DOT11_CIPHER_ALGO_GCMP_256
        case DOT11_CIPHER_ALGO_GCMP_256:return "GCMP-256";
#endif
        default:                        return "Unknown";
    }
}

/* Fill severity + finding for one network based on auth/cipher. */
static void assess(wa_network *n,
                   DOT11_AUTH_ALGORITHM auth,
                   DOT11_CIPHER_ALGORITHM cipher,
                   int secured) {
    if (!secured ||
        (auth == DOT11_AUTH_ALGO_80211_OPEN &&
         cipher == DOT11_CIPHER_ALGO_NONE)) {
        n->severity = SEV_CRITICAL;
        strcpy(n->finding_title, "Open network (no encryption)");
        strcpy(n->finding_detail,
               "Traffic is unencrypted. Anyone in range can passively read "
               "data on this network.");
        return;
    }
    if (cipher == DOT11_CIPHER_ALGO_WEP ||
        cipher == DOT11_CIPHER_ALGO_WEP40 ||
        cipher == DOT11_CIPHER_ALGO_WEP104 ||
        auth == DOT11_AUTH_ALGO_80211_SHARED_KEY) {
        n->severity = SEV_CRITICAL;
        strcpy(n->finding_title, "WEP encryption");
        strcpy(n->finding_detail,
               "WEP is fundamentally broken and recoverable quickly. "
               "Replace with WPA2 or WPA3.");
        return;
    }
    if (auth == DOT11_AUTH_ALGO_WPA ||
        auth == DOT11_AUTH_ALGO_WPA_PSK ||
        auth == DOT11_AUTH_ALGO_WPA_NONE) {
        n->severity = SEV_HIGH;
        strcpy(n->finding_title, "Legacy WPA (v1)");
        strcpy(n->finding_detail,
               "Original WPA is outdated and weaker than WPA2/WPA3. "
               "Upgrade the access point configuration.");
        return;
    }
    if (auth == DOT11_AUTH_ALGO_RSNA ||
        auth == DOT11_AUTH_ALGO_RSNA_PSK) {
        if (cipher == DOT11_CIPHER_ALGO_TKIP) {
            n->severity = SEV_MEDIUM;
            strcpy(n->finding_title, "WPA2 with TKIP cipher");
            strcpy(n->finding_detail,
                   "TKIP is deprecated and weaker than CCMP/AES. "
                   "Configure the AP to use AES (CCMP) only.");
        } else {
            n->severity = SEV_LOW;
            strcpy(n->finding_title, "WPA2-Personal/Enterprise");
            strcpy(n->finding_detail,
                   "Acceptable, but consider WPA3 where supported. "
                   "Strength depends heavily on passphrase quality.");
        }
        return;
    }
    if (auth == DOT11_AUTH_ALGO_WPA3 ||
        auth == DOT11_AUTH_ALGO_WPA3_SAE ||
        auth == DOT11_AUTH_ALGO_OWE) {
        n->severity = SEV_INFO;
        strcpy(n->finding_title, "WPA3 / Enhanced Open in use");
        strcpy(n->finding_detail,
               "Strongest current standard. Good configuration.");
        return;
    }
    n->severity = SEV_INFO;
    strcpy(n->finding_title, "No obvious weaknesses observed");
    strcpy(n->finding_detail,
           "Based on advertised properties only; not a guarantee of security.");
}

static void fail(wa_result *r, const char *msg) {
    r->error = 1;
    strncpy(r->error_msg, msg, sizeof(r->error_msg) - 1);
    r->error_msg[sizeof(r->error_msg) - 1] = '\0';
}

wa_result wa_scan(void) {
    wa_result r;
    memset(&r, 0, sizeof(r));

    DWORD negotiated = 0;
    HANDLE h = NULL;
    DWORD rc = WlanOpenHandle(2, NULL, &negotiated, &h);
    if (rc != ERROR_SUCCESS) {
        fail(&r, "Could not open WLAN handle (is the WLAN service running?).");
        return r;
    }

    PWLAN_INTERFACE_INFO_LIST iflist = NULL;
    rc = WlanEnumInterfaces(h, NULL, &iflist);
    if (rc != ERROR_SUCCESS || !iflist || iflist->dwNumberOfItems == 0) {
        fail(&r, "No wireless interface found.");
        if (iflist) WlanFreeMemory(iflist);
        WlanCloseHandle(h, NULL);
        return r;
    }

    /* First pass: count networks across all interfaces. */
    int cap = 0;
    for (DWORD i = 0; i < iflist->dwNumberOfItems; i++) {
        PWLAN_AVAILABLE_NETWORK_LIST nl = NULL;
        if (WlanGetAvailableNetworkList(
                h, &iflist->InterfaceInfo[i].InterfaceGuid,
                WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
                NULL, &nl) == ERROR_SUCCESS && nl) {
            cap += (int)nl->dwNumberOfItems;
            WlanFreeMemory(nl);
        }
    }

    if (cap > 0) {
        r.items = (wa_network *)calloc((size_t)cap, sizeof(wa_network));
        if (!r.items) {
            fail(&r, "Out of memory.");
            WlanFreeMemory(iflist);
            WlanCloseHandle(h, NULL);
            return r;
        }
    }

    /* Second pass: fill records. */
    for (DWORD i = 0; i < iflist->dwNumberOfItems; i++) {
        PWLAN_AVAILABLE_NETWORK_LIST nl = NULL;
        if (WlanGetAvailableNetworkList(
                h, &iflist->InterfaceInfo[i].InterfaceGuid,
                WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
                NULL, &nl) != ERROR_SUCCESS || !nl) {
            continue;
        }
        for (DWORD j = 0; j < nl->dwNumberOfItems && r.count < cap; j++) {
            WLAN_AVAILABLE_NETWORK *src = &nl->Network[j];
            wa_network *n = &r.items[r.count];

            ULONG len = src->dot11Ssid.uSSIDLength;
            if (len > WA_MAX_SSID - 1) len = WA_MAX_SSID - 1;
            memcpy(n->ssid, src->dot11Ssid.ucSSID, len);
            n->ssid[len] = '\0';
            n->hidden = (len == 0) ? 1 : 0;

            strncpy(n->auth, auth_name(src->dot11DefaultAuthAlgorithm),
                    sizeof(n->auth) - 1);
            strncpy(n->cipher, cipher_name(src->dot11DefaultCipherAlgorithm),
                    sizeof(n->cipher) - 1);
            n->signal_pct = (int)src->wlanSignalQuality; /* 0..100 */
            n->bss_count  = src->uNumberOfBssids;
            n->secured    = src->bSecurityEnabled ? 1 : 0;

            assess(n, src->dot11DefaultAuthAlgorithm,
                   src->dot11DefaultCipherAlgorithm, n->secured);
            r.count++;
        }
        WlanFreeMemory(nl);
    }

    WlanFreeMemory(iflist);
    WlanCloseHandle(h, NULL);
    return r;
}

void wa_free(wa_result *r) {
    if (r && r->items) {
        free(r->items);
        r->items = NULL;
        r->count = 0;
    }
}
