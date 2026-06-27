/*
 * wifi_scan.c - WLAN enumeration + per-radio details + vulnerability
 * assessment (C, assessment-only).
 *
 * Read-only WLAN API calls only:
 *   WlanOpenHandle / WlanEnumInterfaces
 *   WlanGetAvailableNetworkList   (networks + auth/cipher/signal)
 *   WlanGetNetworkBssList         (per-BSSID radio details)
 * No association or attack is performed.
 */
#include "wifi_scan.h"

#include <windows.h>
#include <wlanapi.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Some MinGW SDK headers predate the newest 802.11 auth constants. */
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

/* center frequency (kHz) -> channel + band */
static int freq_to_channel(ULONG khz, char *band, size_t band_sz) {
    int mhz = (int)(khz / 1000);
    band[0] = '\0';
    if (mhz >= 2412 && mhz <= 2472) {
        snprintf(band, band_sz, "2.4 GHz");
        return (mhz - 2412) / 5 + 1;
    }
    if (mhz == 2484) { snprintf(band, band_sz, "2.4 GHz"); return 14; }
    if (mhz >= 5160 && mhz <= 5885) {
        snprintf(band, band_sz, "5 GHz");
        return (mhz - 5000) / 5;
    }
    if (mhz >= 5955 && mhz <= 7115) {
        snprintf(band, band_sz, "6 GHz");
        return (mhz - 5950) / 5;
    }
    return 0;
}

/* push a check; tracks worst severity on the network */
static void add_check(wa_network *n, wa_severity sev, const char *title,
                      const char *detail, const char *rec) {
    if (n->check_count >= WA_MAX_CHECKS) return;
    wa_check *c = &n->checks[n->check_count++];
    c->severity = sev;
    strncpy(c->title, title, sizeof(c->title) - 1);
    strncpy(c->detail, detail, sizeof(c->detail) - 1);
    strncpy(c->recommendation, rec, sizeof(c->recommendation) - 1);
    if (sev > n->severity) n->severity = sev;
}

/* Build the full vulnerability checklist for one network. */
static void assess(wa_network *n,
                   DOT11_AUTH_ALGORITHM auth,
                   DOT11_CIPHER_ALGORITHM cipher,
                   int secured) {
    n->severity = SEV_INFO;
    n->check_count = 0;

    /* 1. Encryption present */
    int is_open = (!secured) ||
                  (auth == DOT11_AUTH_ALGO_80211_OPEN &&
                   cipher == DOT11_CIPHER_ALGO_NONE);
    if (is_open && auth != DOT11_AUTH_ALGO_OWE) {
        add_check(n, SEV_CRITICAL, "No encryption (open network)",
                  "Traffic is sent in clear text; anyone in range can read it.",
                  "Enable WPA2-AES at minimum; prefer WPA3. Use a VPN on open WiFi.");
    } else {
        add_check(n, SEV_INFO, "Encryption enabled",
                  "The network advertises link-layer encryption.",
                  "Keep encryption enabled.");
    }

    /* 2. Cipher strength */
    if (cipher == DOT11_CIPHER_ALGO_WEP ||
        cipher == DOT11_CIPHER_ALGO_WEP40 ||
        cipher == DOT11_CIPHER_ALGO_WEP104 ||
        auth == DOT11_AUTH_ALGO_80211_SHARED_KEY) {
        add_check(n, SEV_CRITICAL, "WEP cipher in use",
                  "WEP is cryptographically broken and recoverable quickly.",
                  "Replace WEP with WPA2-AES or WPA3 immediately.");
    } else if (cipher == DOT11_CIPHER_ALGO_TKIP) {
        add_check(n, SEV_MEDIUM, "TKIP cipher in use",
                  "TKIP is deprecated and weaker than AES (CCMP).",
                  "Configure the AP to use AES (CCMP) only; disable TKIP.");
    } else if (cipher == DOT11_CIPHER_ALGO_CCMP) {
        add_check(n, SEV_INFO, "AES (CCMP) cipher",
                  "Strong, modern symmetric cipher.",
                  "No action needed.");
    }

    /* 3. Authentication protocol generation */
    if (auth == DOT11_AUTH_ALGO_WPA ||
        auth == DOT11_AUTH_ALGO_WPA_PSK ||
        auth == DOT11_AUTH_ALGO_WPA_NONE) {
        add_check(n, SEV_HIGH, "Legacy WPA (v1) authentication",
                  "Original WPA is outdated and weaker than WPA2/WPA3.",
                  "Upgrade the access point to WPA2 or WPA3.");
    } else if (auth == DOT11_AUTH_ALGO_RSNA ||
               auth == DOT11_AUTH_ALGO_RSNA_PSK) {
        add_check(n, SEV_LOW, "WPA2 authentication",
                  "Acceptable, but WPA3 (SAE) resists offline guessing better.",
                  "Move to WPA3 where supported; use a long, random passphrase.");
    } else if (auth == DOT11_AUTH_ALGO_WPA3 ||
               auth == DOT11_AUTH_ALGO_WPA3_SAE) {
        add_check(n, SEV_INFO, "WPA3 authentication",
                  "Strongest current standard (SAE / 192-bit).",
                  "No action needed.");
    } else if (auth == DOT11_AUTH_ALGO_OWE) {
        add_check(n, SEV_INFO, "Enhanced Open (OWE)",
                  "Opportunistic encryption on an otherwise open network.",
                  "Good for guest networks; consider a passphrase for private use.");
    }

    /* 4. PSK vs Enterprise exposure (informational) */
    if (auth == DOT11_AUTH_ALGO_WPA_PSK ||
        auth == DOT11_AUTH_ALGO_RSNA_PSK ||
        auth == DOT11_AUTH_ALGO_WPA3_SAE) {
        add_check(n, SEV_LOW, "Pre-shared key (personal) mode",
                  "Security depends entirely on passphrase strength; a weak "
                  "passphrase is vulnerable to offline guessing if a handshake "
                  "is captured.",
                  "Use a 16+ character random passphrase; rotate if shared widely.");
    }

    /* 5. Hidden SSID */
    if (n->hidden) {
        add_check(n, SEV_INFO, "Hidden SSID",
                  "A hidden network name is trivially discoverable and is not a "
                  "real security control.",
                  "Do not rely on SSID hiding for security.");
    }

    if (n->check_count == 0) {
        add_check(n, SEV_INFO, "No obvious weaknesses observed",
                  "Based on advertised properties only; not a guarantee.",
                  "Keep firmware and security settings up to date.");
    }
}

static void fail(wa_result *r, const char *msg) {
    r->error = 1;
    strncpy(r->error_msg, msg, sizeof(r->error_msg) - 1);
    r->error_msg[sizeof(r->error_msg) - 1] = '\0';
}

/* Compare a network's SSID against a DOT11_SSID. */
static int ssid_matches(const wa_network *n, const DOT11_SSID *s) {
    size_t len = s->uSSIDLength;
    if (len >= WA_MAX_SSID) len = WA_MAX_SSID - 1;
    if (strlen(n->ssid) != len) return 0;
    return memcmp(n->ssid, s->ucSSID, len) == 0;
}

/* Attach per-BSSID radio details from a BSS list to matching networks. */
static void attach_bss(wa_result *r, PWLAN_BSS_LIST bl) {
    for (DWORD i = 0; i < bl->dwNumberOfItems; i++) {
        WLAN_BSS_ENTRY *e = &bl->wlanBssEntries[i];
        for (int k = 0; k < r->count; k++) {
            wa_network *n = &r->items[k];
            if (!ssid_matches(n, &e->dot11Ssid)) continue;
            if (n->bss_actual >= WA_MAX_BSS) break;
            wa_bss *b = &n->bss[n->bss_actual++];
            snprintf(b->bssid, sizeof(b->bssid),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     e->dot11Bssid[0], e->dot11Bssid[1], e->dot11Bssid[2],
                     e->dot11Bssid[3], e->dot11Bssid[4], e->dot11Bssid[5]);
            b->rssi = e->lRssi;
            b->quality = (int)e->uLinkQuality;
            b->channel = freq_to_channel(e->ulChCenterFrequency,
                                         b->band, sizeof(b->band));
            break;
        }
    }
}

wa_result wa_scan(void) {
    wa_result r;
    memset(&r, 0, sizeof(r));

    DWORD negotiated = 0;
    HANDLE h = NULL;
    if (WlanOpenHandle(2, NULL, &negotiated, &h) != ERROR_SUCCESS) {
        fail(&r, "Could not open WLAN handle (is the WLAN service running?).");
        return r;
    }

    PWLAN_INTERFACE_INFO_LIST iflist = NULL;
    if (WlanEnumInterfaces(h, NULL, &iflist) != ERROR_SUCCESS ||
        !iflist || iflist->dwNumberOfItems == 0) {
        fail(&r, "No wireless interface found.");
        if (iflist) WlanFreeMemory(iflist);
        WlanCloseHandle(h, NULL);
        return r;
    }

    /* First pass: count networks. */
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

    /* Second pass: fill records + assess. */
    for (DWORD i = 0; i < iflist->dwNumberOfItems; i++) {
        const GUID *guid = &iflist->InterfaceInfo[i].InterfaceGuid;
        PWLAN_AVAILABLE_NETWORK_LIST nl = NULL;
        if (WlanGetAvailableNetworkList(
                h, guid,
                WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
                NULL, &nl) == ERROR_SUCCESS && nl) {
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
                n->signal_pct = (int)src->wlanSignalQuality;
                n->bss_count  = src->uNumberOfBssids;
                n->secured    = src->bSecurityEnabled ? 1 : 0;

                assess(n, src->dot11DefaultAuthAlgorithm,
                       src->dot11DefaultCipherAlgorithm, n->secured);
                r.count++;
            }
            WlanFreeMemory(nl);
        }

        /* Per-radio details for this interface. */
        PWLAN_BSS_LIST bl = NULL;
        if (WlanGetNetworkBssList(h, guid, NULL, dot11_BSS_type_any,
                                  FALSE, NULL, &bl) == ERROR_SUCCESS && bl) {
            attach_bss(&r, bl);
            WlanFreeMemory(bl);
        }
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
