/***********************************************************************************
*  libicd-network-wpasupplicant: Open source implementation of wpa_supplicant
*  integration icd2 on Maemo Leste
*  Copyright (C) 2018 Merlijn B. W. Wajer
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*
***********************************************************************************/

/* This file implements reading an entire gconf network structure into a C
 * structure. In the near future, it will likely also map the gconf network
 * details to a structure that wpaicd (wpa_supplicant code) will understand.
 * Some code/headers should probably be shared with connui-wlan and other
 * packages.*/

#ifndef _GCONFMAP_H_
#define _GCONFMAP_H_

#include <gio/gio.h>
#include <gconf/gconf-client.h>

#include "log-common.h"
/*
TODO:
   See:

   - connui-wlan/wizard/wlan.c -- perhaps share code or defines?
   - http://maemo.org/community/maemo-developers/information_required_to_replace_maemo5_wlan_bits/

   Missing keys:
   - wlan_tx_power
   - nai
   - powersave_after_scan
   - wlan_powersave
   - EAP_SIMPLE_CONFIG_device_password
   - TLS_server_authenticates_client_policy_in_client
   -allow_wep_ciphers_in_WPA
*/

/* FIXME/TODO/XXX: Share or take-from connui */
#define EAP_GTC         6
#define EAP_TLS         13
#define EAP_TTLS        21
#define EAP_PEAP        25
#define EAP_MS          26
#define EAP_TTLS_PAP        98
#define EAP_TTLS_MS     99


typedef struct {
    /* if (get_iap_config_bool(ctx->gconf_client, NULL, * "allow_wep_ciphers_in_WPA", FALSE)) */
    gboolean allow_wep_ciphers_in_WPA;

} GConfNetworkPolicies;

typedef struct {
    gboolean EAP_MSCHAPV2_password_prompt;

    char* EAP_MSCHAPV2_username;
    char* EAP_MSCHAPV2_password;

    gboolean EAP_wpa2_only_mode;

    gint EAP_default_type;

    gint PEAP_tunneled_eap_type;

    char *EAP_GTC_identity;
    char *EAP_GTC_passcode;

    char *EAP_TLS_PEAP_client_certificate_file;

    char *EAP_manual_username;
    gboolean EAP_use_manual_username;
} GConfNetworkWPAEAP;

typedef struct {
    char *wlan_wepkey1;
    char *wlan_wepkey2;
    char *wlan_wepkey3;
    char *wlan_wepkey4;

    gint wlan_wepdefkey;
} GConfNetworkWEP;

typedef struct {
    gint wlan_adhoc_channel;
} GConfNetworkAdhoc;

typedef struct {
    /* Passphrase to use with WPA_PSK security mode */
    char *EAP_wpa_preshared_passphrase;
} GConfNetworkWPAPSK;

typedef struct {
    /* IAP name */
    char *id;

    /* Connection name */
    char *name;

    /* TODO: This should be a set of bytes, not string, since APs can contain, afaik, null chars */
    char *wlan_ssid;

    /* One-of: "WLAN_INFRA", "WLAN_ADHOC" */
    char *type;

    /* One-of: "NONE", "WEP", "WPA_PSK", "WPA_EAP" */
    char *wlan_security;

    gboolean temporary;
    gboolean hidden;

    GConfNetworkWPAEAP wpaeap_config;
    GConfNetworkWPAPSK wpapsk_config;
    GConfNetworkWEP wep_config;
    GConfNetworkAdhoc adhoc_config;
    GConfNetworkPolicies policy_config;
} GConfNetwork;

GConfNetwork *get_gconf_network(GConfClient * client, const char *name);
GConfNetwork *get_gconf_network_iapname(GConfClient * client,
                                        const char *iapname);
GSList *get_gconf_networks(GConfClient * client);

GVariant *gconfnet_to_wpadbus(GConfNetwork * net);

GConfNetwork *alloc_gconf_network(void);
void free_gconf_network(GConfNetwork * net);

#endif                          /* _GCONFMAP_H_ */
