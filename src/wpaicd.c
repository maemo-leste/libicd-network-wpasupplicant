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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <osso-ic.h>
#include <icd/icd_wlan_defs.h>
#include <connui/libicd-network-wlan-dev.h>

#include "wpaicd.h"

#define TEST_INTERFACE_PATH WPA_DBUS_INTERFACES_OPATH "/1"

static GDBusConnection *system_bus = NULL;
static GDBusProxy *interface_proxy = NULL;

static NetworkAdded *network_added_cb = NULL;
static void *network_added_data = NULL;

static ScanDone *scan_done_cb = NULL;
static void *scan_done_data = NULL;

static StateChange *state_change_cb = NULL;
static void *state_change_data = NULL;

static void print_bss_info(BssInfo info)
{
    /* Print */
    WPALOG_DEBUG("Signal: %d", info.signal);
    WPALOG_DEBUG("Signal: %d", info.frequency);

    if (info.infrastructure) {
        WPALOG_DEBUG("mode: infrastructure");
    } else {
        WPALOG_DEBUG("mode: ad-hoc");
    }

    gchar *ssid = calloc((info.ssid_len + 1), sizeof(char));
    memcpy(ssid, info.ssid, info.ssid_len);
    ssid[info.ssid_len] = '\0';
    WPALOG_DEBUG("ssid: %s", ssid);
    free(ssid);

    WPALOG_DEBUG("mac_addr: ");
    for (gsize i = 0; i < info.mac_addr_len; i += 1) {
        // XXX: this prints a newline every time...
        WPALOG_DEBUG("%2x", info.mac_addr[i]);
    }
}

static void set_wpa_properties(GVariant * wpa, BssInfo * info)
{
    GVariantDict wpa_dict;
    g_variant_dict_init(&wpa_dict, wpa);

    GVariant *keymgmt = NULL;
    GVariantIter keymgmtiter;
    gchar *keymgmts;
    keymgmt =
        g_variant_dict_lookup_value(&wpa_dict, "KeyMgmt",
                                    G_VARIANT_TYPE_STRING_ARRAY);

    g_variant_iter_init(&keymgmtiter, keymgmt);
    while (g_variant_iter_loop(&keymgmtiter, "s", &keymgmts)) {
        _MATCH_SET(keymgmts, "wpa-psk", info->wpa.keymgmt_wpa_psk)
            _MATCH_SET(keymgmts, "wpa-eap", info->wpa.keymgmt_wpa_eap)
            _MATCH_SET(keymgmts, "wpa-none", info->wpa.keymgmt_wpa_none)
    }
    g_variant_unref(keymgmt);

    GVariant *pairwise;
    GVariantIter pairwiseiter;
    gchar *pairwises;
    pairwise =
        g_variant_dict_lookup_value(&wpa_dict, "Pairwise",
                                    G_VARIANT_TYPE_STRING_ARRAY);

    g_variant_iter_init(&pairwiseiter, pairwise);
    while (g_variant_iter_loop(&pairwiseiter, "s", &pairwises)) {
        _MATCH_SET(pairwises, "ccmp", info->wpa.pairwise_ccmp)
            _MATCH_SET(pairwises, "tkip", info->wpa.pairwise_tkip)
    }
    g_variant_unref(pairwise);

    gchar *group;
    g_variant_dict_lookup(&wpa_dict, "Group", "s", &group);
    _MATCH_SET(group, "ccmp", info->wpa.group_ccmp)
        _MATCH_SET(group, "tkip", info->wpa.group_tkip)
        _MATCH_SET(group, "wep104", info->wpa.group_wep104)
        _MATCH_SET(group, "wep40", info->wpa.group_wep40)
        free(group);

    GVariant *v = g_variant_dict_end(&wpa_dict);
    g_variant_unref(v);

    return;
}

static void set_rsn_properties(GVariant * rsn, BssInfo * info)
{
    GVariantDict rsn_dict;
    g_variant_dict_init(&rsn_dict, rsn);

    GVariant *keymgmt = NULL;
    GVariantIter keymgmtiter;
    gchar *keymgmts;
    keymgmt =
        g_variant_dict_lookup_value(&rsn_dict, "KeyMgmt",
                                    G_VARIANT_TYPE_STRING_ARRAY);

    g_variant_iter_init(&keymgmtiter, keymgmt);
    while (g_variant_iter_loop(&keymgmtiter, "s", &keymgmts)) {
        _MATCH_SET(keymgmts, "wpa-psk", info->rsn.keymgmt_wpa_psk)
            _MATCH_SET(keymgmts, "wpa-eap", info->rsn.keymgmt_wpa_eap)
            _MATCH_SET(keymgmts, "wpa-ft-psk", info->rsn.keymgmt_wpa_ft_psk)
            _MATCH_SET(keymgmts, "wpa-psk-sha256",
                       info->rsn.keymgmt_wpa_psk_sha256)
            _MATCH_SET(keymgmts, "wpa-eap-sha256",
                       info->rsn.keymgmt_wpa_eap_sha256)
    }
    g_variant_unref(keymgmt);

    GVariant *pairwise;
    GVariantIter pairwiseiter;
    gchar *pairwises;
    pairwise =
        g_variant_dict_lookup_value(&rsn_dict, "Pairwise",
                                    G_VARIANT_TYPE_STRING_ARRAY);

    g_variant_iter_init(&pairwiseiter, pairwise);
    while (g_variant_iter_loop(&pairwiseiter, "s", &pairwises)) {
        _MATCH_SET(pairwises, "ccmp", info->rsn.pairwise_ccmp)
            _MATCH_SET(pairwises, "tkip", info->rsn.pairwise_tkip)
    }
    g_variant_unref(pairwise);

    gchar *group;
    g_variant_dict_lookup(&rsn_dict, "Group", "s", &group);

    _MATCH_SET(group, "ccmp", info->rsn.group_ccmp)
        _MATCH_SET(group, "tkip", info->rsn.group_tkip)
        _MATCH_SET(group, "wep104", info->rsn.group_wep104)
        _MATCH_SET(group, "wep40", info->rsn.group_wep40)
        free(group);

    if (g_variant_dict_contains(&rsn_dict, "MgmtGroup")) {
        gchar *mgmtgroup;
        g_variant_dict_lookup(&rsn_dict, "MgmtGroup", "s", &mgmtgroup);

        _MATCH_SET(mgmtgroup, "aes128cmac", info->rsn.mgmtgroup_aes128cmac)
            free(mgmtgroup);
    }

    GVariant *v = g_variant_dict_end(&rsn_dict);
    g_variant_unref(v);

    return;
}

static GError *get_bss_info(const gchar * bss_path, BssInfo * info)
{
    GError *err = NULL;

    GVariant *bss = g_dbus_connection_call_sync(system_bus,
                                                WPA_DBUS_SERVICE,
                                                bss_path,
                                                DBUS_PROPERTIES_INTERFACE_NAME,
                                                "GetAll",
                                                g_variant_new("(s)",
                                                              WPA_DBUS_BSS_INTERFACE),
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1,
                                                NULL,
                                                &err);

    if (err != NULL) {
        return err;
    }
#ifdef _WPA_ICD_DEBUG
    WPALOG_DEBUG("bss info: %s", g_variant_print(bss, TRUE));
#endif
    GVariant *bss_info = g_variant_get_child_value(bss, 0);

    /* Get values */
    GVariantDict bss_info_dict;
    g_variant_dict_init(&bss_info_dict, bss_info);

    gchar *mode;

    _BSS_SIMPLE_INFO_FROM_DICT(&bss_info_dict, "Signal", &info->signal,
                               G_VARIANT_TYPE_INT16, "n")
    _BSS_SIMPLE_INFO_FROM_DICT(&bss_info_dict, "Frequency",
                               &info->frequency, G_VARIANT_TYPE_UINT16, "q")
    /* ad-hoc, infrastructure */
    _BSS_SIMPLE_INFO_FROM_DICT(&bss_info_dict, "Mode", &mode,
                               G_VARIANT_TYPE_STRING, "s")
    info->infrastructure = strcmp(mode, "infrastructure") == 0;
    free(mode);

    _BSS_SIMPLE_INFO_FROM_DICT(&bss_info_dict, "Privacy", &info->privacy,
                               G_VARIANT_TYPE_BOOLEAN, "b")

    _BSS_BYTESTRING_FROM_DICT(&bss_info_dict, "SSID", info->ssid,
                              info->ssid_len);
    _BSS_BYTESTRING_FROM_DICT(&bss_info_dict, "BSSID", info->mac_addr,
                              info->mac_addr_len);

    GVariant *rsn = g_variant_dict_lookup_value(&bss_info_dict, "RSN",
                                                G_VARIANT_TYPE_VARDICT);
    set_rsn_properties(rsn, info);
    g_variant_unref(rsn);

    GVariant *wpa = g_variant_dict_lookup_value(&bss_info_dict, "WPA",
                                                G_VARIANT_TYPE_VARDICT);
    set_wpa_properties(wpa, info);
    g_variant_unref(wpa);

    /* TODO: WPS */
    /* TODO: Privacy (?), Rates, Age */

    GVariant *v = g_variant_dict_end(&bss_info_dict);
    g_variant_unref(v);

    /* Clean up */
    g_variant_unref(bss_info);
    g_variant_unref(bss);

    return NULL;
}

void wpaicd_destroy_bss_info(BssInfo * info)
{
    free(info->ssid);
    free(info->mac_addr);
    free(info);
}

char *wpaicd_add_network(GConfNetwork * net)
{
    GError *err = NULL;

    GVariant *args = gconfnet_to_wpadbus(net);
    if (args == NULL) {
        return NULL;
    }

    GVariant *ret = g_dbus_connection_call_sync(system_bus,
                                                WPA_DBUS_SERVICE,
                                                TEST_INTERFACE_PATH,
                                                WPA_DBUS_INTERFACES_INTERFACE,
                                                "AddNetwork",
                                                args,
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1,
                                                NULL,
                                                &err);

    if (err != NULL) {
        WPALOG_ERR("Could not add network: %s", err->message);
        g_error_free(err);
        return NULL;
    }

    char *path = NULL;
    g_variant_get(ret, "(o)", &path);
    g_variant_unref(ret);

    return path;
}

/* TODO: '/' means no connected network */
char *wpaicd_current_network_path()
{
    GError *err = NULL;

    GVariant *ret = g_dbus_connection_call_sync(system_bus,
                                                WPA_DBUS_SERVICE,
                                                TEST_INTERFACE_PATH,
                                                DBUS_PROPERTIES_INTERFACE_NAME,
                                                "Get",
                                                g_variant_new("(ss)",
                                                              WPA_DBUS_INTERFACES_INTERFACE,
                                                              "CurrentNetwork"),
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1,
                                                NULL,
                                                &err);

    if (err != NULL) {
        WPALOG_ERR("Could not get current network path: %s",
                err->message);
        g_error_free(err);
        return NULL;
    }

    GVariant *tmp = NULL;
    g_variant_get(ret, "(v)", &tmp);
    const char *varpath = g_variant_get_string(tmp, NULL);
    char *path = g_strdup(varpath);
    g_variant_unref(tmp);
    g_variant_unref(ret);

    return path;
}

/* TODO: '/' means not connected to a BSS*/
char *wpaicd_current_bss_path()
{
    GError *err = NULL;

    GVariant *ret = g_dbus_connection_call_sync(system_bus,
                                                WPA_DBUS_SERVICE,
                                                TEST_INTERFACE_PATH,
                                                DBUS_PROPERTIES_INTERFACE_NAME,
                                                "Get",
                                                g_variant_new("(ss)",
                                                              WPA_DBUS_INTERFACES_INTERFACE,
                                                              "CurrentBSS"),
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1,
                                                NULL,
                                                &err);

    if (err != NULL) {
        WPALOG_ERR("Could not get current network path: %s",
                  err->message);
        g_error_free(err);
        return NULL;
    }

    GVariant *tmp = NULL;
    g_variant_get(ret, "(v)", &tmp);

    const char *varpath = g_variant_get_string(tmp, NULL);
    char *path = g_strdup(varpath);

    g_variant_unref(tmp);
    g_variant_unref(ret);

    return path;
}

BssInfo *wpaicd_current_bss_info()
{
    GError *err = NULL;

    BssInfo *info = calloc(1, sizeof(BssInfo));

    if (info == NULL)
        return NULL;

    char *path = wpaicd_current_bss_path();
    if (path == NULL) {
        wpaicd_destroy_bss_info(info);
        return NULL;
    }

    if (strcmp(path, "/") == 0) {
        WPALOG_ERR("No bss path!");
        wpaicd_destroy_bss_info(info);
        return NULL;
    }

    err = get_bss_info(path, info);

    if (err != NULL) {
        WPALOG_ERR("Unable to get current bss info: %s", err->message);
        g_error_free(err);
        g_free(path);
        return NULL;
    }

    g_free(path);

    return info;
}

int wpaicd_remove_all_networks(void)
{
    GError *err = NULL;

    GVariant *ret = g_dbus_connection_call_sync(system_bus,
                                                WPA_DBUS_SERVICE,
                                                TEST_INTERFACE_PATH,
                                                WPA_DBUS_INTERFACES_INTERFACE,
                                                "RemoveAllNetworks",
                                                NULL,
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1,
                                                NULL,
                                                &err);

    if (err != NULL) {
        WPALOG_ERR("Could not add network: %s", err->message);
        g_error_free(err);
        return 1;
    }

    g_variant_unref(ret);

    return 0;
}

int wpaicd_select_network(const char *network_path)
{
    GError *err = NULL;

    GVariant *args;

    args = g_variant_new("(o)", network_path);

    GVariant *ret = g_dbus_connection_call_sync(system_bus,
                                                WPA_DBUS_SERVICE,
                                                TEST_INTERFACE_PATH,
                                                WPA_DBUS_INTERFACES_INTERFACE,
                                                "SelectNetwork",
                                                args,
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1,
                                                NULL,
                                                &err);

    if (err != NULL) {
        WPALOG_ERR("Could not select network: %s", err->message);
        g_error_free(err);
        return 1;
    }

    g_variant_unref(ret);

    return 0;
}

static void property_changed(GVariant * params)
{
#ifdef _WPA_ICD_DEBUG
    WPALOG_DEBUG("properties_changed: %s", g_variant_print(params, TRUE));
#endif

    GVariant *d = NULL;
    GVariant *state = NULL;

    d = g_variant_get_child_value(params, 0);

    state = g_variant_lookup_value(d, "State", G_VARIANT_TYPE_STRING);

    if (state) {
        const char *state_s = g_variant_get_string(state, NULL);

        if (state_change_cb) {
            state_change_cb(state_s, state_change_data);
        }

        g_variant_unref(state);
    }

    g_variant_unref(d);
}

/* TODO: Rename function, split up for various signals */
static void on_scan_done(GDBusProxy * proxy,
                         gchar * sender_name,
                         gchar * signal_name,
                         GVariant * parameters, gpointer user_data)
{
    if (strcmp(signal_name, "PropertiesChanged") == 0) {
        property_changed(parameters);
        return;
    }

    if (strcmp(signal_name, "ScanDone")) {
        WPALOG_DEBUG("Ignoring: %s", signal_name);
        return;
    }

    /* TODO: Ensure everything is freed, GError checking, Gerror re-initialisation, etc */
    /* TODO: Ensure that we properly deal with errors / missing values */

    WPALOG_DEBUG("on_scan_done. params: %s",
            g_variant_print(parameters, TRUE));

    GError *error = NULL;

    GVariant *bsss = g_dbus_connection_call_sync(system_bus,
                                                 WPA_DBUS_SERVICE,
                                                 TEST_INTERFACE_PATH,
                                                 DBUS_PROPERTIES_INTERFACE_NAME,
                                                 "Get",
                                                 g_variant_new("(ss)",
                                                               WPA_DBUS_INTERFACES_INTERFACE,
                                                               "BSSs"),
                                                 NULL,
                                                 G_DBUS_CALL_FLAGS_NONE,
                                                 -1,
                                                 NULL,
                                                 &error);

    if (bsss == NULL) {
        WPALOG_ERR("Could not get BSSs: %s", error->message);
        g_error_free(error);
        return;
    }

    GVariant *tmp = g_variant_get_child_value(bsss, 0);
    GVariant *tmp2 = g_variant_get_child_value(tmp, 0);

    GVariantIter *iter;
    iter = g_variant_iter_new(tmp2);

    for (unsigned int i = 0; i < g_variant_iter_n_children(iter); i++) {
        GVariant *val;
        val = g_variant_iter_next_value(iter);

        const gchar *bss_path = g_variant_get_string(val, NULL);
        BssInfo *info = calloc(1, sizeof(BssInfo));

        error = get_bss_info(bss_path, info);
        if (error) {
            WPALOG_ERR("Could not get BSS info for %s (%s)",
                    bss_path, error->message);
            g_error_free(error);

            g_variant_unref(val);
            wpaicd_destroy_bss_info(info);
            continue;
        }

        g_variant_unref(val);

        if (network_added_cb) {
            network_added_cb(info, network_added_data);
        }

        wpaicd_destroy_bss_info(info);
    }

    g_variant_iter_free(iter);
    g_variant_unref(tmp);
    g_variant_unref(tmp2);
    g_variant_unref(bsss);

    if (scan_done_cb) {
        scan_done_cb(0 /* TODO */ , scan_done_data);
    }

}

int wpaicd_initiate_scan(void)
{
    GError *error = NULL;
    GVariantBuilder *b;
    GVariant *args = NULL;

    b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(b, "{sv}", "Type", g_variant_new_string("active"));

    /* Do not need to be unref'd, call_sync does that apparently */
    args = g_variant_new("(a{sv})", b);

    g_variant_builder_unref(b);

    GVariant *ret = g_dbus_connection_call_sync(system_bus,
                                                WPA_DBUS_SERVICE,
                                                TEST_INTERFACE_PATH,
                                                "fi.w1.wpa_supplicant1.Interface",
                                                "Scan",
                                                args,
                                                NULL,
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1,
                                                NULL,
                                                &error);

    if (error != NULL) {
        WPALOG_ERR("Could not start scan: %s", error->message);
        g_error_free(error);
        return 1;
    }

    g_variant_unref(ret);

    return 0;
}

guint wpaicd_bssinfo_to_network_attrs(BssInfo * info)
{
    gboolean is_wpa2_psk = info->rsn.keymgmt_wpa_psk ||
                           info->rsn.keymgmt_wpa_ft_psk ||
                           info->rsn.keymgmt_wpa_psk_sha256;
    gboolean is_wpa_psk =  info->wpa.keymgmt_wpa_psk;

    gboolean is_wpa2_eap = info->rsn.keymgmt_wpa_eap ||
                           info->rsn.keymgmt_wpa_ft_eap ||
                           info->rsn.keymgmt_wpa_eap_sha256;
    gboolean is_wpa_eap = info->wpa.keymgmt_wpa_eap;
    guint cap = 0;
    guint attr = 0;

    if (info->infrastructure) {
        cap |= WLANCOND_INFRA;
    } else {
        /* TODO: WLANCOND_ADHOC, WLANCOND_AUTO ? */
    }

    if (is_wpa_eap || is_wpa2_eap) {
        attr |= WLAN_SECURITY_WPA_PSK;
        cap |= WLANCOND_WPA_EAP;
    } else if (is_wpa_psk || is_wpa2_psk) {
        attr |= WLAN_SECURITY_WPA_PSK;
        cap |= WLANCOND_WPA_PSK;
    } else if (info->privacy) {
        /* WEP has no WPA nor RSN key management, but does have privacy flag,
         * this likely needs to be reworked a bit more, but it works for now. */
        attr |= WLAN_SECURITY_WEP;
        cap |= WLANCOND_WEP;
    } else {
        attr |= WLAN_SECURITY_OPEN;
        cap |= WLANCOND_OPEN;
    }

    if (is_wpa2_eap || is_wpa2_psk) {
        cap |= WLANCOND_WPA2;
    }

    /* TODO: WLANCOND rates; see wlancond.h */
    /* TODO: WLANCOND encrypt/alg masks; see wlancond.h */

    cap2nwattr(cap, &attr);
    return attr;
}

int wpaicd_init(void)
{
    GError *error = NULL;

    system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (system_bus == NULL) {
        WPALOG_CRIT("Could not get dbus system session bus: %s",
                  error->message);
        g_error_free(error);
        return 1;
    }

    interface_proxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
                                                    G_DBUS_PROXY_FLAGS_NONE
                                                    |
                                                    G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
                                                    NULL, WPA_DBUS_SERVICE,
                                                    TEST_INTERFACE_PATH,
                                                    WPA_DBUS_INTERFACES_INTERFACE,
                                                    NULL, &error);

    if (error != NULL) {
        WPALOG_CRIT("Could not create interface proxy: %s",
                  error->message);
        g_error_free(error);
        return 1;
    }

    g_signal_connect(interface_proxy, "g-signal",
                     G_CALLBACK(on_scan_done), NULL);

    return 0;
}

void wpaicd_free(void)
{
    g_object_unref(interface_proxy);
    g_object_unref(system_bus);
}

void wpaicd_set_network_added_cb(NetworkAdded * cb, void *data)
{
    network_added_cb = cb;
    network_added_data = data;
}

void wpaicd_set_scan_done_cb(ScanDone * cb, void *data)
{
    scan_done_cb = cb;
    scan_done_data = data;
}

void wpaicd_set_state_change_cb(StateChange * cb, void *data)
{
    state_change_cb = cb;
    state_change_data = data;
}

#if 0
void wpaicd_test_network_added_cb(BssInfo * info, void *data)
{
    print_bss_info(*info);

    return;
}

void wpaicd_test_scan_done_cb(int ret, void *data)
{
    WPALOG_DEBUG("scan done, ret: %d", ret);

    GConfClient *client;
    client = gconf_client_get_default();
    GConfNetwork *net = get_gconf_network_iapname(client, "8ed28b2b-d17e-4b00-ad91-d42393bada62");

    char *path = wpaicd_add_network(net);
    wpaicd_select_network(path);
    free(path);

    free_gconf_network(net);
    g_object_unref(client);

/*
    usleep(10 * 1000 * 1000);
    wpaicd_remove_all_networks();
*/

    return;
}

void wpaicd_test_state_change_cb(const char *state, void *data)
{
    WPALOG_DEBUG("state change: %s", state);

    char *net = wpaicd_current_network_path();
    WPALOG_DEBUG("Current network path: %s", net);
    free(net);

    char *bss = wpaicd_current_bss_path();
    WPALOG_DEBUG("Current BSS path: %s", bss);
    free(bss);

    BssInfo *info = wpaicd_current_bss_info();
    char *tmpssid = malloc(info->ssid_len + 1);
    strncpy(tmpssid, info->ssid, info->ssid_len);
    tmpssid[info->ssid_len] = '\0';
    WPALOG_DEBUG("Current BSS ssid: %s", tmpssid);
    free(tmpssid);
    wpaicd_destroy_bss_info(info);
}

int main_loop(void)
{
    static GMainLoop *loop = NULL;

    if (wpaicd_init()) {
        WPALOG_CRIT("Failed to initialise");
        return 1;
    }

    wpaicd_set_network_added_cb(wpaicd_test_network_added_cb, (void *)42);
    wpaicd_set_scan_done_cb(wpaicd_test_scan_done_cb, (void *)42);
    wpaicd_set_state_change_cb(wpaicd_test_state_change_cb, (void *)42);

    wpaicd_initiate_scan();

    loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);

    wpaicd_free();

    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    main_loop();
}
#endif
