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
#include <stdio.h>
#include <string.h>

#include <glib-2.0/glib.h>

#include <osso-ic-gconf.h>

#include "gconfmap.h"

static gchar *get_iap_config_bytearray(GConfClient * gconf_client,
                                       const char *iap_name,
                                       const char *key_name, GError ** error)
{
    gchar *key, *ret = NULL;
    GConfValue *value;
    GSList *list, *entry;
    gint i;

    key = g_strdup_printf("%s/%s", iap_name, key_name);
    value = gconf_client_get(gconf_client, key, error);
    if ((value == NULL) || (*error != NULL)) {
        g_free(key);
        return NULL;
    }

    switch (value->type) {
    case GCONF_VALUE_STRING:
        ret = g_strdup(gconf_value_get_string(value));
        break;
    case GCONF_VALUE_LIST:
        if (gconf_value_get_list_type(value) == GCONF_VALUE_INT) {
            list = gconf_value_get_list(value);
            ret = g_new(gchar, g_slist_length(list) + 1);
            for (i = 0, entry = list; entry; entry = entry->next, i++)
                ret[i] = gconf_value_get_int(entry->data);
            ret[i] = '\0';
            break;
        }
        /* fallthrough for error */
    default:
        ;
    }
    gconf_value_free(value);
    g_free(key);

    return ret;
}

static gchar *get_iap_config_string(GConfClient * gconf_client,
                                    const char *iap_name,
                                    const char *key_name, GError ** error)
{
    gchar *key, *value;

    key = g_strdup_printf("%s/%s", iap_name, key_name);
    value = gconf_client_get_string(gconf_client, key, error);
    g_free(key);

    if (*error != NULL) {
        return NULL;
    }

    return value;
}

static gint get_iap_config_int(GConfClient* gconf_client,
                               const char *iap_name,
                               const char *key_name, GError ** error)
{
    gchar *key;
    int value;

    key = g_strdup_printf("%s/%s", iap_name, key_name);
    value = gconf_client_get_int(gconf_client, key, error);
    g_free(key);

    if (*error != NULL) {
        /* Callee must check error anyway, so that we return 0 here doesn't
         * matter. */
        return 0;
    }

    return value;
}

static gboolean get_iap_config_bool(GConfClient* gconf_client,
                               const char *iap_name,
                               const char *key_name, GError** error)
{
    gchar *key;
    GConfValue *value;
    gboolean boolval = FALSE;

    key = g_strdup_printf("%s/%s", iap_name, key_name);
    value = gconf_client_get(gconf_client, key, error);
    g_free(key);


    if (*error != NULL) {
        /* Callee must check error anyway, so that we return FALSE her
         * doesn't matter. */
        return FALSE;
    }

    if (value != NULL) {
        if (value->type == GCONF_VALUE_BOOL) {
            boolval = gconf_value_get_bool(value);
        } else {
            /* TODO XXX: Give error a GError value here? */
        }
        gconf_value_free(value);
    }


    return boolval;
}

GConfNetwork *alloc_gconf_network(void)
{
    GConfNetwork *net = malloc(sizeof(GConfNetwork));
    if (net) {
        memset(net, 0, sizeof(GConfNetwork));
    }
    return net;
}

void free_gconf_network(GConfNetwork * net)
{
    /* TODO: Also free other values in the sub structs */

    /* wpapsk_config */
    free(net->wpapsk_config.EAP_wpa_preshared_passphrase);


    /* wep_config */
    free(net->wep_config.wlan_wepkey1);
    free(net->wep_config.wlan_wepkey2);
    free(net->wep_config.wlan_wepkey3);
    free(net->wep_config.wlan_wepkey4);

    /* generic */
    free(net->wlan_security);
    free(net->name);
    free(net->wlan_ssid);
    free(net->type);
    free(net->id);
    free(net);
}

static char *get_iap_name_from_path(char *path)
{
    char *saveptr = NULL;
    char *last = NULL;
    char *cur = NULL;
    char *dup = strdup(path);

    if (dup == NULL) {
        return NULL;
    }

    last = strtok_r(dup, "/", &saveptr);
    while (1) {
        cur = strtok_r(NULL, "/", &saveptr);
        if (cur == NULL) {
            break;
        }
        last = cur;
    }

    last = strdup(last);

    free(dup);

    return last;
}

#define GCONF_IAP_READ(func, structvar, var) \
{ \
	net->structvar = func(client, name, var, &error); \
	if (error != NULL) { \
		g_error_free(error); \
		free_gconf_network(net); \
		return NULL; \
	} \
}

GConfNetwork *get_gconf_network_iapname(GConfClient * client,
                                        const char *iapname)
{
    GConfNetwork *r = NULL;
    gchar *key = g_strdup_printf(ICD_GCONF_PATH "/%s", iapname);
    r = get_gconf_network(client, key);
    g_free(key);
    return r;
}

GConfNetwork *get_gconf_network(GConfClient * client, const char *name)
{
    GConfNetwork *net = alloc_gconf_network();
    GError *error = NULL;

    net->id = get_iap_name_from_path((char *)name);
    GCONF_IAP_READ(get_iap_config_string, type, "type")
    GCONF_IAP_READ(get_iap_config_bytearray, wlan_ssid, "wlan_ssid")
    GCONF_IAP_READ(get_iap_config_string, name, "name")
    GCONF_IAP_READ(get_iap_config_string, wlan_security, "wlan_security")
    GCONF_IAP_READ(get_iap_config_bool, temporary, "temporary")

    /* wep_config */
    GCONF_IAP_READ(get_iap_config_int, wep_config.wlan_wepdefkey, "wlan_wepdefkey")

    GCONF_IAP_READ(get_iap_config_string, wep_config.wlan_wepkey1, "wlan_wepkey1")
    GCONF_IAP_READ(get_iap_config_string, wep_config.wlan_wepkey2, "wlan_wepkey2")
    GCONF_IAP_READ(get_iap_config_string, wep_config.wlan_wepkey3, "wlan_wepkey3")
    GCONF_IAP_READ(get_iap_config_string, wep_config.wlan_wepkey4, "wlan_wepkey4")


    /* wpapsk_config */
    GCONF_IAP_READ(get_iap_config_string,
                   wpapsk_config.EAP_wpa_preshared_passphrase,
                   "EAP_wpa_preshared_passphrase")

        /* TODO: All other values in GConfNetwork */
        return net;
}

GSList *get_gconf_networks(GConfClient * client)
{
    GSList *ret = NULL;

    GError *error = NULL;
    GSList *iap_list, *iap_iter;

    iap_list = gconf_client_all_dirs(client, ICD_GCONF_PATH, &error);

    if (error != NULL) {
        fprintf(stderr, "Cannot get dirs in gconf:%s \n", error->message);
        g_error_free(error);
        return NULL;
    }

    iap_iter = iap_list;

    while (iap_iter) {
        /* This should never happen */
        if (iap_iter->data == NULL) {
            iap_iter = g_slist_next(iap_iter);

            continue;
        }

        GConfNetwork *net = get_gconf_network(client, (char *)iap_iter->data);
        ret = g_slist_append(ret, (void *)net);

        g_free(iap_iter->data);
        iap_iter = g_slist_next(iap_iter);
    }
    g_slist_free(iap_list);

    return ret;
}

GVariant *gconfnet_to_wpadbus(GConfNetwork * net)
{
    GVariant *args = NULL;
    GVariantBuilder *b;

    b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

    g_variant_builder_add(b, "{sv}", "ssid",
                          g_variant_new_string(net->wlan_ssid));

    /* TODO: support ad-hoc */
    if (strcmp(net->type, "WLAN_INFRA")) {
        /* XXX: set auth_alg=NONE ? */
        goto fail;
    }

    if (!strcmp(net->wlan_security, "NONE")) {
        g_variant_builder_add(b, "{sv}", "key_mgmt",
                              g_variant_new_string("NONE"));
        g_variant_builder_add(b, "{sv}", "auth_alg",
                              g_variant_new_string("OPEN"));
    } else if (!strcmp(net->wlan_security, "WEP")) {
        switch (net->wep_config.wlan_wepdefkey) {
            case 1:
                g_variant_builder_add(b, "{sv}", "wep_key0",
                                      g_variant_new_string(net->wep_config.wlan_wepkey1));

                break;
            case 2:
                g_variant_builder_add(b, "{sv}", "wep_key1",
                                      g_variant_new_string(net->wep_config.wlan_wepkey2));

                break;
            case 3:
                g_variant_builder_add(b, "{sv}", "wep_key2",
                                      g_variant_new_string(net->wep_config.wlan_wepkey3));

                break;
            case 4:
                g_variant_builder_add(b, "{sv}", "wep_key3",
                                      g_variant_new_string(net->wep_config.wlan_wepkey4));

                break;
            default:
                fprintf(stderr, "wlan_wepdefkey not in (1,2,3,4): %d\n", net->wep_config.wlan_wepdefkey);
                goto fail;

        }
        g_variant_builder_add(b, "{sv}", "wep_tx_keyidx",
                              g_variant_new_int32(net->wep_config.wlan_wepdefkey - 1));

        g_variant_builder_add(b, "{sv}", "key_mgmt",
                              g_variant_new_string("NONE"));

        /* FIXME: WEP104 == 104 bits password, aka 26 hex digits, WEP40 == 40
         * bits password, aka 10 hex digits. We just set both for now, not sure
         * if we need to differentiate. (We could, based on the
         * 'net->wep_config.wlanwepkey?' lengths.)
         * Let's just add both for now
         */
        g_variant_builder_add(b, "{sv}", "group",
                              g_variant_new_string("WEP104 WEP40"));


        /* XXX: I think this is not always correct, there might be two different
         * WEP types... But how do we differentiate them?
         * openwrt shows: "WEP Open System" and "WEP Shared Key" (WEP104)
         * I believe WEP Open System might actually just be an open wifi with
         * some encryption, and only WEP Shared Key requires auth...
         * http://wirelessnetworkssecurity.blogspot.nl/2013/01/wep-open-key-vs-wep-shared-key.html
        */
    } else if (!strcmp(net->wlan_security, "WPA_PSK")) {
        /* Go over net->wpapsk_config */
        g_variant_builder_add(b, "{sv}", "psk",
                              g_variant_new_string(net->
                                                   wpapsk_config.EAP_wpa_preshared_passphrase));

        g_variant_builder_add(b, "{sv}", "key_mgmt",
                              g_variant_new_string("WPA-PSK"));

    } else if (!strcmp(net->wlan_security, "WPA_EAP")) {
        /* Go over net->wpaeap_config */
        goto fail;
    }

    /* Do not need to be unref'd, call_sync does that apparently */
    args = g_variant_new("(a{sv})", b);

    /* XXX: This should be debug only */
    char *pr = g_variant_print(args, TRUE);
    fprintf(stderr, "gconfnet_to_wpadbus: %s\n", pr);
    free(pr);


 fail:
    g_variant_builder_unref(b);
    return args;

}

#if 0
static GConfClient *client = NULL;

int main_loop(void)
{
    client = gconf_client_get_default();
    if (client == NULL) {
        fprintf(stderr, "Could not create gconf client\n");
    }
    fprintf(stderr, "Got gconf client: %p\n", client);

#if 0
    GConfNetwork *net =
        get_gconf_network_iapname(client,
                                  "550bcade-e34e-4dcf-8d3f-b492b47f21e8");
    fprintf(stderr, "name: %s\n", net->name);
    fprintf(stderr, "wlan_ssid: %s\n", net->wlan_ssid);
    fprintf(stderr, "type: %s\n", net->type);
    fprintf(stderr, "wlan_security: %s\n", net->wlan_security);
    fprintf(stderr, "wpa-psk passphrase: %s\n",
            net->wpapsk_config.EAP_wpa_preshared_passphrase);
    free_gconf_network(net);
#endif

#if 0
    GSList *iaps = get_gconf_networks(client);

    GSList *iap_iter = iaps;
    while (iap_iter) {
        GConfNetwork *net = (GConfNetwork *) iap_iter->data;
        if (net) {
            fprintf(stderr, "id: %s\n", net->id);
            fprintf(stderr, "name: %s\n", net->name);
            fprintf(stderr, "wlan_ssid: %s\n", net->wlan_ssid);
            fprintf(stderr, "type: %s\n", net->type);
            fprintf(stderr, "wlan_security: %s\n", net->wlan_security);
            fprintf(stderr, "wpa-psk passphrase: %s\n",
                    net->wpapsk_config.EAP_wpa_preshared_passphrase);
            free_gconf_network(net);
        }

        iap_iter = g_slist_next(iap_iter);
    }

    g_slist_free(iaps);
#endif

    g_object_unref(client);

    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    main_loop();
}
#endif
