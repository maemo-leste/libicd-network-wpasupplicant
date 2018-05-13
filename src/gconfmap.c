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


/* TODO: COPYRIGHT: from libicd-network-wlan wlan.c */
/* TODO: pick better name */
static gchar *get_iap_config_bytearray(GConfClient *gconf_client,
                       const char *iap_name,
                       const char *key_name,
					   GError **error)
{
    gchar *key, *ret = NULL;
    GConfValue *value;
    GSList *list, *entry;
    gint i;

    //key = g_strdup_printf(ICD_GCONF_PATH "/%s/%s", iap_name, key_name);
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
		/* TODO return/print error */
    }
    gconf_value_free(value);
    g_free(key);

    return ret;
}

/* TODO: COPYRIGHT: from libicd-network-wlan wlan.c */
/* TODO: pick better name */
static gchar *get_iap_config_string(GConfClient *gconf_client,
                    const char *iap_name,
                    const char *key_name,
					GError **error)
{
	/* TODO: Take pointer to GError ? */
    gchar *key, *value;

    key = g_strdup_printf("%s/%s", iap_name, key_name);
    //key = g_strdup_printf(ICD_GCONF_PATH "/%s/%s", iap_name, key_name);
    value = gconf_client_get_string(gconf_client, key, error);
    g_free(key);

	/* TODO: What to do with error? Do not like hiding errors! */
    //check_gconf_error(&error);
	if (*error != NULL) {
		return NULL;
	}

    return value;
}

GConfNetwork* alloc_gconf_network(void) {
    GConfNetwork *net = malloc(sizeof(GConfNetwork));
	if (net) {
		memset(net, 0, sizeof(GConfNetwork));
	}
	return net;
}

void free_gconf_network(GConfNetwork* net) {
	/* TODO: Also free other values in the sub structs */
	free(net->wpapsk_config.EAP_wpa_preshared_passphrase);
	free(net->wlan_security);
	free(net->name);
	free(net->wlan_ssid);
	free(net->type);
	free(net->id);
	free(net);
}

static char* get_iap_name_from_path(char *path) {
    char* saveptr = NULL;
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


#define GCONF_IAP_READ_STRING(func, structvar, var) \
{ \
	net->structvar = func(client, name, var, &error); \
	/* TODO: Print error as well? */ \
	if (error != NULL) { \
		g_error_free(error); \
		free_gconf_network(net); \
		return NULL; \
	} \
}

GConfNetwork* get_gconf_network_iapname(GConfClient *client, const char* iapname) {
    GConfNetwork* r = NULL;
    gchar* key = g_strdup_printf(ICD_GCONF_PATH "/%s", iapname);
    r = get_gconf_network(client, key);
    g_free(key);
    return r;
}

GConfNetwork* get_gconf_network(GConfClient *client, const char* name) {
	GConfNetwork* net = alloc_gconf_network();
	GError *error = NULL;

	net->id = get_iap_name_from_path((char*)name);
	GCONF_IAP_READ_STRING(get_iap_config_string, type, "type")
	GCONF_IAP_READ_STRING(get_iap_config_bytearray, wlan_ssid, "wlan_ssid")
	GCONF_IAP_READ_STRING(get_iap_config_string, name, "name")
	GCONF_IAP_READ_STRING(get_iap_config_string, wlan_security, "wlan_security")
	GCONF_IAP_READ_STRING(get_iap_config_string, wpapsk_config.EAP_wpa_preshared_passphrase, "EAP_wpa_preshared_passphrase")

	/* TODO: All other values in GConfNetwork */

    return net;
}

GSList* get_gconf_networks(GConfClient *client) {
	GSList *ret = NULL;

    GError *error = NULL;
    GSList *iap_list, *iap_iter;

    iap_list = gconf_client_all_dirs(client,
                     ICD_GCONF_PATH,
                     &error);

    if (error != NULL) {
        fprintf(stderr, "Cannot get dirs in gconf:%s \n", error->message);
        g_error_free(error);
        return NULL;
    }

    iap_iter = iap_list;

    while (iap_iter) {
        if (iap_iter->data == NULL) {
            iap_iter = g_slist_next(iap_iter);
			/* XXX: This should never happen */
            //fprintf(stderr, "gconfmap: No data from gconf?");

            continue;
        }

		GConfNetwork* net = get_gconf_network(client, (char*)iap_iter->data);
		ret = g_slist_append(ret, (void*)net);

		g_free(iap_iter->data);
        iap_iter = g_slist_next(iap_iter);
    }
	g_slist_free(iap_list);

	return ret;
}

static GConfClient* client = NULL;

#if 0
int main_loop(void) {
    client = gconf_client_get_default();
    if (client == NULL) {
        fprintf(stderr, "Could not create gconf client\n");
    }
    fprintf(stderr, "Got gconf client: %p\n", client);

#if 0
    GConfNetwork* net = get_gconf_network_iapname(client, "550bcade-e34e-4dcf-8d3f-b492b47f21e8");
    fprintf(stderr, "name: %s\n", net->name);
    fprintf(stderr, "wlan_ssid: %s\n", net->wlan_ssid);
    fprintf(stderr, "type: %s\n", net->type);
    fprintf(stderr, "wlan_security: %s\n", net->wlan_security);
    fprintf(stderr, "wpa-psk passphrase: %s\n", net->wpapsk_config.EAP_wpa_preshared_passphrase);
    free_gconf_network(net);
#endif

#if 0
	GSList *iaps = get_gconf_networks(client);

	GSList *iap_iter = iaps;
	while (iap_iter) {
		GConfNetwork* net = (GConfNetwork*)iap_iter->data;
		if (net) {
			fprintf(stderr, "id: %s\n", net->id);
			fprintf(stderr, "name: %s\n", net->name);
			fprintf(stderr, "wlan_ssid: %s\n", net->wlan_ssid);
			fprintf(stderr, "type: %s\n", net->type);
			fprintf(stderr, "wlan_security: %s\n", net->wlan_security);
			fprintf(stderr, "wpa-psk passphrase: %s\n", net->wpapsk_config.EAP_wpa_preshared_passphrase);
			free_gconf_network(net);
		}

        iap_iter = g_slist_next(iap_iter);
	}

	g_slist_free(iaps);
#endif

	g_object_unref(client);

    return 0;
}

int
main (int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    main_loop();
}
#endif
