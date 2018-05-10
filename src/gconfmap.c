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
                       const char *key_name)
{
    gchar *key, *ret = NULL;
    GError *error = NULL;
    GConfValue *value;
    GSList *list, *entry;
    gint i;

    key = g_strdup_printf(ICD_GCONF_PATH "/%s/%s", iap_name, key_name);
    value = gconf_client_get(gconf_client, key, &error);
    if (value == NULL) {
/*
TODO
        check_gconf_error(&error);
        g_free(key);
*/
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
        //ILOG_ERR("GConf error: Expected `string' or `list of int' for key %s", key);
    }
    gconf_value_free(value);
    g_free(key);

    return ret;
}

/* TODO: COPYRIGHT: from libicd-network-wlan wlan.c */
/* TODO: pick better name */
static gchar *get_iap_config_string(GConfClient *gconf_client,
                    const char *iap_name,
                    const char *key_name)
{
    gchar *key, *value;
    GError *error = NULL;

    key = g_strdup_printf(ICD_GCONF_PATH "/%s/%s", iap_name, key_name);
    value = gconf_client_get_string(gconf_client, key, &error);
    g_free(key);

	/* TODO: What to do with error? Do not like hiding errors! */
    //check_gconf_error(&error);
	if (error != NULL) {
		fprintf(stderr, "Failed to get string value: %s\n", error->message);
		g_error_free(error);
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
	free(net->name);
	free(net->wlan_ssid);
	free(net->type);
	free(net->wlan_security);
	free(net);
}

GConfNetwork* get_gconf_network(GConfClient *client, const char* name) {
	GConfNetwork* net = alloc_gconf_network();

	net->type = get_iap_config_string(client, name, "type");
	net->wlan_ssid = get_iap_config_bytearray(client, name, "wlan_ssid");
	net->name = get_iap_config_string(client, name, "name");
	net->wlan_security = get_iap_config_string(client, name, "wlan_security");

	net->wpapsk_config.EAP_wpa_preshared_passphrase = get_iap_config_string(client, name, "EAP_wpa_preshared_passphrase");

	/* TODO: All other values in GConfNetwork */

	fprintf(stderr, "name: %s\n", net->name);
	fprintf(stderr, "wlan_ssid: %s\n", net->wlan_ssid);
	fprintf(stderr, "type: %s\n", net->type);
	fprintf(stderr, "wlan_security: %s\n", net->wlan_security);
	fprintf(stderr, "wpa-psk passphrase: %s\n", net->wpapsk_config.EAP_wpa_preshared_passphrase);

    return net;
}

static GConfClient* client = NULL;

#if 0
int main_loop(void) {
    client = gconf_client_get_default();
    if (client == NULL) {
        fprintf(stderr, "Could not create gconf client\n");
    }
    fprintf(stderr, "Created create gconf client: %p\n", client);

	GConfNetwork* net = get_gconf_network(client, "df07958f-b408-4cc3-b0e1-5aae58aa5d11");
	if (net)
		free_gconf_network(net);

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
