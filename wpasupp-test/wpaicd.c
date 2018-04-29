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

#include "wpaicd.h"

#define TEST_INTERFACE "wlan0"

/* TODO: Free system_bus in free_wpaicd */
static GDBusConnection* system_bus = NULL;
static GDBusProxy *interface_proxy = NULL;


static void on_scan_done(GDBusProxy *proxy,
               gchar      *sender_name,
               gchar      *signal_name,
               GVariant   *parameters,
               gpointer    user_data) {
	if (strcmp(signal_name, "ScanDone")) {
#ifdef _WPA_ICD_DEBUG
		fprintf(stderr, "Ignoring: %s\n", signal_name);
#endif
		return;
    }

	/* TODO: Ensure everything is freed, GError checking, Gerror re-initialisation, etc */
	/* TODO: Ensure that we properly deal with errors / missing values */

#ifdef _WPA_ICD_DEBUG
    fprintf(stderr, "on_scan_done. params: %s\n", g_variant_print(parameters, TRUE));
#endif

	GError *error = NULL;

	GVariant* bsss = g_dbus_connection_call_sync(system_bus,
			WPA_DBUS_SERVICE,
			WPA_DBUS_INTERFACES_OPATH "/1",
			DBUS_PROPERTIES_INTERFACE_NAME,
			"Get",
			g_variant_new("(ss)", WPA_DBUS_INTERFACES_INTERFACE, "BSSs"),
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (bsss == NULL) {
        fprintf(stderr, "Could not get BSSs: %s\n", error->message);
        g_error_free(error);
        return;
    }

#ifdef _WPA_ICD_DEBUG
	fprintf(stderr, "bsss: %s\n", g_variant_print(bsss, TRUE));
#endif

    GVariant* tmp = g_variant_get_child_value(bsss, 0);
    GVariant* tmp2 = g_variant_get_child_value(tmp, 0);

    GVariantIter* iter;
    iter = g_variant_iter_new(tmp2);
	for (unsigned int i = 0; i < g_variant_iter_n_children(iter); i++) {
		GVariant *val;
		val = g_variant_iter_next_value(iter);
#ifdef _WPA_ICD_DEBUG
		fprintf(stderr, "subbsss: %s\n", g_variant_print(val, TRUE));
#endif

		const gchar* bss_path = g_variant_get_string(val, NULL);

		GError* err = NULL;
		GVariant* bss = g_dbus_connection_call_sync(system_bus,
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

		if (bss == NULL) {
			fprintf(stderr, "Could not get BSS info for %s (%s)\n", bss_path, err->message);
			g_error_free(err);
			g_variant_unref(val);
			continue;
		}
#ifdef _WPA_ICD_DEBUG
		fprintf(stderr, "bss info: %s\n", g_variant_print(bss, TRUE));
#endif
		GVariant* bss_info = g_variant_get_child_value(bss, 0);

		BssInfo info;

		/* Get values */
		GVariantDict bss_info_dict;
		g_variant_dict_init(&bss_info_dict, bss_info);

		_BSS_SIMPLE_INFO_FROM_DICT(&bss_info_dict, "Signal", &info.signal, G_VARIANT_TYPE_INT16, "n")
		_BSS_SIMPLE_INFO_FROM_DICT(&bss_info_dict, "Frequency", &info.frequency, G_VARIANT_TYPE_UINT16, "q")
		_BSS_BYTESTRING_FROM_DICT(&bss_info_dict, "SSID", info.ssid, info.ssid_len);
		_BSS_BYTESTRING_FROM_DICT(&bss_info_dict, "BSSID", info.mac_addr, info.mac_addr_len);

		g_variant_dict_end(&bss_info_dict);


		/* Clean up */
		g_variant_unref(bss_info);
		g_variant_unref(bss);
		g_variant_unref(val);

		/* Print */
		fprintf(stderr, "signal: %d\n", info.signal);
		fprintf(stderr, "freq: %d\n", info.frequency);

		fprintf(stderr, "ssid: ");
		for (int i = 0; i < info.ssid_len; i+=1) {
			fprintf(stderr, "%c", info.ssid[i]);
		}
		fprintf(stderr, "\n");

		fprintf(stderr, "mac_addr: ");
		for (int i = 0; i < info.mac_addr_len; i+=1) {
			 fprintf(stderr, "%2x", info.mac_addr[i]);
		}
		fprintf(stderr, "\n");
	}

	g_variant_iter_free(iter);
	g_variant_unref(tmp);
	g_variant_unref(tmp2);
	g_variant_unref(bsss);
}

int init_wpaicd(void) {
    GError *error = NULL;

    system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (system_bus == NULL) {
        fprintf(stderr, "Could not get dbus system session bus: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    GVariantBuilder *b;
    GVariant *dict = NULL;
    GVariant *args = NULL;
    
    /* TODO: FREE ALL THIS STUFF */
    b = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
    g_variant_builder_add (b, "{sv}", "Type", g_variant_new_string ("active"));
/*
    GVariant* const foo[1] = {dict};
    args = g_variant_new_tuple(foo, 1);
*/

	args = g_variant_new("(a{sv})", b);
    //dict = g_variant_builder_end (b);

    interface_proxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM,
		G_DBUS_PROXY_FLAGS_NONE | G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		NULL,
		WPA_DBUS_SERVICE,
		WPA_DBUS_INTERFACES_OPATH "/1",
		WPA_DBUS_INTERFACES_INTERFACE,
		NULL,
		&error);

    if (interface_proxy == NULL) {
        fprintf(stderr, "Could not create interface proxy: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    g_signal_connect(interface_proxy, "g-signal",
                     G_CALLBACK(on_scan_done), NULL);

#if 1
    g_dbus_connection_call_sync(system_bus,
                WPA_DBUS_SERVICE,
                WPA_DBUS_INTERFACES_OPATH "/1", 
                "fi.w1.wpa_supplicant1.Interface",
                "Scan",
                args,
                NULL,
                G_DBUS_CALL_FLAGS_NONE,
                -1,
                NULL,
                &error);
    /* TODO: Check for error */
#endif

    return 0;
}

void free_wpaicd(void) {
    /* g_object_unref(private.proxy); */
}

int main_loop(void) {
    static GMainLoop *loop = NULL;

    if (init_wpaicd()) {
        fprintf(stderr, "Failed to initialise\n");
        return 1;
    }

    loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);

    free_wpaicd();

    return 0;
}

int
main (int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    main_loop();
}
