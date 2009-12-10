#ifndef icd_common_utils_defined
#define icd_common_utils_defined

#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>

#include <glib.h>
#include <dbus/dbus.h>

#define WLAN "WLAN: "


/** structure for keeping wlan network information indexed by ssid */
struct wlan_ssid_info {
	/** ssid of the network */
	gchar *ssid;

	/** IAPs that match this SSID */
	GSList *id_list;

	/** wheter the network is (hidden and) not yet scanned */
	gboolean is_scanned;
};



/**
 * Structure to identify a wlan network, stores the name and security
 *  settings. This struct is used as data in the 'id_list' of struct
 * 'wlan_ssid_info' */
struct wlan_ssid_identification {
	/** IAP name */
	gchar *name;

	/** IAP id (the part after /IAP/ in gconf */
	gchar *id;

	/** wlan capability for this IAP */
	guint capability;

	/** is this ssid hidden or not */
	gboolean is_hidden;

	/** if hidden IAP, then tells if it has been scanned or not yet */
	gboolean is_scanned;

	/** set if the IAP is a temporary one */
	gboolean is_temporary;
};


gboolean icd_get_wlan_ssid_names (GHashTable **wlan_table);


#endif

