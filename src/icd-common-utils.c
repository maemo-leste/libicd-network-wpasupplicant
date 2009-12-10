/**
 * Copyright (C) 2007 Nokia Corporation. All rights reserved.
 *
 * @author patrik.flykt@nokia.com
 * @author jukka.rissanen@nokia.com
 *
 * @file wlan.c
 */

/* Some common utility functions that might be needed by various network,
 * link and IP layer modules.
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gconf/gconf-client.h>

#include <osso-ic-gconf.h>
#include <wlancond.h>
#include <wlancond-dbus.h>
#include <icd/icd_log.h>

#include "icd-common-utils.h"



/* ------------------------------------------------------------------------- */
/**
 * Helper function for removing a 'wlan_ssid_info' element from a hash table.
 *
 * @param data the structure to remove
 */
static void iap_settings_wlan_ssid_info_free(gpointer data)
{
	struct wlan_ssid_info *info = (struct wlan_ssid_info *)data;
	GSList *cur;
	struct wlan_ssid_identification *id;

	if (info == NULL)
		return;

	for (cur = info->id_list; cur; cur = g_slist_next(cur)) {
		id = (struct wlan_ssid_identification *)cur->data;

#if 0
		ILOG_DEBUG(WLAN "removing IAP '%s' with ssid '%s' and security '%d'",
			   id->name, info->ssid, id->security);
#endif

		g_free(id->name);
		g_free(id->id);
		g_free(id);
	}

	g_free(info->ssid);
	g_slist_free(info->id_list);
	g_free(info);
}


/* ------------------------------------------------------------------------- */
/**
 * Helper function for providing security settings values
 *
 * @param security the wlan security setting string from gconf
 * @return wlancond network capability parameter
 */
static guint wlan_security_to_capability(const gchar *security)
{
	if (security == NULL)
		return 0;

	if (!strncmp( security, "NONE", 4))
		return WLANCOND_OPEN;

	if (!strncmp (security, "WEP", 3))
		return WLANCOND_WEP;

	if (!strncmp(security, "WPA_PSK", 7))
		return WLANCOND_WPA_PSK;

	if (!strncmp(security, "WPA_EAP", 7))
		return WLANCOND_WPA_EAP;

	return 0;
}



/* ------------------------------------------------------------------------- */
static guint get_wlan_capability_by_path(const gchar *escaped_iap_path)
{
	GConfClient *gconf_client;
	gchar *key;
	GError *error = NULL;
	gchar *str;
	guint capability;

	gconf_client = gconf_client_get_default ();

	key = g_strdup_printf ( "%s/wlan_security", escaped_iap_path );
	str = gconf_client_get_string ( gconf_client, key, &error );
	g_free ( key );

	if (error != NULL) {
		ILOG_ERR(WLAN "error fetching capability string from gconf: '%s'",
			 error->message );
		g_error_free(error);
	}
  
	capability = wlan_security_to_capability(str);

#if 0
	ILOG_DEBUG(WLAN "IAP '%s', sec=%s, cap=0x%x", escaped_iap_path, str, capability);
#endif

	g_free(str);
	g_object_unref(gconf_client);

	return capability;
}


/* ------------------------------------------------------------------------- */
/**
 * Get the IAP type for the escaped IAP name
 *
 * @param iap_name the escaped name of the IAP
 * @param iap_id IAP name in gconf path
 * @param iap_name_found is the id and name same (FALSE if yes)
 */
static gchar *get_escaped_iap_gconf_type(const gchar *escaped_name,
					 gchar *iap_id,
					 gboolean iap_name_found)
{
	GConfClient *gconf_client;
	gchar *iap_type_path;
	gchar *iap_type_name;
	GError *error = NULL;

	if (escaped_name == NULL)
		return NULL;

	gconf_client = gconf_client_get_default();

	/* get the IAP type */
	iap_type_path = g_strdup_printf(ICD_GCONF_PATH "/%s/type",
					escaped_name);

	iap_type_name = gconf_client_get_string(gconf_client,
						iap_type_path,
						&error);
	g_free (iap_type_path);

	if (!iap_type_name && iap_name_found==TRUE) {
		/* Check the new names */
		iap_type_path = g_strdup_printf(ICD_GCONF_PATH "/%s/type",
						iap_id);

		iap_type_name = gconf_client_get_string(gconf_client,
							iap_type_path,
							&error);
		g_free (iap_type_path);
	}


	if (error != NULL) {
		ILOG_ERR(WLAN "could not read IAP type: '%s'", error->message);

		g_clear_error(&error);
		g_object_unref(gconf_client);
		return NULL;
	}

	g_object_unref(gconf_client);

	return iap_type_name;
}


/* ------------------------------------------------------------------------- */
/**
 * Get the IAP type
 *
 * @param iap_name the (unescaped) plain text IAP name
 * @param iap_id IAP name in gconf path
 * @param iap_name_found is the id and name same (FALSE if yes)
 */
static gchar *get_iap_gconf_type(const gchar *iap_name,
				 gchar *iap_id,
				 gboolean iap_name_found)
{
	gchar *escaped_name;
	gchar *iap_type_name;

	if (iap_name == NULL)
		return NULL;

	/* get the IAP type */
	escaped_name = gconf_escape_key (iap_name, -1);
	iap_type_name = get_escaped_iap_gconf_type(escaped_name,
						   iap_id,
						   iap_name_found);
	g_free (escaped_name);

	return iap_type_name;
}


/* ------------------------------------------------------------------------- */
/**
 * Helper function to test wheter this IAP is a temporary "easywlan" IAP
 *
 * @param iap_name the IAP name to test
 * @return TRUE if temporay "easywlan" IAP, FALSE otherwise
 */
static gboolean iap_common_iap_is_easywlan ( const gchar *iap_name )
{
  if ( iap_name == NULL )
    return FALSE;

  if ( !strncmp ( iap_name, "[EasyWLAN", 9 ) )
    return TRUE;

  return FALSE;
}


/* ------------------------------------------------------------------------- */
/**
 * Fetch the SSID for the escaped full IAP path name
 *
 * @param escaped_iap_path the escaped gconf path name of the IAP
 * @return the null-terminated SSID which must be freed by caller or NULL on
 *         error
 */
static gchar *get_wlan_ssid_path(const gchar *escaped_iap_path)
{
	GConfClient *gconf_client;
	gchar *key;
	GError *error = NULL;
	GSList *ssid_int_list;
	gint list_length;
	gchar *ssid_array;
	gint current = 0;

	gconf_client = gconf_client_get_default();

	key = g_strdup_printf("%s/wlan_ssid", escaped_iap_path);

	/* get the ssid int list from gconf */
	ssid_int_list = gconf_client_get_list(gconf_client,
					      key,
					      GCONF_VALUE_INT,
					      &error);

	/* ssid was stored as a list of ints */
	if (error == NULL) {
		g_free(key);

		/* create the destination char array */
		list_length = g_slist_length(ssid_int_list);
		ssid_array = g_new0(gchar, list_length + 1);

		/* copy values from list to array */
		while (ssid_int_list != NULL) {
			ssid_array[current] = GPOINTER_TO_INT(ssid_int_list->data);
			ssid_int_list = g_slist_delete_link(ssid_int_list,
							    ssid_int_list);
			current += 1;
		}
		ssid_array[current] = '\0';
		g_slist_free(ssid_int_list);
	} else {
		/* error fetching list, maybe the entry is a string? */
		ILOG_ERR(WLAN "error fetching ssid list, trying string instead ('%s')",
			 error->message);
		g_error_free(error);
		error = NULL;

		/* fallback to string*/
		ssid_array = gconf_client_get_string(gconf_client,
						     key,
						     &error);
		g_free(key);

		if (error != NULL) {
			/* debug ( "error fetching (fallback) ssid string from gconf: '%s'",
			   error->message ); */
			g_error_free(error);
		}
	}

	g_object_unref(gconf_client);

	return ssid_array;
}



/* ------------------------------------------------------------------------- */
/**
 * Fill in a hash table with a mapping from the ssid to the IAP name
 *
 * @param wlan_table the supplied hash table to append entries to; if the table
 *        points to NULL, it will be created
 * @return TRUE on success, FALSE on failure
 */
gboolean icd_get_wlan_ssid_names(GHashTable **wlan_table)
{
	GConfClient *client;
	GSList *iap_list;
	GSList *list_iter;
	GError *error = NULL;
	gchar *iap_name;
	gchar *type_value;
	gchar *ssid_value;
	gchar *key;
	struct wlan_ssid_info *ssid_info = NULL;
	struct wlan_ssid_identification *id;

	if (wlan_table == NULL)
		return FALSE;

	/* get a list of all IAPs */
	client = gconf_client_get_default();
	iap_list = gconf_client_all_dirs(client,
					 ICD_GCONF_PATH,
					 &error);

	if (error != NULL) {
		ILOG_ERR(WLAN "cannot get list of IAPs: %s", error->message);
		g_clear_error(&error);
		g_object_unref(client);
		return FALSE;
	}


	/* create the ssid to IAP name hash table if needed */
	if (*wlan_table == NULL) {
		*wlan_table = g_hash_table_new_full(g_str_hash,
						    g_str_equal,
						    g_free,
						    iap_settings_wlan_ssid_info_free);
		ILOG_DEBUG(WLAN "created new ssid to IAP hash table");
	} else {
		ILOG_DEBUG(WLAN "using supplied ssid to IAP hash table");
	}
    
	list_iter = iap_list;
	while (list_iter) {

		gchar *gconf_name;
		gboolean name_found, is_hidden, is_temporary;

		/* if we hit this, gconf is broken */
		if (list_iter->data == NULL) {
			/* go to next element */
			list_iter = g_slist_next(list_iter);
			ILOG_ERR(WLAN "gconf is broken, got NULL data from "
				 "'gconf_client_all_dirs()'");
			continue;
		}

		gconf_name = g_strrstr((gchar *)list_iter->data, "/");
		if (gconf_name)
			gconf_name++;

		//ILOG_DEBUG(WLAN "GConf = \"%s\"", gconf_name);


		/* Get the "name" attribute of the iap and use that as a
		 * iap name. NB#78982
		 */
		key = g_strconcat((gchar *)list_iter->data, "/name", NULL);
		iap_name = gconf_client_get_string(client, key, NULL);
		g_free (key);

		if (!iap_name && gconf_name) {
			/* Use last part of the gconf IAP name as a name */
			iap_name = gconf_unescape_key(gconf_name, -1);
			name_found = FALSE;
		} else
			name_found = TRUE;

		//ILOG_DEBUG(WLAN "IAP name = \"%s\"", iap_name);

		/* Old stuff, not seen any more in newly created
		 * IAPs, only found in IAPs restored from backups
		 */
		if (iap_common_iap_is_easywlan(iap_name)) {
			g_free(iap_name);
			g_free(list_iter->data);
			list_iter->data = NULL;
			list_iter = g_slist_next(list_iter);
			ILOG_DEBUG(WLAN "IAP(%s) is EasyWLAN", iap_name);
			continue;
		}

		/* Get the IAP type */
		type_value = get_iap_gconf_type(iap_name, gconf_name, name_found);
		if (type_value == NULL) {
			g_free(iap_name);
			g_free(list_iter->data);
			list_iter->data = NULL;
			list_iter = g_slist_next(list_iter);
			continue;
		}
		//ILOG_DEBUG(WLAN "IAP(%s) type = \"%s\"", iap_name, type_value);


		/* Get the "wlan_hidden" attribute of the iap and remember it.
		 * NB#79446
		 */
		key = g_strconcat((gchar *)list_iter->data, "/wlan_hidden", NULL);
		is_hidden = gconf_client_get_bool(client, key, NULL);
		g_free (key);


		/* Get the "temporary" attribute of the iap and remember it.
		 * NB#80356
		 */
		key = g_strconcat((gchar *)list_iter->data, "/temporary", NULL);
		is_temporary = gconf_client_get_bool(client, key, NULL);
		g_free (key);


		/* add to list everything starting with WLAN */
		if (!strncmp("WLAN", type_value, 4)) {
			int free_ssid, added;
			ssid_value = get_wlan_ssid_path(
				(gchar*)list_iter->data);

			if (ssid_value == NULL) {
				g_free(iap_name);
				g_free(type_value);
				g_free(list_iter->data);
				list_iter->data = NULL;
				list_iter = g_slist_next(list_iter);
				continue;
			}

			//ILOG_DEBUG(WLAN "IAP(%s) ssid = \"%s\"", iap_name, ssid_value);

			if ((ssid_info = g_hash_table_lookup(
				     *wlan_table, ssid_value)) == NULL) {

				ssid_info = g_new0(struct wlan_ssid_info, 1);

				/* place ssid_value in struct instead of freeing it */
				ssid_info->ssid = ssid_value;
				ssid_info->is_scanned = FALSE;
				g_hash_table_insert(*wlan_table,
						      g_strdup(ssid_info->ssid),
						      ssid_info);
				//ILOG_DEBUG(WLAN "added ssid '%s', name '%s'", ssid_info->ssid, iap_name);
				free_ssid = 0;
				added = 1;
			} else {
				free_ssid = 1;
				added = 0;
			}

			/* place iap_name and capability in list */
			id = g_new0(struct wlan_ssid_identification, 1);
			id->name = iap_name;
			id->id = g_strdup(gconf_name);
			id->capability = get_wlan_capability_by_path(
				(gchar*)list_iter->data);
			id->is_hidden = is_hidden;
			id->is_temporary = is_temporary;

			/* set additional bits according to type */
			if (!strcmp("WLAN_INFRA", type_value))
				id->capability |= WLANCOND_INFRA;
			else if (!strcmp("WLAN_ADHOC", type_value))
				id->capability |= WLANCOND_ADHOC;

			ILOG_DEBUG(WLAN "id=\"%s\", name=\"%s\", ssid=\"%s\", type=%s, cap=0x%x, hidden=%s, temp=%s, added=%s",
				   gconf_name,
				   iap_name,
				   ssid_value,
				   type_value, id->capability,
				   is_hidden ? "true" : "false",
				   is_temporary ? "true" : "false",
				   added ? "yes" : "no");

			if (free_ssid)
				g_free(ssid_value);

			ssid_info->id_list = g_slist_prepend(ssid_info->id_list, id);
		}
		else
			g_free(iap_name);

		g_free(type_value);
		g_free(list_iter->data);
		list_iter->data = NULL;

		list_iter = g_slist_next(list_iter);
	}

	g_slist_free(iap_list);
	g_object_unref(client);
      
	return TRUE;
}


