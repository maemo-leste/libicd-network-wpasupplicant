/**
 * Copyright (C) 2007 Nokia Corporation. All rights reserved.
 *
 * @author patrik.flykt@nokia.com
 * @author jukka.rissanen@nokia.com
 *
 * @file wlan.c
 */


/** @addtogroup wlan WLAN network api implementation
 * @ingroup wlan_network_plugin
 * @{ */

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
#include <ctype.h>

#include "../config.h"

#include <glib.h>
#include <dbus/dbus.h>

#if 0
#include <wlancond.h>
#include <wlancond-dbus.h>
#endif

#include <osso-ic.h>
#include <osso-ic-dbus.h>
#include <osso-ic-gconf.h>
#include <icd/support/icd_log.h>

#include <maemosec_certman.h>

#include "libicd-network-wlan-dev.h"
#include "wlan.h"
#include "icd-common-utils.h"

#ifdef DMALLOC_ENABLE
#include <dmalloc.h>
#endif

#ifndef MINVAL
#define MINVAL(a, b) ((a) < (b) ? (a) : (b))
#endif

#if 0
#define SCAN_TIMEOUT 10
#else
#define SCAN_TIMEOUT 30  /* temporarily increased to 30 secs because of the problems in r0v3r scanning */
#endif
#define WLAN_PRIORITY 20
#define WLAN_INFRA "WLAN_INFRA"
#define WLAN_ADHOC "WLAN_ADHOC"

static dbus_bool_t scan_ssid(struct wlan_context *ctx, const gchar *network_type);
static void wlan_bring_up(const gchar *network_type,
			  const guint network_attrs,
			  const gchar *network_id,
			  icd_nw_link_up_cb_fn link_up_cb,
			  const gpointer link_up_cb_token,
			  gpointer *private);
static gboolean wlan_scan_timeout(void *data);
static dbus_bool_t find_ssid(struct wlan_context *ctx,
			     gchar *ssid,
			     iap_state state);

/* to avoid double free */
#define g_free_z(a) do { g_free(a); (a)=0; } while(0)

int wlan_debug_level = 1;


/* helper struct for remembering adhoc networks */
struct adhoc_helper {
	gchar *ssid;
	guint capability;
};


/* ------------------------------------------------------------------------- */
/* Helpers for dbus errors
 */
static inline void error_init(DBusError *error)
{
	dbus_error_init(error);
}

static inline void error_clear(DBusError *error)
{
	if (dbus_error_is_set(error)) {
		dbus_error_free(error);  /* this does also initialization */
	}
}

static inline void error_set(DBusError *error,
			     const char *name,
			     const char *message)
{
	error_clear(error);
	dbus_set_error_const(error, name, message);
}


/* ------------------------------------------------------------------------- */
/* Helper function for emptying a hash table.
 * Note that the hash table is to be set up with explicite destroy functions
 */
static gboolean hash_table_clear(gpointer key,
				 gpointer value,
				 gpointer user_data)
{
	return TRUE;
}


/* ------------------------------------------------------------------------- */
static void check_gconf_error(GError **error)
{
        if (*error) {
                ILOG_ERR(WLAN "GConf error: %s", (*error)->message);
                g_clear_error(error);
                *error = NULL;
        }
}


/* ------------------------------------------------------------------------- */
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
		check_gconf_error(&error);
		g_free_z(key);
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
		ILOG_ERR(WLAN "GConf error: Expected `string' or `list of int' for key %s",
			key);
	}
	gconf_value_free(value);
	g_free_z(key);

	return ret;
}


/* ------------------------------------------------------------------------- */
static gboolean get_iap_config_bool(GConfClient *gconf_client,
				    const char *iap_name,
				    const char *key_name,
				    gboolean def)
{
	gchar *key;
	GConfValue *value;
	GError *error = NULL;
	gboolean ret = def;

	if (iap_name)
		key = g_strdup_printf(ICD_GCONF_PATH "/%s/%s", iap_name, key_name);
	else
		key = g_strdup_printf(ICD_GCONF_PATH "/%s", key_name);

	value = gconf_client_get(gconf_client, key, &error);
	g_free_z(key);

	check_gconf_error(&error);

	if (value != NULL) {
		if (value->type == GCONF_VALUE_BOOL)
			ret = gconf_value_get_bool(value);
		gconf_value_free(value);
	}

	return ret;
}


/* ------------------------------------------------------------------------- */
static gchar *get_iap_config_string(GConfClient *gconf_client,
				    const char *iap_name,
				    const char *key_name)
{
	gchar *key, *value;
	GError *error = NULL;

	key = g_strdup_printf(ICD_GCONF_PATH "/%s/%s", iap_name, key_name);
	value = gconf_client_get_string(gconf_client, key, &error);
	g_free_z(key);
	check_gconf_error(&error);

	return value;
}


/* ------------------------------------------------------------------------- */
static gint get_iap_config_int(GConfClient *gconf_client,
			       const char *iap_name,
			       const char *key_name)
{
	gchar *key;
	gint value;
	GError *error = NULL;

	key = g_strdup_printf(ICD_GCONF_PATH "/%s/%s", iap_name, key_name);
	value = gconf_client_get_int(gconf_client, key, &error);
	g_free_z(key);
	check_gconf_error(&error);

	return value;
}


/* ------------------------------------------------------------------------- */
static inline char *get_state_name(iap_state state)
{
	static char *state_names[]={
		"IDLE",
		"CONNECTING",
		"CONNECTED",
		"DISCONNECTING",
		"SEARCH_SSID",
		"SEARCH_HIDDEN",
		0
	};

	if (state<0 || state>=STATE_MAX_NR)
		return "UNKNOWN";

	return state_names[state];
}


#define CHANGE_STATE(a,b) change_state(__LINE__, a, b)

/* ------------------------------------------------------------------------- */
static iap_state change_state(int linenum, struct wlan_context *ctx, iap_state new_state)
{
	if (ctx->state == new_state)
		return ctx->state;

	ILOG_DEBUG(WLAN "%d: state %s (%d) -> %s (%d)", linenum, 
		   get_state_name(ctx->state), ctx->state,
		   get_state_name(new_state), new_state);
	ctx->state = new_state;
	return ctx->state;
}


/* ------------------------------------------------------------------------- */
static enum icd_nw_levels map_rssi(int rssi)
{
	enum icd_nw_levels val = ICD_NW_LEVEL_NONE;

	if (rssi > -5)
		val = ICD_NW_LEVEL_10;
	else if (rssi > -10)
		val = ICD_NW_LEVEL_9;
	else if (rssi > -20)
		val = ICD_NW_LEVEL_8;
	else if (rssi > -30)
		val = ICD_NW_LEVEL_7;
	else if (rssi > -40)
		val = ICD_NW_LEVEL_6;
	else if (rssi > -50)
		val = ICD_NW_LEVEL_5;
	else if (rssi > -60)
		val = ICD_NW_LEVEL_4;
	else if (rssi > -70)
		val = ICD_NW_LEVEL_3;
	else if (rssi > -80)
		val = ICD_NW_LEVEL_2;
	else if (rssi > -90)
		val = ICD_NW_LEVEL_1;

	return val;
}


/* ------------------------------------------------------------------------- */
static dbus_int32_t get_tx_power(struct wlan_context *ctx)
{
	gint tx=0;
/* XXX: WPASUPPLICANT */
#if 0
	GError *gerror = NULL;

	ENTER;
	tx = gconf_client_get_int(ctx->gconf_client,
				  ICD_GCONF_WLAN_TX_POWER,
				  &gerror);
	if (gerror != NULL) {
		ILOG_ERR(WLAN "Error reading configuration:%s\n",
			 gerror->message);
		g_error_free (gerror);
		gerror = NULL;
	}

	if (tx <= 0)
		tx = WLANCOND_TX_POWER100;
#endif

	EXIT;
	return tx;
}


/* ------------------------------------------------------------------------- */
static dbus_uint32_t parse_security_method(gchar *s)
{
	dbus_uint32_t result = 0;
/* XXX: WPASUPPLICANT */
#if 0
	if (strcmp(s, "NONE") == 0) {
		result = WLANCOND_OPEN;
	} else if (strcmp(s, "WEP") == 0) {
		result = WLANCOND_WEP;
	} else if (strcmp(s, "WPA_PSK") == 0) {
		result = WLANCOND_WPA_PSK;
	} else if (strcmp(s, "WPA_EAP") == 0) {
		result = WLANCOND_WPA_EAP;
	}
#endif

	return result;
}


/* ------------------------------------------------------------------------- */
static dbus_uint32_t parse_wlan_type(gchar *s)
{
	dbus_uint32_t result = 0;
/* XXX: WPASUPPLICANT */
#if 0

	if (strcmp(s, "AUTO") == 0) {
		result = WLANCOND_AUTO;
	} else if (strcmp(s, "WLAN_INFRA") == 0) {
		result = WLANCOND_INFRA;
	} else if (strcmp(s, "WLAN_ADHOC") == 0) {
		result = WLANCOND_ADHOC;
	}
#endif
	return result;
}


#if 0  // not used
/* ------------------------------------------------------------------------- */
static int check_wlan_mode(struct wlan_context *ctx,
			   dbus_uint32_t capabilities)
{
	dbus_uint32_t mode = capabilities & WLANCOND_MODE_MASK;

	ENTER;
	for (GSList *e = ctx->network_types;
	     e;
	     e = g_slist_next(e)) {

		if (strcmp((gchar *)e->data, "WLAN_INFRA") == 0) {
			if (mode == WLANCOND_INFRA) {
				EXIT;
				return TRUE;
			}
		} else if (strcmp((gchar *)e->data, "WLAN_ADHOC") == 0) {
			if (mode == WLANCOND_ADHOC) {
				EXIT;
				return TRUE;
			}
		}
	}

	EXIT;
	return FALSE;
}
#endif


typedef enum {
	IAP_WLAN_ERROR_NONE,
	IAP_WLAN_ERROR_WPA2_ONLY,
	IAP_WLAN_ERROR_AP_SETTINGS_NOT_SUPPORTED
} iap_wlan_error;

/* ------------------------------------------------------------------------- */
static int check_security_method(struct wlan_context *ctx,
				 dbus_uint32_t capabilities,
				 iap_wlan_error *error,
				 gchar *iap_id)
{
/* XXX: WPASUPPLICANT */
#if 0
	gboolean wpa2_only;
	dbus_uint32_t wpa2_enabled;
	dbus_uint32_t method = capabilities & WLANCOND_ENCRYPT_METHOD_MASK;
	gchar *iap;

	ENTER;
	if (iap_id)
		iap = iap_id;
	else
		iap = ctx->iap_name;

	wpa2_only = get_iap_config_bool(ctx->gconf_client, iap,
					"EAP_wpa2_only_mode", FALSE);
	wpa2_enabled = capabilities & WLANCOND_ENCRYPT_WPA2_MASK;

	if (error)
		(*error) = IAP_WLAN_ERROR_NONE;

	/* First check if we support these network settings */
	if ((capabilities & WLANCOND_UNSUPPORTED_NETWORK_MASK) == 
	    WLANCOND_UNSUPPORTED_NETWORK) {
		if (error)
			*error = IAP_WLAN_ERROR_AP_SETTINGS_NOT_SUPPORTED;
		return FALSE;
	}

	/* Check WPA2 support if it is required by user*/
	if (wpa2_only) {
		if (!wpa2_enabled) {
			if (error)
				(*error) = IAP_WLAN_ERROR_WPA2_ONLY;
			EXIT;
			return FALSE;
		} else {
			/* Check for APs that claim WPA2 but use TKIP for
			   cipher suite (not allowed in Wifi tests) */
			if (!(capabilities & WLANCOND_WPA_AES_GROUP) ||
			    !(capabilities & WLANCOND_WPA_AES) ||
			    (capabilities & WLANCOND_WPA_TKIP) ||
			    (capabilities & WLANCOND_WPA_TKIP_GROUP)) {

				if (error)
					(*error) = IAP_WLAN_ERROR_WPA2_ONLY;

				ILOG_DEBUG(WLAN "AES is needed for WPA2 only mode");
				EXIT;
				return FALSE;
			}
		}
	}


	/* Check that network supports the security method that has been
	 * configured */
	if (((capabilities & WLANCOND_ENCRYPT_METHOD_MASK) & method) == 0) {
		EXIT;
		return FALSE;
	}

	/* Everything is okay */
	EXIT;
#endif
	return TRUE;
}


/* ------------------------------------------------------------------------- */
static dbus_bool_t check_security_algorithm(struct wlan_context *ctx, dbus_uint32_t capabilities)
{
/* XXX: WPASUPPLICANT */
#if 0
	dbus_uint32_t unicast_algorithm = capabilities & WLANCOND_ENCRYPT_ALG_MASK;
	dbus_uint32_t multicast_algorithm = capabilities & WLANCOND_ENCRYPT_GROUP_ALG_MASK;
	dbus_uint32_t security_method =	capabilities & WLANCOND_ENCRYPT_METHOD_MASK;

	ENTER;

	/* security_method in capabilities is already alread checked by
	   check_security_method(), so we can trust it */
	if (!(security_method & (WLANCOND_WPA_PSK | WLANCOND_WPA_EAP))) {
		/* no need to check encryption algorithm */
		EXIT;
		return TRUE;
	}

	if (get_iap_config_bool(ctx->gconf_client, NULL, "allow_wep_ciphers_in_WPA", FALSE))
	{
		ILOG_DEBUG(WLAN "All ciphers allowed by the user");
		EXIT;
		return TRUE;
	}

	if (!(unicast_algorithm &
	      (WLANCOND_WPA_TKIP | WLANCOND_WPA_AES))) {
		/* unsupported unicast algorithm */
		EXIT;
		return FALSE;
	}

	if (!(multicast_algorithm &
	      (WLANCOND_WPA_TKIP_GROUP | WLANCOND_WPA_AES_GROUP))) {
		/* unsupported multicast algorithm */
		EXIT;
		return FALSE;
	}

	EXIT;
#endif
	return TRUE;
}


/* ------------------------------------------------------------------------- */
static dbus_uint32_t get_security_algorithm(int capabilities)
{
	dbus_uint32_t result = 0;
/* XXX: WPASUPPLICANT */
#if 0
	dbus_uint32_t supported_unicast_alg, supported_multicast_alg,
		wpa2_enabled, result = 0;

	ENTER;
	supported_unicast_alg = capabilities & WLANCOND_ENCRYPT_ALG_MASK;
	supported_multicast_alg = capabilities & WLANCOND_ENCRYPT_GROUP_ALG_MASK;
	wpa2_enabled = capabilities & WLANCOND_ENCRYPT_WPA2_MASK;

	if (wpa2_enabled) {
		result |= WLANCOND_WPA2;
	}

	if (supported_unicast_alg & WLANCOND_WPA_AES) {
		result |= WLANCOND_WPA_AES;
	} else if (supported_unicast_alg & WLANCOND_WPA_TKIP) {
		result |= WLANCOND_WPA_TKIP;
	} else {
		EXIT;
		return result;
	}

	if (supported_multicast_alg & WLANCOND_WPA_AES_GROUP) {
		result |= WLANCOND_WPA_AES_GROUP;
	} else if (supported_multicast_alg & WLANCOND_WPA_TKIP_GROUP) {
		result |= WLANCOND_WPA_TKIP_GROUP;
	}

	EXIT;
#endif
	return result;
}


/* ------------------------------------------------------------------------- */
static dbus_uint32_t choose_adhoc_channel(struct wlan_context *ctx,
					  dbus_int32_t used_channels)
{
	dbus_int32_t channel = 0;
	int i;

	channel = get_iap_config_int(ctx->gconf_client,
				     ctx->iap_name,
				     "wlan_adhoc_channel");

	if (channel == 0) {
		/* Let wlancond choose the channel. Fixes: NB#101156 */
		ILOG_DEBUG(WLAN "[%s] Choosing Ad-Hoc channel automagically.",
			   ctx->iap_name);
		return 0;
	}

	/* Over the limit value chooses some channel */
	if (channel < 1 || channel > 13) {
		ILOG_DEBUG(WLAN "[%s] Choosing Ad-Hoc channel automatically.",
			   ctx->iap_name);
		channel = 0;
	}

	if (channel == 0) {
		/* automatic channel setting enabled, search an available
		   channel */
		for (i = 1; i <= 11; i++) {
			if (!(used_channels & (1 << i))) {
				channel = i;
				break;
			}
		}
	}

	if (channel == 0) {
		/* No free channel found, choose one randomly from
		 * channels 1 - 11. (Channels 12 and 13 are
		 * power-limited, we don't use them.) */
		srand(time(NULL));
		channel = 1 + (int) (11.0 * rand() / (RAND_MAX + 1.0));
	}

	return channel;
}


/* ------------------------------------------------------------------------- */
static char *get_mode_string(dbus_uint32_t cap)
{
	char *modestr;
/* XXX: WPASUPPLICANT */
#if 0

	switch (cap & WLANCOND_MODE_MASK) {
	case WLANCOND_INFRA:
		modestr = WLAN_INFRA;
		break;
	case WLANCOND_ADHOC:
		modestr = WLAN_ADHOC;
		break;
	default:
		modestr = WLAN_INFRA;
		break;
	}
#endif
	modestr = WLAN_INFRA; /* XXX */

	return modestr;
}


/* ------------------------------------------------------------------------- */
static int send_powersave_req(struct wlan_context *ctx)
{
/* XXX: WPASUPPLICANT */
#if 0
	DBusMessage *msg = NULL, *reply = NULL;
	dbus_bool_t on = TRUE;
	int ret = 0;

	ENTER;

	ILOG_DEBUG(WLAN "Sending %s request.", WLANCOND_SET_POWERSAVE_REQ);

	error_clear(&ctx->error);
	msg = dbus_message_new_method_call(WLANCOND_SERVICE,
					   WLANCOND_REQ_PATH,
					   WLANCOND_REQ_INTERFACE,
					   WLANCOND_SET_POWERSAVE_REQ);
	if (msg == NULL)
		goto err_nomem;

	dbus_message_set_auto_start(msg, TRUE);

	if (!dbus_message_append_args(msg,
				      DBUS_TYPE_BOOLEAN, &on,
				      DBUS_TYPE_INVALID))
		goto err_nomem;

	if (!(reply = dbus_connection_send_with_reply_and_block(
		      ctx->system_bus,
		      msg,
		      -1,
		      &ctx->error)))
		goto err_nomem;

	ret = TRUE;
	goto cleanup;

err_nomem:
	error_set(&ctx->error, DBUS_ERROR_NO_MEMORY,
		  "Cannot create powersave request");
	ret = -1;

cleanup:
	if (msg != NULL)
		dbus_message_unref(msg);
	if (reply != NULL)
		dbus_message_unref(reply);

	if (dbus_error_is_set(&ctx->error)) {
		ILOG_ERR(WLAN "[%s] Error sending %s request: %s (%s)",
			 ctx->iap_name, WLANCOND_SET_POWERSAVE_REQ,
			 ctx->error.message, ctx->error.name);
	}

	EXIT;
	return ret;
#endif
	return 0;
}


/* ------------------------------------------------------------------------- */
/**
 * Callback to after WLAN has been disassociated for too long.
 * @param data The IAP data.
 * @retval TRUE Success.
 * @retval FALSE Error.
 */
static gboolean wlan_associate_timeout(void *data)
{
	struct wlan_context *ctx = get_wlan_context_from_dbus(data);

	ENTER;

	error_clear(&ctx->error);

	/* Notify that the iap is dead now */
	ILOG_INFO(WLAN "%s", "Has been associating for too long; killing");

	error_set(&ctx->error,
		  ICD_DBUS_ERROR_NETWORK_ERROR,
		  "Association timed out");

	/* Stop timer */
	ctx->g_association_timer = 0;

	if (ctx->link_up_cb) {
		ILOG_DEBUG(WLAN "[%s] association timeout, link up failure", ctx->iap_name);
		ctx->link_up_cb(ICD_NW_ERROR, NULL, NULL,
				ctx->link_up_cb_token, NULL);
		ctx->link_up_cb = NULL;
	}

	CHANGE_STATE(ctx, STATE_IDLE);
	ctx->iap_associated = FALSE;

	EXIT;
	return FALSE;
}


/* ------------------------------------------------------------------------- */
/* Clear all timers.
 */
static inline void clear_all_timers(struct wlan_context *ctx)
{
	if (ctx->g_scan_timer) {
		g_source_remove(ctx->g_scan_timer);
		ctx->g_scan_timer = 0;
	}
	if (ctx->g_association_timer) {
		g_source_remove(ctx->g_association_timer);
		ctx->g_association_timer = 0;
	}
}


/* ------------------------------------------------------------------------- */
/**
 * Clear the context and free allocated memory.
 * @param ctx Context pointer
 */
static void clear_connection(struct wlan_context *ctx)
{
	ENTER;

	g_free_z(ctx->iap_name);
	g_free_z(ctx->ssid);
	g_free_z(ctx->interface);
	ctx->scanning_in_progress = FALSE;
	ctx->state = STATE_IDLE;
	ctx->capabilities = 0;
	ctx->iap_associated = FALSE;
	ctx->used_channels = 0;
	ctx->active_scan_count = 0;
	ctx->is_iap_name = FALSE;

	clear_all_timers(ctx);

	if (ctx->ssid_to_iap_table) {
		ILOG_DEBUG(WLAN "%s", "clearing ssid2iap hash...");
		g_hash_table_foreach_remove(
			ctx->ssid_to_iap_table,
			hash_table_clear,
			NULL );
		g_hash_table_destroy(ctx->ssid_to_iap_table);
		ctx->ssid_to_iap_table = NULL;
	}

	if (ctx->adhoc_networks) {
		GSList *l;
		struct adhoc_helper *h;
		for (l=ctx->adhoc_networks; l; l=g_slist_next(l)) {
			h = (struct adhoc_helper *)l->data;
			g_free_z(h->ssid);
			g_free_z(h);
		}

		g_slist_free(ctx->adhoc_networks);
		ctx->adhoc_networks = NULL;
	}

	if (ctx->scan_ctx) {
		if (ctx->scan_ctx->g_scan_wait_timer) {
			g_source_remove(ctx->scan_ctx->g_scan_wait_timer);
			ctx->scan_ctx->g_scan_wait_timer = 0;
		}
		g_free_z(ctx->scan_ctx);
	}

	EXIT;
}


/* ------------------------------------------------------------------------- */
/* Convert bssid to xx:yy:zz notation. Caller must deallocate the returned
 * string.
 */
static char *convert_bss_to_hex(char *bssid, int bssid_len)
{
	int i, idx = 0;
	int hexlen;
	char *hexstr;

	hexlen = bssid_len * 3;
	if (!(hexlen > 0)) {
		return NULL;
	}

	hexstr = (char *)g_malloc0(hexlen);
	if (!hexstr) {
		return NULL;
	}

	for (i=0; i<bssid_len; i++) {
		/* Note that last ':' will not be printed */
		idx += snprintf(hexstr + idx, hexlen - idx, "%02x:", (unsigned char)bssid[i]);
	}

	return hexstr;
}


/* ------------------------------------------------------------------------- */
/**
 * Convert ASCII encoded hex character to integer.
 * @param v ASCII character.
 * @return Decoded value of v.
 */
static int hex_char_to_int(char v)
{
	if (v >= '0' && v <= '9')
		return v - '0';
	if (v >= 'a' && v <= 'f')
		return v - 'a' + 10;
	if (v >= 'A' && v <= 'F')
		return v - 'A' + 10;
	return -1;
}


/* ------------------------------------------------------------------------- */
/**
 * Convert string of ASCII encoded hex characters to
 * table of binary data.
 * @param from ASCIIZ string containing encoded data.
 * @param to Destination buffer for decoded binary data.
 */
static int hex_to_binary(const char *from, char *to)
{
	int i, j;

	if (from == NULL)
		return 0;

	for (i = j = 0; i < 32 && from[i] && from[i+1]; i += 2, j++) {
		int a1, a2;

		a1 = hex_char_to_int(from[i]);
		a2 = hex_char_to_int(from[i+1]);

		if (a1 < 0 || a2 < 0)
			return -1;

		to[j] = (a1 << 4) | a2;
	}

	return j;
}


/* ------------------------------------------------------------------------- */
#if 0
static dbus_bool_t add_wep_keys(struct wlan_context *ctx,
				gchar *network_id,
				int security_method,
				DBusMessage *msg,
				DBusError *error)
{
	int i, j, default_key = 0;
	dbus_bool_t result;

	for (i = 1; i <= 4; i++) {
		char keyname[32];
		char binary_key[29], *array_ptr;
		int length = 0, l;
		gchar *key = NULL;

		if (security_method == WLANCOND_WEP) {
			sprintf(keyname, "wlan_wepkey%d", i);
			key = get_iap_config_string(ctx->gconf_client,
						    ctx->iap_name,
						    keyname);
			if (key != NULL) {
				l = strlen(key);
				if (l == 10 || l == 26 || l == 58) {
					/* the key is in hex format */
					length = hex_to_binary(key, binary_key);
				} else {
					/* the key is in ASCII format */
					length = l;
					for (j = 0; j < l; j++) {
						binary_key[j] = key[j];
					}
				}

				if (!(length == 5 || length == 13 || length == 29)) {
					ILOG_WARN(WLAN "[%s] WEP key [%s] has invalid"
						  " length or format.",
						  ctx->iap_name, key);
					length = 0;
				}

#ifdef DEBUG
				for (int j = 0; j < length; j++) {
					ILOG_DEBUG(WLAN "WEP key %i (%i/%i): 0x%02x", i, j + 1,
						   length, binary_key[j]);
				}
#endif
			}
		} else {
			/* if WEP is disabled set key length to zero */
			length = 0;
		}

		/* A crude hack to get the address of binary_key because
		 * with GCC "int array[]; &array == array" is true. See
		 * dbus_message_append_args() documentation for more. */
		array_ptr = binary_key;

		if (dbus_message_append_args(
			    msg,
			    DBUS_TYPE_ARRAY,
			    DBUS_TYPE_BYTE,
			    &array_ptr,
			    length,
			    DBUS_TYPE_INVALID) == FALSE) {

			g_free_z(key);
			goto err_nomem;
		}
		g_free_z(key);
	}

	/* set default key */
	if (security_method == WLANCOND_WEP) {
		default_key = get_iap_config_int(ctx->gconf_client,
						 ctx->iap_name,
						 "wlan_wepdefkey");
		if (default_key < 1 || default_key > 4) {
			ILOG_WARN(WLAN "[%s] Invalid WEP default key number: %i."
				  " Using number 1 as default.",
				  network_id, default_key);
			default_key = 1;
		}
	} else {
		default_key = 0;
	}

	if (dbus_message_append_args(msg,
				     DBUS_TYPE_INT32, &default_key,
				     DBUS_TYPE_INVALID) == FALSE) {
		goto err_nomem;
	}

	result = TRUE;
	goto exit;

err_nomem:
	error_set(error, DBUS_ERROR_NO_MEMORY,
		  "Cannot add WEP keys to WLAN settings_and_connect request");
	result = FALSE;
exit:
	return result;
}
#endif


/* ------------------------------------------------------------------------- */
static void disconnect_cb(DBusPendingCall *pending, void *user_data)
{
	struct wlan_context *ctx = get_wlan_context_from_dbus(user_data);

	ENTER;

	if (ctx->disconnect_call) {
		dbus_pending_call_unref(ctx->disconnect_call);
		ctx->disconnect_call = NULL;
	}

	/* The actual disconnect is handled by disconnected signal sent
	 * by wlancond so we don't do anything here.
	 */

	EXIT;
}


/* ------------------------------------------------------------------------- */
static void setup_cb(DBusPendingCall *pending, void *user_data)
{
	ENTER;
/* XXX: WPASUPPLICANT */
#if 0
	struct wlan_context *ctx = get_wlan_context_from_dbus(user_data);
	DBusMessage *reply = NULL;
	gchar *interface = 0;
	int is_error = 0;

	ENTER;

	error_clear(&ctx->error);

	reply = dbus_pending_call_steal_reply(pending);
	dbus_pending_call_unref(pending);

	if (!reply) {
		ILOG_ERR(WLAN "[%s] WLAN setup failed, no reply from wlancond",
			 ctx->iap_name);
		is_error = 1;
		goto cleanup;
	}

	if (dbus_set_error_from_message(&ctx->error, reply)) {
		ILOG_ERR(WLAN "[%s] WLAN configuration failed (%s)",
			 ctx->iap_name, ctx->error.message);
		is_error = 1;
		goto cleanup;
	}

	if (dbus_message_get_args(reply, &ctx->error,
				  DBUS_TYPE_STRING, &interface,
				  DBUS_TYPE_INVALID) == FALSE) {
		ILOG_ERR(WLAN "[%s] WLAN configuration failed (no interface name)",
			 ctx->iap_name);
		is_error = 1;
		goto cleanup;
	}

	/* Note that interface variable is freed in icd callback so it is not
	 * done here.
	 */

	if ((ctx->capabilities & WLANCOND_MODE_MASK) != WLANCOND_ADHOC) {
		/* Add initial association timeout: 60sec
		 * if we hear nothing from AP by then something is propably
		 * wrong in encryption.
		 */
		if (ctx->g_association_timer) {
			ILOG_DEBUG(WLAN "[%s] Resetting association %s", ctx->iap_name, "timer");
			g_source_remove(ctx->g_association_timer);
			ctx->g_association_timer = 0;
		}
		ctx->g_association_timer = g_timeout_add(60*1000,
							 wlan_associate_timeout,
							 ctx);
	}

cleanup:
	if (reply != NULL)
		dbus_message_unref(reply);

	if (is_error) {
		/* Tell the error to icd because the results will
		 * not be received from wlancond
		 */
		if (ctx->link_up_cb) {
			ILOG_DEBUG(WLAN "[%s] no reply from wlancond, link up failure", ctx->iap_name);
			ctx->link_up_cb(ICD_NW_ERROR, NULL, NULL,
					ctx->link_up_cb_token, NULL);
			ctx->link_up_cb = NULL;
		}
	}
	EXIT;
#endif
	EXIT;
}


/* ------------------------------------------------------------------------- */
static void clear_ssid_hash_table(struct wlan_context *ctx)
{
	if (ctx->ssid_to_iap_table) {
		g_hash_table_foreach_remove(
			ctx->ssid_to_iap_table,
			hash_table_clear,
			NULL );
		g_hash_table_destroy(ctx->ssid_to_iap_table);
		ctx->ssid_to_iap_table = NULL;
	}
}

/* ------------------------------------------------------------------------- */
#define EAP_GTC			6
#define EAP_TLS			13
#define EAP_TTLS		21
#define EAP_PEAP		25
#define EAP_MS			26
#define EAP_TTLS_PAP		98
#define EAP_TTLS_MS		99
#define DEFAULT_PASSWORD	"AeHi5ied"
/**
 * Get autoconnect flag for WLAN WPA EAP infra network
 * @param ctx Context
 * @param iap_name IAP name
 * @return ICD_NW_ATTR_AUTOCONNECT if autoconnectable, 0 otherwise
 */
static guint wlan_get_eap_autoconnect(struct wlan_context *ctx, const char *iap_name)
{
	maemosec_key_id key_id;
	EVP_PKEY *pkey;
	gchar *client_certificate_file;
	gchar *password;
	gboolean password_prompt;
	gint eap_type, eap_inner_type;

	if (!iap_name)
		return 0;

	/* Check for supported EAP type */
	eap_type = get_iap_config_int(ctx->gconf_client, iap_name, "EAP_default_type");
	if (eap_type != EAP_TLS && eap_type != EAP_TTLS && eap_type != EAP_PEAP)
		return 0;

	/* Check for supported inner EAP type */
	eap_inner_type = get_iap_config_int(ctx->gconf_client, iap_name, "PEAP_tunneled_eap_type");
	if (eap_type == EAP_TTLS && eap_inner_type != EAP_GTC && eap_inner_type != EAP_MS && eap_inner_type != EAP_TTLS_PAP && eap_inner_type != EAP_TTLS_MS)
		return 0;
	if (eap_type == EAP_PEAP && eap_inner_type != EAP_GTC && eap_inner_type != EAP_MS)
		return 0;

	/* Check if we have password for inner EAP type */
	if (eap_type == EAP_TTLS || eap_type == EAP_PEAP) {
		if (eap_inner_type == EAP_GTC) {
			password = get_iap_config_string(ctx->gconf_client, iap_name, "EAP_GTC_passcode");
			if (!password || !password[0])
				return 0;
		} else {
			password_prompt = get_iap_config_bool(ctx->gconf_client, iap_name, "EAP_MSCHAPV2_password_prompt", FALSE);
			if (password_prompt)
				return 0;
			password = get_iap_config_string(ctx->gconf_client, iap_name, "EAP_MSCHAPV2_password");
			if (!password || !password[0])
				return 0;
		}
	}

	/* Check if we can decrypt private key for certificate */
	client_certificate_file = get_iap_config_string(ctx->gconf_client, iap_name, "EAP_TLS_PEAP_client_certificate_file");
	if (client_certificate_file && client_certificate_file[0]) {
		if (maemosec_certman_str_to_key_id(client_certificate_file, key_id) != 0)
			return 0;
		if (maemosec_certman_retrieve_key(key_id, &pkey, DEFAULT_PASSWORD) != 0)
			return 0;
		g_free(pkey);
	}

	ILOG_INFO(WLAN "AUTOCONNECT flag for WLAN WPA EAP infra network with IAP \"%s\" is supported", iap_name);
	return ICD_NW_ATTR_AUTOCONNECT;

}

/* ------------------------------------------------------------------------- */
/**
 * Get autoconnect flag if WLAN is an open, WEP or WPA PSK or WPA EAP infra network
 * @param ctx Context
 * @param capability wlancond capability bits
 * @param iap_name IAP name
 * @return ICD_NW_ATTR_AUTOCONNECT if autoconnectable, 0 otherwise
 */
static guint wlan_get_autoconnect(struct wlan_context *ctx, guint capability, const char *iap_name)
{
/* XXX: WPASUPPLICANT */
#if 0
  /* autoconnect to open, wep and wpa psk infra networks */
  if (capability & (WLANCOND_OPEN |
		    WLANCOND_WEP |
		    WLANCOND_WPA_PSK) &&
      capability & WLANCOND_INFRA)
    return ICD_NW_ATTR_AUTOCONNECT;

  /* check autoconnect for wpa eap infra networks */
  if ((capability & WLANCOND_WPA_EAP) && (capability & WLANCOND_INFRA))
    return wlan_get_eap_autoconnect(ctx, iap_name);
#endif

  return 0;
}

/* ------------------------------------------------------------------------- */
/**
 * Helper for iterating through ssid hash.
 */
static void check_adhoc_networks(gpointer key,
				 gpointer value,
				 gpointer user_data)
{
/* XXX: WPASUPPLICANT */
#if 0
	char *ssid = (char *)key;
	struct wlan_ssid_info *info = (struct wlan_ssid_info *)value;
	struct wlan_context *ctx = (struct wlan_context *)user_data;
	struct wlan_ssid_identification *id;
	GSList *e, *l;
	int skip;

	//ILOG_DEBUG(WLAN "Checking \"%s\"", ssid);

	for (e = info->id_list; e; e = g_slist_next(e)) {
		id = (struct wlan_ssid_identification *)e->data;
		if (id->capability & WLANCOND_ADHOC) {

			skip = 0;

			for (l=ctx->adhoc_networks; l; l=g_slist_next(l)) {
				/* If same adhoc network is found, then do not
				 * return the saved one again. Fixes: NB#80390
				 */
				struct adhoc_helper *h = (struct adhoc_helper *)l->data;

				guint stripped_caps =
					(h->capability & WLANCOND_ENCRYPT_METHOD_MASK) |
					(h->capability & WLANCOND_MODE_MASK);

				if ((id->capability == stripped_caps) &&
				    (strcmp(h->ssid, (gchar *)ssid)==0)) {
					skip = 1;
					break;
				}
			}

			if (skip) {
				ILOG_DEBUG(WLAN "[%s] Adhoc network already found", ssid);

			} else {
				guint nwattrs = 0;
				cap2nwattr(id->capability, &nwattrs);

				ILOG_DEBUG(WLAN "[%s] Adhoc found \"%s\", ssid=\"%s\", cap=0x%04x", id->id, id->name, ssid, id->capability);
				ctx->search_cb(ICD_NW_SEARCH_CONTINUE,
					       id->name,
					       WLAN_ADHOC,
					       nwattrs | 
					       ICD_NW_ATTR_IAPNAME |
					       wlan_get_autoconnect (ctx, id->capability, id->id),
					       id->id,
					       0,
					       0,
					       0,
					       ctx->search_cb_token);
			}
		}
	}
#endif
}


/* ------------------------------------------------------------------------- */
/**
 * Helper for iterating through ssid hash.
 */
static void check_hidden_networks(gpointer key,
				  gpointer value,
				  gpointer user_data)
{
	char *ssid = (char *)key;
	struct wlan_ssid_info *info = (struct wlan_ssid_info *)value;
	struct wlan_context *ctx = (struct wlan_context *)user_data;
	struct wlan_ssid_identification *id;
	GSList *e = NULL;

	//ILOG_DEBUG(WLAN "Checking \"%s\"", ssid);

	/* Do the checking one IAP at a time */
	if (ctx->state == STATE_SEARCH_HIDDEN)
		return;

	ENTER;

	for (e = info->id_list; e; e = g_slist_next(e)) {
		id = (struct wlan_ssid_identification *)e->data;
#if 0
		ILOG_DEBUG(WLAN "[%s]: hidden=%d, scanned=%d",
			   ssid, id->is_hidden, id->is_scanned);
#endif

		if (id->is_hidden && !id->is_scanned) {
			ILOG_DEBUG(WLAN "[%s]: IAP \"%s\" is hidden, scanning it.", ssid, id->id);
			id->is_scanned = TRUE;
			find_ssid(ctx, ssid, STATE_SEARCH_HIDDEN);
			break;
		}
	}

	if (!e) {
		if ((ctx->state!=STATE_SEARCH_HIDDEN)) {
			ctx->scanning_in_progress = FALSE;
		}
	}

	EXIT;
}


/* ------------------------------------------------------------------------- */
/**
 * Dbus handler for wlan scan results.
 * @param conn Dbus connection
 * @param msg Dbus message that is returned
 * @param user_data Wlan context
 * @retval TRUE Success.
 * @retval FALSE Error.
 */
static dbus_bool_t wlan_get_scan_result(DBusConnection *conn,
					DBusMessage *msg,
					void *user_data)
{
/* XXX: WPASUPPLICANT */
#if 0
	struct wlan_context *ctx = get_wlan_context_from_dbus(user_data);
	DBusMessageIter iter;
	dbus_bool_t ret = TRUE;
	dbus_int32_t num_results;
	dbus_uint32_t capability = 0; /* if searching for one specific ssid,
				       * then cap bits are saved here
				       */
	guint nwattrs;
	int i, found = 0;
	char *conv_essid;

	ENTER;

	/* If we are in connection setup phase (STATE_SEARCH_SSID), or
	 * getting results for hidden AP (STATE_SEARCH_HIDDEN) then
	 * we must get the results that are needed by wlan_bring_up()
	 */
	if ((ctx->state != STATE_SEARCH_SSID) &&
	    (ctx->state != STATE_SEARCH_HIDDEN) &&
	    !ctx->scanning_in_progress) {
		ILOG_DEBUG(WLAN "%s", "Results received while not expecting them, ignored.");
		EXIT;
		return FALSE;
	}

	error_clear(&ctx->error);

	dbus_message_iter_init(msg, &iter);


	/* int32: number of scan results */
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32)
		goto bad_arguments;
	dbus_message_iter_get_basic(&iter, &num_results);
	dbus_message_iter_next(&iter);

	if (ctx->state == STATE_DISCONNECTING) {
		/* Fixes: NB#83911 */
		ILOG_DEBUG(WLAN "Already disconnecting, "
			   "ignoring %d results.", num_results);
		goto OUT;
	}

	ILOG_DEBUG(WLAN "Received %d scan results.", num_results);

	if ((ctx->state != STATE_SEARCH_SSID) &&
	    (ctx->state != STATE_SEARCH_HIDDEN) &&
	    (num_results>0)) {
		clear_ssid_hash_table(ctx);

		if (!icd_get_wlan_ssid_names(&ctx->ssid_to_iap_table)) {
			ILOG_ERR(WLAN "%s", "Cannot create ssid-to-iap hash.");
		}
	}


	for (i = 0; i < num_results; i++) {
		char *essid, *bssid, *mode;
		int bssid_len, essid_len, level;
		dbus_int32_t rssi;
		dbus_uint32_t channel, cap_bits;
		DBusMessageIter array_iter;
		struct wlan_ssid_info *ssid_info;
		char *bsshex;

		/* array of byte: essid */
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
		    dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_BYTE)
			goto bad_arguments;
		dbus_message_iter_recurse(&iter, &array_iter);
		dbus_message_iter_get_fixed_array(&array_iter, &essid,
						  &essid_len);
		dbus_message_iter_next(&iter);

		/*  array of byte: bssid */
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
		    dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_BYTE)
			goto bad_arguments;
		dbus_message_iter_recurse(&iter, &array_iter);
		dbus_message_iter_get_fixed_array(&array_iter, &bssid,
						  &bssid_len);
		dbus_message_iter_next(&iter);

		/*  int32: rssi */
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32)
			goto bad_arguments;
		dbus_message_iter_get_basic(&iter, &rssi);
		dbus_message_iter_next(&iter);

		/*  uint32: channel */
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
			goto bad_arguments;
		dbus_message_iter_get_basic(&iter, &channel);
		dbus_message_iter_next(&iter);

		/*  uint32: cap_bits */
		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
			goto bad_arguments;
		dbus_message_iter_get_basic(&iter, &cap_bits);
		dbus_message_iter_next(&iter);

		if (essid == NULL)
			continue;

		bsshex = convert_bss_to_hex(bssid, bssid_len);

		nwattrs = 0;
		cap2nwattr(cap_bits, &nwattrs);

		conv_essid = essid;
		ILOG_DEBUG(WLAN "ssid=\"%s\", bssid=%s, rssi=%d, ch=%d, cap=0x%08x, nwattrs=0x%08x", essid, bsshex ? bsshex : "?", rssi, channel, cap_bits, nwattrs);

		level = map_rssi((int)rssi);
		ctx->used_channels |= 1 << channel;

		if (ctx->state == STATE_SEARCH_SSID) {
			if (!found && (ctx->ssid &&
				       strcmp(ctx->ssid, conv_essid) == 0) &&
			    /* Because we might not have algorithm yet, check
			     * only mode and method.
			     */
			    ((cap_bits & WLANCOND_MODE_MASK) ==
			     (ctx->capabilities & WLANCOND_MODE_MASK)) &&
			    ((cap_bits & WLANCOND_ENCRYPT_METHOD_MASK) ==
			     (ctx->capabilities & WLANCOND_ENCRYPT_METHOD_MASK))) {
				ILOG_DEBUG(WLAN "Found \"%s\" capabilities (bits=0x%08x, cap=0x%08x)",
					   ctx->iap_name,
					   cap_bits, ctx->capabilities);

				if (ctx->iap_name == NULL) {
					/* This could happen if AnyOpenWlan
					 * tries to connect to AP and the AP
					 * is not a saved one.
					 */
					/* We must set the iap_name otherwise
					 * wlan_bring_up() will not be called
					 * somewhere below.
					 */
					/* Fixes: NB#84196 */
					ctx->iap_name = g_strdup(ctx->ssid);
					ctx->is_iap_name = FALSE;
					ctx->capabilities = cap_bits;
					ILOG_DEBUG(WLAN "IAP name not set, using ssid \"%s\"", ctx->ssid);
				}

				capability = cap_bits;
				found = 1;
				ctx->active_scan_count = -1;
			}
			g_free_z(bsshex);
			continue;
		}

		mode = g_strdup(get_mode_string(cap_bits));

		if (conv_essid && conv_essid[0] &&
		    (strcmp(mode, WLAN_ADHOC)==0)) {
			/* Remember the adhocs for a while, NB#80390 */
			struct adhoc_helper *adhoc;
			adhoc = (struct adhoc_helper *)g_malloc0(sizeof(struct adhoc_helper));
			if (!adhoc) {
				EXIT;
				return FALSE;
			}
			adhoc->ssid = g_strdup(conv_essid);
			adhoc->capability = cap_bits;

			ctx->adhoc_networks = g_slist_prepend(
				ctx->adhoc_networks,
				(char *)adhoc);
		}


		/* Get IAP names for this ssid */
		if (conv_essid && conv_essid[0] &&
		    ctx->ssid_to_iap_table &&
		    (ssid_info = g_hash_table_lookup(ctx->ssid_to_iap_table,
						     conv_essid))!=NULL) {
			struct wlan_ssid_identification *id;
			gboolean found_one = FALSE;
			
			ILOG_DEBUG(WLAN "hash table (%p) found, id_list=%p",
				   ctx->ssid_to_iap_table, ssid_info->id_list);

			for (GSList *e = ssid_info->id_list; e;
			     e = g_slist_next(e)) {
				id = (struct wlan_ssid_identification *)e->data;

				/* Do we know this AP already (capability must
				 * also match). Fixes: NB#74704
				 * We are only interested in encryption method and
				 * wlan mode flags that is why we strip extra bits
				 */
				guint stripped_caps =
					(cap_bits & WLANCOND_ENCRYPT_METHOD_MASK) |
					(cap_bits & WLANCOND_MODE_MASK);
				int known = FALSE;

				ILOG_DEBUG(WLAN "id=%s, name=\"%s\", ssid=\"%s\", cap=0x%04x, caps=0x%04x, stripped=0x%04x",
					   id->id, id->name, conv_essid, id->capability, cap_bits, stripped_caps);

				if (id->is_temporary == TRUE) {

					/* Temporary IAPs are not saved */
					ILOG_DEBUG(WLAN "[%s] is temporary IAP", id->id);
					known = FALSE;

				} else if (id->capability == stripped_caps) {

					/* Check WPA2 only mode.
					 * Fixes: NB#78849
					 */
					iap_wlan_error wpa2only=0;
					if (check_security_method(
						    ctx,
						    cap_bits,
						    &wpa2only,
						    id->id) == FALSE) {
						known = FALSE;
						if (wpa2only == IAP_WLAN_ERROR_WPA2_ONLY) {
							ILOG_INFO(WLAN "%s: WPA2 only defined but AP security method bits are 0x%x", id->name, cap_bits & WLANCOND_ENCRYPT_METHOD_MASK);
						}
						else if (wpa2only == IAP_WLAN_ERROR_AP_SETTINGS_NOT_SUPPORTED) {
							ILOG_INFO(WLAN "%s: AP security method not supported, capability = 0x%x", id->name, cap_bits);
						}

					} else if (check_security_algorithm(ctx, cap_bits) == FALSE) {
						known = FALSE;
						ILOG_INFO(WLAN "%s: AP security algorithm not supported (0x%x)", id->name, cap_bits);

					} else {
						known = TRUE;
					}
				}


				if (known == TRUE) {
					/* send scan results to icd */
					ILOG_DEBUG(WLAN "known AP: mode=%s, id=%s: name=\"%s\"", mode, id->id, id->name);

					ctx->search_cb(ICD_NW_SEARCH_CONTINUE,
						       id->name,
						       mode,
						       nwattrs |
						       ICD_NW_ATTR_IAPNAME |
						       wlan_get_autoconnect(ctx, cap_bits, id->id),
						       id->id,
						       level,
						       bsshex,
						       rssi,
						       ctx->search_cb_token);

					found_one = TRUE;

				} else {
					/* We do not know this AP */
					if (id->is_temporary != TRUE) {
						ILOG_DEBUG(WLAN "security mismatch: \"%s\"", conv_essid);
					}
				}
			}

			/* We did not found any known AP. Fixes: NB#97850 */
			if (found_one == FALSE) {
				goto UNKNOWN_AP;
			}


		} else {
			/* so we do not know the IAP name */
			ILOG_DEBUG(WLAN "unknown AP: \"%s\"", conv_essid);
		UNKNOWN_AP:
			{
				int is_ascii  = 1, j;

				for (j=0; j<essid_len; j++) {
					if (!isascii(essid[j])) {
						is_ascii=0;
						break;
					}
				}

				ctx->search_cb(ICD_NW_SEARCH_CONTINUE,
					       is_ascii ? conv_essid : "",
					       mode,
					       nwattrs &
					       ~ICD_NW_ATTR_IAPNAME &
					       ~ICD_NW_ATTR_AUTOCONNECT,
					       conv_essid,
					       level,
					       bsshex,
					       rssi,
					       ctx->search_cb_token);
			}
		}

		g_free_z(mode);
		g_free_z(bsshex);
	}


	if (ctx->state == STATE_SEARCH_SSID) {

		/* This needs to be done now, otherwise there will be
		 * a core dump in wlan_scan_timeout()
		 */
		if (ctx->g_scan_timer) {
			ILOG_DEBUG(WLAN "Removing ssid scan %s.", "timer");
			g_source_remove(ctx->g_scan_timer);
			ctx->g_scan_timer = 0;
		}

		ctx->scanning_in_progress = FALSE;

		if (found) {
			/* Now we just simulate icd2 main loop */
			gpointer x;

		TRY_AGAIN:
			if (ctx->iap_name == NULL) {
				/* We are now somehow confused and cannot
				 * really continue to wlan_bring_up().
				 * Fixes: NB#84613
				 */
				ILOG_DEBUG(WLAN "IAP is %s, quitting.", "NULL");
				goto LINK_DOWN;

			} else {
				x = ctx; // to avoid gcc warning
				nwattrs = 0;
				cap2nwattr(capability, &nwattrs);

				ILOG_DEBUG(WLAN "Going up: type=%s, nwattrs=0x%04x, iap=\"%s\", up_cb=%p", ctx->network_type, nwattrs, ctx->iap_name, ctx->link_up_cb);
				wlan_bring_up(ctx->network_type,
					      nwattrs,
					      ctx->iap_name,
					      ctx->link_up_cb,
					      ctx->link_up_cb_token,
					      &x);
			}
		} else {
			ctx->active_scan_count++;
			if (ctx->active_scan_count>3) {
				ILOG_ERR(WLAN "Asked data for ssid \"%s\" but got %d results but no req ssid, ignoring all results (up=%p)", ctx->ssid, num_results, ctx->link_up_cb);
				ctx->active_scan_count = 0;

			LINK_DOWN:
				if (ctx->link_up_cb) {
					gboolean do_powersave;
					ILOG_DEBUG(WLAN "Sending powersave, state=%d", ctx->state);
					do_powersave = get_iap_config_bool(
						ctx->gconf_client,
						NULL,
						"powersave_after_scan",
						TRUE);
					if (do_powersave) {
						send_powersave_req(ctx);
					}

					ctx->link_up_cb(ICD_NW_ERROR, NULL, NULL,
							ctx->link_up_cb_token, NULL);
					ctx->link_up_cb = NULL;
				}
				CHANGE_STATE(ctx, STATE_IDLE);
			} else {
				/* Note that iap name can be null if the
				 * connection request came from AnyOpenWLAN
				 * service module. This means that we tried to
				 * connect open WLAN AP which was not found in
				 * the scan.
				 * Fixes: NB#84613
				 */
				if (ctx->iap_name == NULL) {
					ILOG_DEBUG(WLAN "Asked data for ssid \"%s\" but got %d results but no req ssid, IAP name was not set.", ctx->ssid, num_results);
					if (ctx->ssid && !ctx->iap_name) {
						ctx->iap_name = g_strdup(ctx->ssid);
						ctx->is_iap_name = FALSE;
					}
					
				} else {
					ILOG_DEBUG(WLAN "Asked data for ssid \"%s\" but got %d results but no req ssid, trying again (%d)", ctx->ssid, num_results, ctx->active_scan_count);
				}
				goto TRY_AGAIN;
			}
		}

		/* Just quit now, no need to do anything else */
		EXIT;
		return ret;

	} else {

		/* Check saved adhoc networks. Fixes: NB#79324 */

		/* Damn, no iterators in current maemo glib,
		 * doing it the hard way through callback.
		 */
		int failed = 0;
		if (!ctx->ssid_to_iap_table) {
			if (!icd_get_wlan_ssid_names(&ctx->ssid_to_iap_table)) {
				ILOG_ERR(WLAN "%s", "Cannot create ssid-to-iap hash for adhoc.");
				failed = 1;
			}
		}

		if (!failed) {
			g_hash_table_foreach(ctx->ssid_to_iap_table,
					     check_adhoc_networks,
					     ctx);

			/* Scan next hidden IAP. When we are in SEARCH_HIDDEN state,
			 * it means that we are currently searching some specific
			 * hidden IAP. When results are returned from wlancond, we
			 * reset the state back to normal so that next hidden IAP
			 * can be searched.
			 */
			if (ctx->state == STATE_SEARCH_HIDDEN) {
				CHANGE_STATE(ctx, ctx->prev_state);
			}

			/* Check saved hidden networks. Fixes: NB#79446 */
			ILOG_DEBUG(WLAN "Checking hidden IAPs (state=%d)", ctx->state);
			g_hash_table_foreach(ctx->ssid_to_iap_table,
					     check_hidden_networks,
					     ctx);

			if (ctx->state == STATE_SEARCH_HIDDEN) {
				/* Do not quit yet, but handle all hidden APs and
				 * wait the results to arrive.
				 */
				EXIT;
				ILOG_DEBUG(WLAN "Handled %d scan results when searching hidden AP", i);
				return TRUE;
			}
		}
	}

OUT:
	/* we do not need the hash any longer */
	ILOG_DEBUG(WLAN "%s", "Clearing hash");
	clear_ssid_hash_table(ctx);

	if (ctx->adhoc_networks) {
		GSList *l;
		struct adhoc_helper *h;
		for (l=ctx->adhoc_networks; l; l=g_slist_next(l)) {
			h = (struct adhoc_helper *)l->data;
			g_free_z(h->ssid);
			g_free_z(h);
		}
		g_slist_free(ctx->adhoc_networks);
		ctx->adhoc_networks = NULL;
	}

	if (ctx->g_scan_timer) {
		ILOG_DEBUG(WLAN "Removing scan %s.", "timer");
		g_source_remove(ctx->g_scan_timer);
		ctx->g_scan_timer = 0;
	}

	if (ctx->scan_ctx) {
		/* This was not here earlier and if it is missing it
		 * might be causing problems seen in bug NB#83911
		 */
		if (ctx->scan_ctx->g_scan_wait_timer) {
			g_source_remove(ctx->scan_ctx->g_scan_wait_timer);
			ctx->scan_ctx->g_scan_wait_timer = 0;
		}
		g_free_z(ctx->scan_ctx);
	}

	ctx->scanning_in_progress = FALSE;

	/* send scan stop */
	ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
		       NULL,
		       NULL,
		       0,
		       NULL,
		       0,
		       NULL,
		       0,
		       ctx->search_cb_token);

	if (ctx->scan_started) {
		/* Only to be sent after scan */
		gboolean do_powersave;

		do_powersave = get_iap_config_bool(ctx->gconf_client,
						   NULL,
						   "powersave_after_scan",
						   TRUE);
		ctx->scan_started = FALSE;

		/* No powersave if we are already connected. We can be 
		 * connected if user initiates connection when we are still
		 * receiving scan results.
		 */
		if (do_powersave &&
		    (ctx->state != STATE_CONNECTED) &&
		    (ctx->state != STATE_CONNECTING)) {
			ILOG_DEBUG(WLAN "Sending powersave (%d), state=%d", do_powersave, ctx->state);
			send_powersave_req(ctx);
		} else {
			ILOG_DEBUG(WLAN "Not sending powersave (%d), state=%d (%s)", do_powersave, ctx->state, ctx->state==STATE_CONNECTED ? "CONNECTED" : (ctx->state==STATE_CONNECTING ? "CONNECTING" : "?"));
		}

		ctx->last_scan = 0;  /* force active scan when connecting */
	} else {
		ILOG_DEBUG(WLAN "Powersave not sent, state=%d", ctx->state);
	}

	PDEBUG("Handled %d scan results\n", i);

	EXIT;
	return ret;

bad_arguments:
	error_set(&ctx->error, ICD_DBUS_ERROR_SYSTEM_ERROR,
		  "Scan results have bad format");

	EXIT;
#endif
	return FALSE;
}



/* ------------------------------------------------------------------------- */
/**
 * Callback to handle WLAN connected events from wlancond.
 * Trigger authentication or DHCP.
 * @param conn D-BUS connection that received the signal.
 * @param msg The D-BUS scan_result signal.
 * @param user_data Wlan context.
 * @retval TRUE Success.
 * @retval FALSE Error.
 */
static dbus_bool_t wlan_connected(DBusConnection *conn,
				  DBusMessage *msg,
				  void *user_data)
{
	struct wlan_context *ctx = get_wlan_context_from_dbus(user_data);
	dbus_bool_t ret = FALSE;
	dbus_uint32_t bssid_len;
	gchar *bssid = NULL, *interface = NULL;

	ENTER;

	error_clear(&ctx->error);

	if (dbus_message_get_args(msg, &ctx->error,
				  DBUS_TYPE_STRING, &interface,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				  &bssid, &bssid_len,
				  DBUS_TYPE_INVALID) == FALSE) {
		ILOG_ERR(WLAN "Failed to parse WLAN connected signal: %s",
			 ctx->error.message);
		EXIT;
		return FALSE;
	}

	if (bssid_len != 6) {
		ILOG_ERR(WLAN "%s", "Received WLAN BSSID has bad length");
		goto OUT;
	}


	if (ctx->state != STATE_CONNECTING &&
	    ctx->state != STATE_CONNECTED) {
		ILOG_ERR(WLAN "[%s] Received WLAN connected event, but IAP is going "
			 "down or not connected (%d)", ctx->iap_name, ctx->state);
		goto OUT;
	}

	if (ctx->iap_associated) {
		ILOG_DEBUG(WLAN "[%s] Received WLAN connected event "
			   "to %02x:%02x:%02x:%02x:%02x:%02x, "
			   "but was already associated.", ctx->iap_name,
			   bssid[0], bssid[1], bssid[2], bssid[3],
			   bssid[4], bssid[5]);
		goto OUT;
	}

	ctx->iap_associated = TRUE;
	ILOG_INFO(WLAN "[%s] Associated with %02x:%02x:%02x:%02x:%02x:%02x",
		  ctx->iap_name, bssid[0], bssid[1], bssid[2], bssid[3],
		  bssid[4], bssid[5]);

	if (ctx->g_association_timer) {
		ILOG_DEBUG(WLAN "[%s] Removing association timer (%d)",
			   ctx->iap_name, ctx->g_association_timer);
		g_source_remove(ctx->g_association_timer);
		ctx->g_association_timer = 0;
	}

	ctx->interface = g_strdup(interface);

#if 0
	switch (ctx->capabilities & WLANCOND_ENCRYPT_METHOD_MASK) {
	case WLANCOND_OPEN:
	case WLANCOND_WEP:
	case WLANCOND_WPA_PSK:
	case WLANCOND_WPA_EAP:
		CHANGE_STATE(ctx, STATE_CONNECTED);

		ILOG_DEBUG(WLAN "Next layer up at %s (encryption=0x%x, state=%d, up=%p)",
			   ctx->interface,
			   ctx->capabilities & WLANCOND_ENCRYPT_METHOD_MASK,
			   ctx->state,
			   ctx->link_up_cb);
		if (ctx->link_up_cb) {
			ctx->link_up_cb(ICD_NW_SUCCESS_NEXT_LAYER,
					NULL,
					ctx->interface,
					ctx->link_up_cb_token,
					NULL);
			ctx->link_up_cb = NULL;
		}
		ret = TRUE;
		break;

	default:
		ILOG_ERR(WLAN "Unknown security method in %s: %i",
			 ctx->iap_name,
			 ctx->capabilities & WLANCOND_ENCRYPT_METHOD_MASK);
		break;
	}
#endif

OUT:
	EXIT;
	return ret;
}


/* ------------------------------------------------------------------------- */
/**
 * Callback to handle WLAN disconnected events from wlancond.
 * @param conn D-BUS connection that received the signal.
 * @param msg The D-BUS scan_result signal.
 * @param user_data Wlan context.
 * @retval TRUE Success.
 * @retval FALSE Error.
 */
static dbus_bool_t wlan_disconnected(DBusConnection *conn,
				     DBusMessage *msg,
				     void *user_data)
{
	struct wlan_context *ctx = get_wlan_context_from_dbus(user_data);
	char *iface = 0;
	gchar *modestr;
	int st = 0;
	int close_called = 0;

	ENTER;

	error_clear(&ctx->error);

	/* If iap_name is not set, then it is a bug as we are not connected but
	 * still got disassociated event. Seen that happen in wimax tablet.
	 * See bug 85767 in this attachment
	 * https://projects.maemo.org/bugzilla/attachment.cgi?id=34228
	 * in 20080615-170207/log/logs/syslog at the end of the file.
	 */
	if (ctx->iap_name == NULL) {
		ILOG_ERR(WLAN "Got disassociation event but is not connected, ignoring (%s)", get_state_name(ctx->state));
		EXIT;
		return FALSE;
	}


	/* This timer must be removed so that we do not try to connect while
	 * disconnecting. The wlan_bring_up() is called in
	 * wlan_scan_stop_timeout() and it will cause problems if we are
	 * disconnecting and a new connect is tried. See the attachment
	 * #33859 in NB#83911 at or around this line
	 * "May 13 09:55:39 Nokia-N810-WiMAX-20-0 icd2 0.44[1622]: WLAN: IAP (Wippies) going up (state 0)"
	 */
	if (ctx->scan_ctx) {
		if (ctx->scan_ctx->g_scan_wait_timer) {
			g_source_remove(ctx->scan_ctx->g_scan_wait_timer);
			ctx->scan_ctx->g_scan_wait_timer = 0;
		}
		g_free_z(ctx->scan_ctx);
	}

	/* Just in case remove earlier call if it exist */
	if (ctx->disconnect_call) {
		dbus_pending_call_unref(ctx->disconnect_call);
		ctx->disconnect_call = NULL;
	}

	if (dbus_message_get_args(msg, &ctx->error,
				  DBUS_TYPE_STRING, &iface,
				  DBUS_TYPE_INVALID) == FALSE) {
		ILOG_ERR(WLAN "Failed to parse WLAN disconnected signal: %s",
			 ctx->error.message);

	} else {

		ILOG_INFO(WLAN "[%s] Disassociated from network \"%s\"", iface, ctx->iap_name);
		error_set(&ctx->error, ICD_DBUS_ERROR_NETWORK_ERROR,
			  "Disassociated from network");

		st = 1;
	}

	if (ctx->scanning_in_progress || ctx->g_scan_timer) {
		/* Fixes: NB#82482
		 * We were scanning hidden IAP but got disconnected event and
		 * search complete was not sent to icd2
		 */
		ctx->scanning_in_progress = FALSE;

		if (ctx->g_scan_timer) {
			g_source_remove(ctx->g_scan_timer);
			ctx->g_scan_timer = 0;
			ILOG_DEBUG(WLAN "Scan %s removed.", "timer");
		}

		ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
			       NULL,
			       NULL,
			       0,
			       NULL,
			       ICD_NW_LEVEL_NONE,
			       NULL,
			       0,
			       ctx->search_cb_token);
	}

	if (ctx->g_association_timer) {
		ILOG_DEBUG(WLAN "[%s] Removing association timer because of disconnect (%d)",
			   ctx->iap_name, ctx->g_association_timer);
		g_source_remove(ctx->g_association_timer);
		ctx->g_association_timer = 0;
	}

	modestr = get_mode_string(ctx->capabilities);
	cap2nwattr(ctx->capabilities, &ctx->network_attrs);

	if (ctx->state == STATE_DISCONNECTING) {
		/* The disconnect was initiated by user, in this case
		 * call link down callback.
		 */
		if (ctx->link_down_cb) {
			ILOG_DEBUG(WLAN "[%s] calling link down for \"%s\", down=%p",
				   iface, ctx->iap_name, ctx->link_down_cb);
			ctx->link_down_cb(ICD_NW_SUCCESS_NEXT_LAYER,
					  ctx->link_down_cb_token);
			ctx->link_down_cb = NULL;
		}

	} else if (ctx->state == STATE_CONNECTING ||
		   ctx->state == STATE_SEARCH_SSID) {
		/* We were connecting but something went wrong. */
		if (ctx->link_up_cb) {
			ILOG_DEBUG(WLAN "[%s] calling link up failure for \"%s\", up=%p",
				   iface, ctx->iap_name, ctx->link_up_cb);
			ctx->link_up_cb(ICD_NW_ERROR, NULL, iface,
					ctx->link_up_cb_token, NULL);
			ctx->link_up_cb = NULL;
		} else {
			/* This close is needed here. The problem was seen when
			 * connecting to ad-hoc network and the user selected
			 * offline mode. The real problem is that connect to
			 * ad-hoc network can take a long time (because of
			 * long delays in udhcpc) so when the user selected
			 * offline mode we were still in connecting state.
			 * The return to online mode will not work without
			 * this fix.
			 * Fixes: NB#90556  (external bugzilla MB#3660)
			 */
			goto CLOSING;
		}
	} else {
	CLOSING:
		/* For uninitiated closes, just use normall close callback */
		ILOG_DEBUG(WLAN "[%s] closing \"%s\" (%s, %s)",
			   iface, 
			   ctx->iap_name ? ctx->iap_name : ctx->ssid,
			   ctx->is_iap_name ? "TRUE" : "FALSE",
			   modestr);
		ctx->close_cb(ICD_NW_ERROR,
			      ICD_DBUS_ERROR_NETWORK_ERROR,
			      modestr, // infra or adhoc
			      ctx->is_iap_name == TRUE ? 
			      (ctx->network_attrs | ICD_NW_ATTR_IAPNAME) :
			      (ctx->network_attrs & ~ICD_NW_ATTR_IAPNAME),
			      ctx->iap_name ? ctx->iap_name : ctx->ssid);
		close_called = 1;
	}


	if (close_called) {
		/* This was uninitiated disconnect (close_cb was just called),
		 * do not change state now because it is already done by other
		 * wlan module functions which are called by close_cb().
		 * We must not change the state to IDLE in this case because
		 * then the disconnecting branch above (the link_down_cb()
		 * function) would not be called at all which would then cause
		 * the icon blinking, because icd2 would then be in
		 * disconnecting state instead of disconnected state.
		 * The link_down_cb() must be called in disconnect otherwise 
		 * the connection icon will blink forever.
		 * This is a complicated issue :)
		 * Fixes: NB#87764
		 */
		ILOG_DEBUG(WLAN "[%s] current state %s", ctx->iap_name, get_state_name(ctx->state));
	} else {
		ctx->prev_state = STATE_IDLE;
		CHANGE_STATE(ctx, STATE_IDLE);
	}
	ctx->iap_associated = FALSE;

	EXIT;
	return st;
}


/* ------------------------------------------------------------------------- */
/**
 * Called from icd when wlan is to be taken down.
 * @param network_type network type
 * @param network_attrs attributes, such as type of network_id, security, etc.
 * @param network_id IAP name or local id, e.g. SSID
 * @param interface_name interface that was enabled
 * @param link_down_cb callback function for notifying ICd when the IP address
 *        is configured
 * @param link_down_cb_token token to pass to the callback function
 * @param private a reference to the icd_nw_api private memeber
 */
static void wlan_take_down(const gchar *network_type,
			   const guint network_attrs,
			   const gchar *network_id,
			   const gchar *interface_name,
			   icd_nw_link_down_cb_fn link_down_cb,
			   const gpointer link_down_cb_token,
			   gpointer *private)
{
	struct wlan_context *ctx = get_wlan_context_from_icd(private);

	DBusMessage *msg = NULL;
	gboolean st = TRUE;

	ENTER;

	error_clear(&ctx->error);

	CHANGE_STATE(ctx, STATE_DISCONNECTING);
	ctx->link_down_cb = link_down_cb;
	ctx->link_down_cb_token = link_down_cb_token;
	ctx->active_scan_count = 0;

	ILOG_DEBUG(WLAN "[%s] link going down at %s", ctx->iap_name, interface_name);

/* XXX: WPASUPPLICANT */
#if 0
	msg = dbus_message_new_method_call(WLANCOND_SERVICE,
					   WLANCOND_REQ_PATH,
					   WLANCOND_REQ_INTERFACE,
					   WLANCOND_DISCONNECT_REQ);
	if (msg == NULL) {
		st = FALSE;
		goto cleanup;
	}

	if (!dbus_connection_send_with_reply(ctx->system_bus,
					     msg,
					     &ctx->disconnect_call,
					     -1)) {
		st = FALSE;
		goto cleanup;
	}

	if (ctx->disconnect_call == NULL) {
		/* Seen one core about this, so check it */
		ILOG_ERR(WLAN "[%s] pending call null, disconnect message cannot be sent.", ctx->iap_name);
	} else {
		dbus_pending_call_set_notify(ctx->disconnect_call,
					     disconnect_cb,
					     ctx,
					     NULL);
	}

cleanup:
	if (msg != NULL)
		dbus_message_unref(msg);

	if (!st) {
		ILOG_DEBUG(WLAN "link (%s) at %s, cannot connect to %s:%s:%s:%s",
			  network_id,
			  interface_name,
			  WLANCOND_SERVICE,
			  WLANCOND_REQ_PATH,
			  WLANCOND_REQ_INTERFACE,
			  WLANCOND_DISCONNECT_REQ);
		ctx->link_down_cb(ICD_NW_ERROR, link_down_cb_token);
		ctx->link_down_cb = NULL;
		EXIT;
		return;
	}

#endif
	EXIT;
	return;
}



/* ------------------------------------------------------------------------- */
/**
 * Send D-BUS message to wlancond to configure WLAN adapter for
 * specific IAP.
 * @param ctx Context
 * @param network_id ssid
 * @param network_attrs capabilities flag
 * @retval TRUE Success.
 * @retval FALSE Error
 */
static dbus_bool_t setup_wlan(struct wlan_context *ctx,
			      gchar *network_id,
			      dbus_uint32_t capabilities)
{
/* XXX: WPASUPPLICANT */
	dbus_bool_t result = FALSE;
#if 0
	DBusMessage *msg = NULL;
	dbus_uint32_t algorithm = 0, flags = 0;
	dbus_int32_t txpower, mode, security_method, 
		security_method_and_wps, wps;
	dbus_uint32_t channel = 0;
	iap_wlan_error wpa2only=0;
	char *conv_network_id;
	gboolean is_temporary = TRUE;

	ENTER;

	conv_network_id = (char *)network_id;

	ILOG_DEBUG(WLAN "[%s] Configuring WLAN (cap=0x%08x)", conv_network_id, capabilities);

	mode = capabilities & WLANCOND_MODE_MASK;
	security_method = capabilities & WLANCOND_ENCRYPT_METHOD_MASK;

#ifdef WLANCOND_WPS_MASK
	wps = capabilities & WLANCOND_WPS_MASK;
#else
	wps = 0;
#endif

	/* Check WPA2 only mode. Do the checks here also just in case.
	 * Fixes: NB#78849
	 */
	if (check_security_method(ctx, capabilities, &wpa2only, 0) == FALSE) {
		if (wpa2only == IAP_WLAN_ERROR_WPA2_ONLY) {
			ILOG_INFO(WLAN "%s: WPA2 only defined (capability = 0x%x)", conv_network_id, capabilities);
			/* WPA2 only error dialog (CON-NOT041) is removed in uispec "Fremantle Connectivity Dialogs and notes UI specification v1.6" and replaced by generic error (see bug NB#92878). Fixes: NB#94400 */
			error_set(&ctx->error,
				  ICD_DBUS_ERROR_NETWORK_ERROR,
				  "WPA2 is configured, but network does not support it");
		}
		else if (wpa2only == IAP_WLAN_ERROR_AP_SETTINGS_NOT_SUPPORTED) {
			ILOG_INFO(WLAN "%s: AP security settings not supported (capability = 0x%x)", conv_network_id, capabilities);
			error_set(&ctx->error,
				  ICD_DBUS_ERROR_NETWORK_ERROR,
				  "AP settings not supported");
		}
		goto cleanup;
	}

	if (check_security_algorithm(ctx, capabilities) == FALSE) {
		ILOG_INFO(WLAN "%s: AP security algorithm not supported (0x%x)",
			  conv_network_id, capabilities);
		error_set(&ctx->error,
			  ICD_DBUS_ERROR_NETWORK_ERROR,
			  "AP security settings not supported");
		goto cleanup;
	}

	msg = dbus_message_new_method_call(
		WLANCOND_SERVICE,
		WLANCOND_REQ_PATH,
		WLANCOND_REQ_INTERFACE,
		WLANCOND_SETTINGS_AND_CONNECT_REQ);
	if (msg == NULL)
		goto err_nomem;

	if (security_method == WLANCOND_WPA_PSK ||
	    security_method == WLANCOND_WPA_EAP) {
		algorithm = get_security_algorithm(capabilities);
		if (algorithm == 0) {
			ILOG_ERR(WLAN "[%s] Not supported security algorithm.", ctx->iap_name);
			error_set(&ctx->error, DBUS_ERROR_NO_MEMORY,
				  "No supported security algorithm.");
			goto cleanup;
		}
	}

	txpower = get_tx_power(ctx);
	security_method |= algorithm;

	if (ctx->iap_name) {
		/* If hot plug service module is used, then iap_name
		 * might not be set.
		 */

		/* Add flags, NB#73394 */
		flags = get_iap_config_int(ctx->gconf_client,
					   ctx->iap_name,
					   "wlan_powersave");

		is_temporary = get_iap_config_bool(ctx->gconf_client,
						   ctx->iap_name,
						   "temporary",
						   FALSE);
	}


	if (!is_temporary) {
		/* We clear WPS bits for saved IAPs so that wlancond
		 * is not confused.
		 */
		wps = 0;
	}

#ifdef WLANCOND_AUTOCONNECT
	/* Fixes: NB#142549 */
	if (capabilities & WLANCOND_AUTOCONNECT)
		flags |= WLANCOND_AUTOCONNECT;
#endif

	security_method_and_wps = security_method | wps;

	ILOG_DEBUG(WLAN "Sending WLANCOND_SETTINGS_AND_CONNECT_REQ: "
		   "0x%x, \"%s\", 0x%x, 0x%x, 0x%x",
		   txpower, conv_network_id, mode, security_method_and_wps, flags);

	if (dbus_message_append_args(
		    msg,
		    DBUS_TYPE_INT32, &txpower,
		    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
		    &conv_network_id, strlen(conv_network_id)+1,
		    DBUS_TYPE_INT32, &mode,
		    DBUS_TYPE_INT32, &security_method_and_wps,
		    DBUS_TYPE_INVALID) == FALSE)
		goto err_nomem;

	add_wep_keys(ctx, (gchar *)network_id, security_method, msg,
		     &ctx->error);

	if (mode == WLANCOND_ADHOC)
		channel = choose_adhoc_channel(ctx, ctx->used_channels);

	if (dbus_message_append_args(
		    msg,
		    DBUS_TYPE_UINT32, &channel,
		    DBUS_TYPE_INVALID) == FALSE) {
		goto err_nomem;
	}

	if (flags &&
	    dbus_message_append_args(msg,
				     DBUS_TYPE_UINT32, &flags,
				     DBUS_TYPE_INVALID) == FALSE) {
		goto err_nomem;
	}

	/* Send the message and do not wait for response */
	if (!dbus_connection_send_with_reply(ctx->system_bus,
					     msg,
					     &ctx->setup_call,
					     -1)) {
		goto cleanup;
	}

	dbus_pending_call_set_notify(ctx->setup_call,
				     setup_cb,
				     ctx,
				     NULL);
	result = TRUE;
	goto cleanup;

err_nomem:
	error_set(&ctx->error, DBUS_ERROR_NO_MEMORY,
		  "Cannot create WLAN settings_and_connect request");
cleanup:
	if (msg != NULL)
		dbus_message_unref(msg);

	EXIT;
#endif
	return result;
}


/* ------------------------------------------------------------------------- */
/**
 * Send D-BUS message to wlancond to invoke WLAN scan. This is only done in
 * special case, when the UI has done the connection setup and we do not know
 * all the connection details (because they are not saved in gconf).
 * Also used when searching hidden IAPs
 * @param ctx context
 * @param ssid ssid to search
 * @param state what state we should be in
 * @retval TRUE Success.
 * @retval FALSE Error
 */
static dbus_bool_t find_ssid(struct wlan_context *ctx,
			     gchar *ssid,
			     iap_state state)
{
/* XXX: WPASUPPLICANT */
	dbus_bool_t result = FALSE;
#if 0
	DBusMessage *msg = NULL, *reply = NULL;
	gboolean succesful = FALSE;
	int tries = 0;
	dbus_int32_t txpower = get_tx_power(ctx);

	if (ctx->state != state) {
		ctx->prev_state = ctx->state;
		CHANGE_STATE(ctx, state);
	}
	ctx->last_scan = time(0);

	ENTER;

	for (tries = 0; tries < 5; tries++) {
		error_clear(&ctx->error);

		msg = dbus_message_new_method_call(
			WLANCOND_SERVICE,
			WLANCOND_REQ_PATH,
			WLANCOND_REQ_INTERFACE,
			WLANCOND_SCAN_REQ);
		if (msg == NULL)
			goto err_nomem;

		if (!dbus_message_append_args(msg,
			DBUS_TYPE_INT32, &txpower,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ssid, strlen(ssid)+1,
			DBUS_TYPE_INVALID))
			goto err_nomem;

		/* Send the message and wait for response, this should probably
		 * be changed to non-blocking.
		 * Fixme: XXX
		 */
		reply = dbus_connection_send_with_reply_and_block(
			ctx->system_bus, msg, 5*1000, &ctx->error);
		if (reply != NULL) {
			/* scan request succeeded */
			succesful = TRUE;
			break;
		} else if (dbus_error_has_name(
				   &ctx->error,
				   WLANCOND_ERROR_ALREADY_ACTIVE)) {
			/* wlancond was busy, try again a bit later */
			usleep(500000*(tries+1));
			dbus_message_unref(msg);
			msg = NULL;
			continue;
		} else {
			if (dbus_error_has_name(
				    &ctx->error,
				    WLANCOND_ERROR_WLAN_DISABLED)) {
				/* we are in flight/offline mode */
				ILOG_INFO(WLAN "In %s mode, find aborted", "offline");
			} else {
				/* some other error, stop scan */
				ILOG_DEBUG(WLAN "Received %s (%s) error",
					   ctx->error.message, ctx->error.name);
			}

			if (!ctx->search_cb) {
				/* just in case do this check */
				ILOG_ERR(WLAN "%s", "Error, search callback is missing");
			} else {
				ILOG_DEBUG(WLAN "%s", "Completing search scan");
				ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
					       NULL,
					       NULL,
					       0,
					       NULL,
					       0,
					       NULL,
					       0,
					       ctx->search_cb_token);
			}
			result = FALSE;
			goto cleanup;
		}
	}

	if (!succesful) {
		error_set(&ctx->error, ICD_DBUS_ERROR_NETWORK_ERROR,
			  "Failed to do WLAN find");
		result = FALSE;
		goto cleanup;
	}

	if (dbus_message_get_args(reply, &ctx->error, DBUS_TYPE_INVALID) == FALSE)
		goto cleanup;

	/* The scan must not continue to infinity */
	if (ctx->g_scan_timer) {
		g_source_remove(ctx->g_scan_timer);
		ctx->g_scan_timer = 0;
		ILOG_DEBUG(WLAN "Reset scan %s for find.", "timer");
	}

	ILOG_DEBUG(WLAN "[%s] creating scan timer for find (%d)", ssid, SCAN_TIMEOUT);
	ctx->g_scan_timer = g_timeout_add(SCAN_TIMEOUT*1000,
					  wlan_scan_timeout,
					  ctx);

	result = TRUE;
	goto cleanup;

err_nomem:
	error_set(&ctx->error, DBUS_ERROR_NO_MEMORY,
		  "Cannot create WLAN network find request");
cleanup:
	if (reply != NULL)
		dbus_message_unref(reply);
	if (msg != NULL)
		dbus_message_unref(msg);

	EXIT;
#endif
	return result;
}


/* ------------------------------------------------------------------------- */
/**
 * Timeout is called if scan has taken too long time.
 * @param data context
 * @retval FALSE This is always returned so that function is not called again.
 */
static gboolean wlan_scan_stop_timeout(void *data)
{
	struct wlan_context *ctx = get_wlan_context_from_dbus(data);

	ENTER;

	if (!ctx->scan_ctx) {
		/* serious error, we should not be here */
		ILOG_ERR(WLAN "ERROR: %s",
			 "In scanning wait timeout but context is not set!");
		EXIT;
		if (ctx->link_up_cb) {
			ctx->link_up_cb(ICD_NW_ERROR, NULL, NULL,
					ctx->link_up_cb_token, NULL);
			ctx->link_up_cb = NULL;
		}

		return FALSE;
	}

	g_source_remove(ctx->scan_ctx->g_scan_wait_timer);
	ctx->scan_ctx->g_scan_wait_timer = 0;
	ctx->scan_ctx->retry_count++;

	EXIT;

	/* Then just call bring up which sets the timer again */
	ILOG_DEBUG(WLAN "[%s] going up again.", ctx->scan_ctx->network_id);
	wlan_bring_up(ctx->scan_ctx->network_type,
		      ctx->scan_ctx->network_attrs,
		      ctx->scan_ctx->network_id,
		      ctx->scan_ctx->link_up_cb,
		      ctx->scan_ctx->link_up_cb_token,
		      ctx->scan_ctx->private);

	return FALSE;
}


/* ------------------------------------------------------------------------- */
/** 
 * Called from icd when link should be brought up.
 * @param network_type network type
 * @param network_attrs attributes, such as type of network_id, security, etc.
 * @param network_id IAP name or local id, e.g. SSID
 * @param interface_name interface that was enabled
 * @param link_up_cb callback function for notifying ICd when the IP address
 *        is configured
 * @param link_up_cb_token token to pass to the callback function
 * @param private a reference to the icd_nw_api private memeber
 */
static void wlan_bring_up(const gchar *network_type,
			  const guint network_attrs,
			  const gchar *network_id,
			  icd_nw_link_up_cb_fn link_up_cb,
			  const gpointer link_up_cb_token,
			  gpointer *private)
{
	struct wlan_context *ctx = get_wlan_context_from_icd(private);
	dbus_uint32_t mode, smethod, algorithm;

	ENTER;
#if 0

	/* If there is connection already on, then close it first. */
	if (ctx->state == STATE_CONNECTED) {
		ILOG_INFO(WLAN "Already connected, tearing down old connection to [%s]", ctx->iap_name);
		link_up_cb(ICD_NW_TOO_MANY_CONNECTIONS,
			   NULL,
			   NULL,
			   link_up_cb_token,
			   NULL);
		EXIT;
		return;
	}

	/* If we are disconnecting, the just ignore the request for a moment.
	 * Fixes: NB#91643
	 */
	if (ctx->state == STATE_DISCONNECTING) {
		ILOG_INFO(WLAN "[%s] currently disconnecting, try again later", ctx->iap_name);
		link_up_cb(ICD_NW_TOO_MANY_CONNECTIONS,
			   NULL,
			   NULL,
			   link_up_cb_token,
			   NULL);
		EXIT;
		return;
	}

	error_clear(&ctx->error);

	if (ctx->scanning_in_progress) {
		/* Fixes: NB#82482
		 * If we are scanning and receive connect request, then just
		 * stop the scan immediately.
		 */
		ctx->scanning_in_progress = FALSE;
		ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
			       NULL,
			       NULL,
			       0,
			       NULL,
			       ICD_NW_LEVEL_NONE,
			       NULL,
			       0,
			       ctx->search_cb_token);
	}
	
	/* Check that we are not connected and if we are then stop
	 * the earlier connection. Fixes: NB#88711
	 */
	if (((ctx->state == STATE_SEARCH_HIDDEN) ||
	     (ctx->state == STATE_SEARCH_SSID)) &&
	    (ctx->prev_state == STATE_CONNECTED)) {
		ILOG_INFO(WLAN "Already connected (while scanning), tearing down old connection to [%s]", ctx->iap_name);
		link_up_cb(ICD_NW_TOO_MANY_CONNECTIONS,
			   NULL,
			   NULL,
			   link_up_cb_token,
			   NULL);
		EXIT;
		return;
	}

	ILOG_DEBUG(WLAN "IAP (%s) going up (state %s)", network_id, get_state_name(ctx->state));

	/* Then the hard core stuff */

	if (ctx->active_scan_count==0) {
		/* If we are scanning, then delay connection a bit. */

		if (ctx->scanning_in_progress) {
			if (!ctx->scan_ctx) {
				ctx->scan_ctx = (struct scanning_delayed *)
					g_malloc0(sizeof(struct scanning_delayed));
				if (!ctx->scan_ctx) {
					ILOG_ERR(WLAN "%s(): out of mem", __FUNCTION__);
					return;
				}
				ctx->scan_ctx->network_type = (gchar *)network_type;
				ctx->scan_ctx->network_attrs = (guint)network_attrs;
				ctx->scan_ctx->network_id = (gchar *)network_id;
				ctx->scan_ctx->link_up_cb = link_up_cb;
				ctx->scan_ctx->link_up_cb_token = link_up_cb_token;
				ctx->scan_ctx->private = private;
			}

			if (ctx->scan_ctx->retry_count < SCAN_DELAY_MAX_RETRY_COUNT) {
				ILOG_DEBUG(WLAN "Scanning in progress, waiting (%d)", ctx->scan_ctx->retry_count);
				if (ctx->scan_ctx->g_scan_wait_timer == 0) {
					ctx->scan_ctx->g_scan_wait_timer = g_timeout_add(
						250,
						wlan_scan_stop_timeout,
						ctx);
				}
				EXIT;
				return;
				
			} else {
				/* waited long enough, return error */
				ILOG_INFO(WLAN "Scanning in progress, cannot connect to \"%s\" (%d)", network_id, ctx->scan_ctx->retry_count);
				link_up_cb(ICD_NW_ERROR, NULL, NULL, link_up_cb_token, NULL);
				EXIT;
				return;
			}
			
		} else {
			if (ctx->scan_ctx) {
				/* Ok, we can now remove this because it is no longer
				 * needed.
				 */
				if (ctx->scan_ctx->g_scan_wait_timer) {
					g_source_remove(ctx->scan_ctx->g_scan_wait_timer);
					ctx->scan_ctx->g_scan_wait_timer = 0;
				}
				g_free_z(ctx->scan_ctx);
			}
		}
	}

	/* Clear old values in order to avoid memory leak */
	if (ctx->state != STATE_SEARCH_SSID) {
		g_free_z(ctx->iap_name);
		ctx->is_iap_name = FALSE;
		g_free_z(ctx->ssid);
		g_free_z(ctx->interface);
		ctx->capabilities = 0;
		ctx->iap_associated = FALSE;

		ctx->link_up_cb = link_up_cb;
		ctx->link_up_cb_token = link_up_cb_token;
		ctx->network_type = network_type;

		//ILOG_DEBUG(WLAN "link up = %p", link_up_cb);

		if (network_attrs & ICD_NW_ATTR_IAPNAME) {
			ctx->iap_name = g_strdup(network_id);
			ctx->is_iap_name = TRUE;
			
			ctx->ssid = get_iap_config_bytearray(ctx->gconf_client,
							     ctx->iap_name,
							     "wlan_ssid");
			if (!ctx->ssid) {
				/* If no ssid is found, then just quit */
				ILOG_INFO(WLAN "No ssid for IAP \"%s\", "
					 "cannot continue.", network_id);
				if (ctx->link_up_cb) {
					ctx->link_up_cb(ICD_NW_ERROR, NULL, NULL,
							ctx->link_up_cb_token, NULL);
					ctx->link_up_cb = NULL;
				}
				EXIT;
				return;
			}

			ILOG_DEBUG(WLAN "IAP \"%s\" --> ssid \"%s\"",
				   ctx->iap_name, ctx->ssid);

		} else {
			ctx->ssid = g_strdup(network_id);
			ctx->iap_name = g_strdup(ctx->ssid);
		}
	}


	ctx->network_attrs = network_attrs;
	nwattr2cap(network_attrs, &ctx->capabilities);

	mode = ctx->capabilities & WLANCOND_MODE_MASK;
	smethod = ctx->capabilities & WLANCOND_ENCRYPT_METHOD_MASK;
	algorithm = ctx->capabilities & WLANCOND_ENCRYPT_ALG_MASK;

	if (smethod==0) {
		/* This means that the search is not yet done, get the
		 * values from gconf.
		 */
		gchar *key;
		dbus_uint32_t val = 0;

		key = get_iap_config_string(ctx->gconf_client,
					    ctx->iap_name,
					    "wlan_security");
		if (key == NULL) {
			ILOG_ERR(WLAN "[%s] could not get security method from gconf", ctx->iap_name);
			goto OUT;
		}
		val = parse_security_method(key);
		if (!val) {
			ILOG_ERR(WLAN "[%s] Unknown security method in gconf: %s",
				 network_id, key);
		} else {
			ctx->capabilities |= val;
			smethod = ctx->capabilities & WLANCOND_ENCRYPT_METHOD_MASK;
		}
		g_free_z(key);
	}

	if (mode==0) {
		gchar *key;
		dbus_uint32_t val = 0;

		key = get_iap_config_string(ctx->gconf_client,
					    ctx->iap_name,
					    "type");
		if (key == NULL) {
			ILOG_ERR(WLAN "%s", "Could not get wlan type from gconf.");
			goto OUT;
		}
		val = parse_wlan_type(key);
		if (!val) {
			ILOG_ERR(WLAN "[%s] Unknown type in gconf: %s",
				 network_id, key);
		} else {
			ctx->capabilities |= val;
			mode = ctx->capabilities & WLANCOND_MODE_MASK;
		}
		g_free_z(key);


		ILOG_DEBUG(WLAN "[%s] Capabilities : 0x%04x (type=0x%02x,"
			  " security=0x%02x, algorithm=0x%02x)",
			  ctx->ssid, ctx->capabilities,
			  ctx->capabilities & WLANCOND_MODE_MASK,
			  ctx->capabilities & WLANCOND_ENCRYPT_METHOD_MASK,
			  ctx->capabilities & WLANCOND_ENCRYPT_ALG_MASK);
	}


	/* For WPA connections, there is a special handling because
	 * there is a weird mistake in old icd, some of the wlan
	 * encryption parameter are not saved in gconf. This means that
	 * in connection phase the old icd needed to make a search in
	 * order to send valid dbus call (settings_and_connect()) to wlancond.
	 * This of course slows down connection setup phase.
	 * This behaviour should be fixed in icd2 (encryption algorithm should
	 * be saved to gconf) so that connection setup is made faster.
	 * But until that happens we need to do the search ourselves here.
	 *
	 * Note, that the search that is implemented in this module fetches
	 * the algorithm from wlancond so if icd2 uses autoconnect, then the
	 * algorithm value is set, but if the search is done only by UI,
	 * then icd2 search is not used at all and algorithm will not be set,
	 * and we must done the search ourselves.
	 */
	if ((ctx->active_scan_count>=0 && ctx->active_scan_count<=3) && 
	    ((smethod == WLANCOND_WPA_PSK) || (smethod == WLANCOND_WPA_EAP)) &&
	    (algorithm == 0)) {
		/* Do a search in order to fetch algorithm.
		 * If algorithm is set, then the search was done using
		 * wlan module search functions and this search is not
		 * needed.
		 */
		if (!find_ssid(ctx, ctx->ssid, STATE_SEARCH_SSID)) {
			/* We cannot continue because the search must
			 * have failed miserably.
			 */
			ILOG_ERR(WLAN "Encryption algorithm is not found, cannot connect to \"%s\"", network_id);
			goto OUT;
		}

		/* Ok, now we just return. The wlancond send results back,
		 * and we continue with the connection setup phase from
		 * signal handler.
		 */
		EXIT;
		return;
	} else {
		ILOG_DEBUG(WLAN "[%s] count=%d, smethod=0x%02x, algo=0x%02x",
			   ctx->iap_name, ctx->active_scan_count,
			   smethod, algorithm);
	}

	if (ctx->capabilities) {
		CHANGE_STATE(ctx, STATE_CONNECTING);

		if (setup_wlan(ctx, ctx->ssid, ctx->capabilities) == TRUE) {

			char *iap = (char *)(ctx->iap_name ? ctx->iap_name : network_id);
			ILOG_DEBUG(WLAN "[%s] WLAN connecting...", iap);

			/* Results from wlancond are returned to icd by callbacks
			 * in different parts of this plugin so we do not return
			 * anything here.
			 */
			EXIT;
			return;
		}
	}

OUT:
	ctx->active_scan_count = 0; /* Fixes: NB#93920 */

	ILOG_INFO(WLAN "[%s] WLAN connect failed: %s (%s)",
		  network_id,
		  ctx->error.message ? ctx->error.message : "",
		  ctx->error.name ? ctx->error.name : "<error not set>");

	CHANGE_STATE(ctx, STATE_IDLE);

	if (ctx->link_up_cb) {
		ctx->link_up_cb(ICD_NW_ERROR, ctx->error.name, NULL,
				ctx->link_up_cb_token, NULL);
		ctx->link_up_cb = NULL;
	} else {
		ILOG_DEBUG(WLAN "link cb is %s", "NULL");
	}
#endif
	EXIT;
	return;
}


/* ------------------------------------------------------------------------- */
/**
 * Callback to handle WPS registrar error event from wlancond. The registrar
 * error signal is returned if wlancond notices overlapping push button
 * condition.
 * @param conn D-BUS connection that received the signal.
 * @param msg The D-BUS scan_result signal.
 * @param user_data Wlan context.
 * @retval TRUE Success.
 * @retval FALSE Error.
 */
static dbus_bool_t wps_registrar_error(DBusConnection *conn,
				       DBusMessage *msg,
				       void *user_data)
{
	struct wlan_context *ctx = get_wlan_context_from_dbus(user_data);

	ENTER;

	error_clear(&ctx->error);
	clear_all_timers(ctx);

	if (ctx->link_up_cb) {
		ILOG_DEBUG(WLAN "[%s] WPS registrar error",
				   ctx->iap_name);
		ctx->link_up_cb(ICD_NW_ERROR, NULL, NULL,
				ctx->link_up_cb_token, NULL);
		ctx->link_up_cb = NULL;
	} else {
		ILOG_DEBUG(WLAN "[%s] WPS registrar failure but callback is missing",
			   ctx->iap_name);
	}

	EXIT;
	return TRUE;
}


/* ------------------------------------------------------------------------- */
/**
 * Callback to handle signals from wlancond.
 * Dispatches signals to proper handler functions.
 * @param c D-BUS connection that received the message.
 * @param msg Received message.
 * @param user_data Unused.
 * @retval DBUS_HANDLER_RESULT_HANDLED Success.
 * @retval DBUS_HANDLER_RESULT_NOT_YET_HANDLED Message not recognized.
 */
static DBusHandlerResult handle_wlan_message(
	DBusConnection *c,
	DBusMessage *msg,
	void *user_data)
{
#if 0
	ENTER;

	if (dbus_message_is_signal(msg,
				   WLANCOND_SIG_INTERFACE,
				   WLANCOND_SCAN_RESULTS_SIG)) {
		wlan_get_scan_result(c, msg, user_data);
		EXIT;
		return DBUS_HANDLER_RESULT_HANDLED;

	} else if (dbus_message_is_signal(msg,
					  WLANCOND_SIG_INTERFACE,
					  WLANCOND_CONNECTED_SIG)) {
		wlan_connected(c, msg, user_data);
		EXIT;
		return DBUS_HANDLER_RESULT_HANDLED;

	} else if (dbus_message_is_signal(msg,
					  WLANCOND_SIG_INTERFACE,
					  WLANCOND_DISCONNECTED_SIG)) {
		wlan_disconnected(c, msg, user_data);
		EXIT;
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg,
					  WLANCOND_SIG_INTERFACE,
					  WLANCOND_REGISTRAR_ERROR_SIG)) {
		wps_registrar_error(c, msg, user_data);
		EXIT;
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	EXIT;
#endif
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


/* ------------------------------------------------------------------------- */
/**
 * Initialize plugin: register to listen D-BUS signals from wlancond.
 * @param ctx wlan context information.
 * @param TRUE Success.
 * @param FALSE Error.
 */
static gboolean wlan_bearer_init(struct wlan_context *ctx)
{
#if 0
	static const char *wlan_path = "/com/nokia/wlancond/signal";
	static struct DBusObjectPathVTable wlan_vtable = {
		.message_function = &handle_wlan_message
	};

	ENTER;

	dbus_bus_add_match(ctx->system_bus,
			   "type='signal',"
			   "interface='" WLANCOND_SIG_INTERFACE "',"
			   "path='" WLANCOND_SIG_PATH "'",
			   NULL);

	if (dbus_connection_register_object_path(
		    ctx->system_bus, wlan_path, &wlan_vtable, (void*) ctx) == FALSE) {
		ILOG_ERR(WLAN
			 "Cannot register dbus signal handler (interface=%s, path=%s)",
			 WLANCOND_SIG_INTERFACE, WLANCOND_SIG_PATH);
		EXIT;
		return FALSE;
	}

	EXIT;
#endif
	return TRUE;
}


/* ------------------------------------------------------------------------- */
/**
 * Callback to after WLAN active scan has been running too long.
 * @param data The IAP data.
 * @retval TRUE Success.
 * @retval FALSE Error.
 */
static gboolean wlan_scan_timeout(void *data)
{
	struct wlan_context *ctx = get_wlan_context_from_dbus(data);

	ENTER;

	error_clear(&ctx->error);

	ctx->g_scan_timer = 0;

	if (ctx->state == STATE_SEARCH_SSID) {
		ILOG_INFO(WLAN "%s", "WLAN find has been running for too long; "
			  "killing it.");

		error_set(&ctx->error,
			  ICD_DBUS_ERROR_NETWORK_ERROR,
			  "WLAN find timed out");

		/* Note that we do not call search_cb because we are
		 * at connection setup phase (not in search)
		 */
		EXIT;
		return FALSE;
	}

	ILOG_INFO(WLAN "%s", "WLAN active scan has been running for too long; "
		  "killing it.");

	error_set(&ctx->error,
		  ICD_DBUS_ERROR_NETWORK_ERROR,
		  "WLAN active scan timed out");

	ctx->scanning_in_progress = FALSE;

	ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
		       NULL,
		       NULL,
		       0,
		       NULL,
		       ICD_NW_LEVEL_NONE,
		       NULL,
		       0,
		       ctx->search_cb_token);

	EXIT;
	return FALSE;
}


/* ------------------------------------------------------------------------- */
/**
 * Send D-BUS message to wlancond to invoke WLAN scan.
 * @param ctx Wlan context.
 * @param network_type network type to search for or NULL for all networks
 * @retval TRUE Success.
 * @retval FALSE Error
 */
static dbus_bool_t scan_ssid(struct wlan_context *ctx,
			     const gchar *network_type)
{
	DBusMessage *msg = NULL, *reply = NULL;
	dbus_bool_t result = FALSE;
	gboolean succesful = FALSE;
	int tries = 0;
	dbus_int32_t txpower = get_tx_power(ctx);
	gchar *ssid = "";

	ENTER;

	ILOG_DEBUG(WLAN "[%s] Starting wlan scan", network_type ? network_type : "<any>");
#if 0

	for (tries = 0; tries < 5; tries++) {
		error_clear(&ctx->error);

		msg = dbus_message_new_method_call(
			WLANCOND_SERVICE,
			WLANCOND_REQ_PATH,
			WLANCOND_REQ_INTERFACE,
			WLANCOND_SCAN_REQ);
		if (msg == NULL)
			goto err_nomem;

		if (!dbus_message_append_args(msg,
			DBUS_TYPE_INT32, &txpower,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ssid, strlen(ssid)+1,
			DBUS_TYPE_INVALID))
			goto err_nomem;

		/* Send the message and wait for response */
		reply = dbus_connection_send_with_reply_and_block(
			ctx->system_bus, msg, -1, &ctx->error);
		if (reply != NULL) {
			/* scan request succeeded */
			succesful = TRUE;
			ctx->scanning_in_progress = TRUE;
			break;
		} else if (dbus_error_has_name(
				   &ctx->error,
				   WLANCOND_ERROR_ALREADY_ACTIVE)) {
			/* wlancond was busy, try again a bit later */
			usleep(500000*(tries+1));
			dbus_message_unref(msg);
			msg = NULL;
			continue;
		} else {
			if (dbus_error_has_name(
				    &ctx->error,
				    WLANCOND_ERROR_WLAN_DISABLED)) {
				/* we are in flight/offline mode */
				ILOG_INFO(WLAN "In %s mode, scan aborted", "offline");
			} else {
				/* some other error, stop scan */
				ILOG_INFO(WLAN "Received %s (%s) error",
					  ctx->error.message, ctx->error.name);
			}

			if (!ctx->search_cb) {
				/* just in case do this check */
				ILOG_ERR(WLAN "Error, %s callback is missing",
					 "search");
			} else {
				ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
					       NULL,
					       NULL,
					       0,
					       NULL,
					       0,
					       NULL,
					       0,
					       ctx->search_cb_token);
			}
			result = FALSE;
			goto cleanup;
		}
	}

	if (!succesful) {
		error_set(&ctx->error,
			  ICD_DBUS_ERROR_NETWORK_ERROR,
			  "Failed to do WLAN scan");
		result = FALSE;
		goto cleanup;
	}

	if (dbus_message_get_args(reply,
				  &ctx->error,
				  DBUS_TYPE_INVALID) == FALSE)
		goto cleanup;

	if (ctx->g_scan_timer) {
		g_source_remove(ctx->g_scan_timer);
		ctx->g_scan_timer = 0;
		ILOG_DEBUG(WLAN "Reset scan %s for scan.", "timer");
	}

	ILOG_DEBUG(WLAN "Creating scan timer (%d)", SCAN_TIMEOUT);
	ctx->g_scan_timer = g_timeout_add(SCAN_TIMEOUT*1000,
					  wlan_scan_timeout,
					  ctx);

	result = TRUE;
	goto cleanup;

err_nomem:
	error_set(&ctx->error, DBUS_ERROR_NO_MEMORY,
		  "Cannot create WLAN network scan request");
cleanup:
	if (reply != NULL)
		dbus_message_unref(reply);
	if (msg != NULL)
		dbus_message_unref(msg);
#endif

	EXIT;
	return result;
}


/* ----------------------------------------------------------------------- */
/**
 * Get link statistics.
 * @param network_type network type
 * @param network_attrs attributes, such as type of network_id, security, etc.
 * @param network_id IAP name or local id, e.g. SSID
 * @param private a reference to the icd_nw_api private memeber
 * @param stats_cb callback function when delivering the data
 * @param link_stats_cb_token token to pass to the callback function
 */
static void wlan_statistics(const gchar *network_type,
			    const guint network_attrs,
			    const gchar *network_id,
			    gpointer *private,
			    icd_nw_link_stats_cb_fn stats_cb,
			    const gpointer link_stats_cb_token)
{
	ENTER;
#if 0
	struct wlan_context *ctx = get_wlan_context_from_icd(private);

	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;

	char *essid, *bssid, *iface;
	int bssid_len, essid_len;
	gboolean st = TRUE;
	dbus_int32_t rssi;
	dbus_uint32_t channel, cap_bits, enc_status;
	gchar *station_id;

	ENTER;

	if (!stats_cb)
		return;

	error_clear(&ctx->error);

	msg = dbus_message_new_method_call(WLANCOND_SERVICE,
					   WLANCOND_REQ_PATH,
					   WLANCOND_REQ_INTERFACE,
					   WLANCOND_STATUS_REQ);
	if (msg == NULL) {
		st = FALSE;
		goto cleanup;
	}

	reply = dbus_connection_send_with_reply_and_block(
		ctx->system_bus, msg, 5*1000, &ctx->error);
	if (!reply) {
		ILOG_ERR(WLAN "[%s] WLAN status req failed, no reply from wlancond",
			 network_id);
		goto cleanup;
	}

	if (dbus_set_error_from_message(&ctx->error, reply)) {
		ILOG_INFO(WLAN "[%s] WLAN statistics failed (%s)",
			  network_id, ctx->error.message);
		goto cleanup;
	}

	if (dbus_message_get_args(
		    reply, &ctx->error,
		    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &essid, &essid_len,
		    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &bssid, &bssid_len,
		    DBUS_TYPE_UINT32, &rssi,
		    DBUS_TYPE_UINT32, &channel,
		    DBUS_TYPE_UINT32, &cap_bits,
		    DBUS_TYPE_UINT32, &enc_status,
		    DBUS_TYPE_STRING, &iface,
		    DBUS_TYPE_INVALID) == FALSE)
		goto cleanup;

	station_id = convert_bss_to_hex(bssid, bssid_len);

	stats_cb(link_stats_cb_token,
		 network_type,
		 network_attrs,
		 network_id,
		 0,              // time active
		 map_rssi(rssi), // signal level
		 station_id,     // base station id
		 rssi,           // db raw signal strength
		 0,              // rx bytes
		 0);             // tx bytes

	g_free_z(station_id);

	ILOG_DEBUG(WLAN "iap=\"%s\", rssi=%d, ch=%d, cap=0x%08x, enc=0x%08x, "
		   "iface=%s",
		   network_id, rssi, channel, cap_bits,
		   enc_status, iface);

	EXIT;
	goto out;

cleanup:
	if (!st) {
		ILOG_DEBUG(WLAN "link (%s) cannot get statistics from %s:%s:%s:%s  %s (%s)",
			  network_id,
			  WLANCOND_SERVICE,
			  WLANCOND_REQ_PATH,
			  WLANCOND_REQ_INTERFACE,
			  WLANCOND_STATUS_REQ,
			  ctx->error.message, ctx->error.name);
	}

	EXIT;

	stats_cb(link_stats_cb_token,
		 network_type,
		 network_attrs,
		 network_id,
		 0,
		 0,
		 0,
		 0,
		 0,
		 0);

out:
	if (msg != NULL)
		dbus_message_unref(msg);
	if (reply != NULL)
		dbus_message_unref(reply);

#endif
	EXIT;
	return;
}


/* ----------------------------------------------------------------------- */
/**
 * Start wlan search
 * @param network_type network type to search for or NULL for all networks
 * @param search_scope scope for network search, not used currently
 * @param search_cb the search callback
 * @param search_cb_token token from the ICd to pass to the callback
 * @private a reference to the icd_nw_api private member
 */
static void wlan_start_search (const gchar *network_type,
			       guint search_scope,
			       icd_nw_search_cb_fn search_cb,
			       const gpointer search_cb_token,
			       gpointer *private)
{
	struct wlan_context *ctx = get_wlan_context_from_icd(private);

	ENTER;
	ILOG_DEBUG(WLAN "STARTING SEARCH");

	error_clear(&ctx->error);

	if (ctx->g_scan_timer) {
		ILOG_DEBUG(WLAN "Already scanning (%d). Search req ignored.", ctx->g_scan_timer);
		EXIT;
		return;
	}

	ctx->search_cb = search_cb;
	ctx->search_cb_token = search_cb_token;

	/* Do not send powersave if we are connected and scan request is
	 * initiated.
	 */
	if (ctx->state != STATE_CONNECTED)
		ctx->scan_started = TRUE;

	if (scan_ssid(ctx, network_type) == FALSE) {
		ILOG_INFO(WLAN "WLAN scan failed: %s (%s)",
			  ctx->error.message, ctx->error.name);
		ctx->scan_started = FALSE;

		/* Fixes: NB#95893 */
		ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
			       NULL,
			       NULL,
			       0,
			       NULL,
			       0,
			       NULL,
			       0,
			       ctx->search_cb_token);
		ctx->search_cb = NULL;
		ctx->search_cb_token = NULL;
	}

	EXIT;
	return;
}


/* ----------------------------------------------------------------------- */
/**
 * Function for stopping an ongoing search
 * @param search_cb the search callback
 * @param search_cb_token token from the ICd to pass to the callback
 * @private a reference to the icd_nw_api private member
 */
static void wlan_stop_search (gpointer *private)
{
	struct wlan_context *ctx = get_wlan_context_from_icd(private);
	char *modestr = get_mode_string(ctx->capabilities);

	ENTER;

	cap2nwattr(ctx->capabilities, &ctx->network_attrs);

	if (ctx->g_scan_timer) {
		ILOG_DEBUG(WLAN "Stopping scan %s.", "timer");
		g_source_remove(ctx->g_scan_timer);
		ctx->g_scan_timer = 0;
	}
	ctx->scan_started = FALSE;

	ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
		       NULL,
		       modestr,
		       ctx->network_attrs,
		       ctx->ssid,
		       ICD_NW_LEVEL_NONE,
		       0,
		       0,
		       ctx->search_cb_token);

	EXIT;
}


/* ----------------------------------------------------------------------- */
static inline DBusConnection *get_dbus_conn(DBusError *error)
{
	DBusConnection *conn;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, error);
	return conn;
}



/* ------------------------------------------------------------------------- */
/**
 * Clean up wlan module.
 */
static void wlan_destruct(gpointer *private)
{
	ENTER;

	if (private) {
		struct wlan_context *ctx = get_wlan_context_from_icd(private);
		clear_connection(ctx);

		/* this is allocated in icd_nw_init() */
		error_clear(&ctx->error);
		if (ctx->system_bus) {
			dbus_connection_unref(ctx->system_bus);
		}

		g_free_z(ctx);
	}

	EXIT;
}


/* ------------------------------------------------------------------------- */
/**
 * Initialize GConfClient connection for icd_context.
 * Creates default GConf client and preloads some of the required keys.
 * @param ctx ICD context to initialize
 * @retval TRUE Success
 * @retval FALSE Failure
 */
static gboolean wlan_gconf_init(struct wlan_context *ctx)
{
	/* GConf init */
	ctx->gconf_client = gconf_client_get_default();
	if (ctx->gconf_client == NULL) {
		ILOG_ERR(WLAN "%s", "Failed to connect to GConf");
		return FALSE;
	}
	return TRUE;
}


/* ------------------------------------------------------------------------- */
/**
 * Initialize WLAN network module
 * @param network_api icd_nw_api structure filled in by the module
 * @param watch_cb function to inform ICd that a child process is to be
 *        monitored for exit status
 * @param watch_cb_token token to pass to the watch pid function
 * @param close_cb function to inform ICd that the network connection is to be
 *        closed
 * @return TRUE on succes; FALSE on failure whereby the module is unloaded
 */
gboolean icd_nw_init (struct icd_nw_api *network_api,
		      icd_nw_watch_pid_fn watch_cb,
		      gpointer watch_cb_token,
		      icd_nw_close_fn close_cb)
{
	struct wlan_context *context;

	ILOG_DEBUG ("%s initializing", PACKAGE_STRING);

#ifdef DEBUG
	wlan_debug_level = 1; /* it should be able to set this up at runtime */
#endif

	network_api->version = ICD_NW_MODULE_VERSION;
	network_api->link_down = wlan_take_down;
	network_api->link_up = wlan_bring_up;
	network_api->start_search = wlan_start_search;
	network_api->stop_search = wlan_stop_search;
	network_api->network_destruct = wlan_destruct;
	network_api->link_stats = wlan_statistics;

	context = (struct wlan_context *)g_malloc0(sizeof(struct wlan_context));
	if (!context) {
		errno = ENOMEM;
		return FALSE;
	}

	if (!wlan_gconf_init(context)) {
		g_free_z(context);
		return FALSE;
	}

	network_api->search_interval = 10;
	network_api->search_lifetime = 2*network_api->search_interval; // XXX: fixme

	error_init(&context->error);
	context->system_bus = get_dbus_conn(&context->error);
	if (!context->system_bus) {
		g_free_z(context);
		return FALSE;
	}

	context->watch_cb = watch_cb;
	context->close_cb = close_cb;
	network_api->private = context;

	/* setup dbus monitor etc. */
	ILOG_DEBUG(WLAN "Made it almost the end of init");
	return wlan_bearer_init(context);
}

/** @} */
