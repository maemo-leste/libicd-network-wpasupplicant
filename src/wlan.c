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
#include <icd/icd_wlan_defs.h>

#include <maemosec_certman.h>


#include "libicd-network-wlan-dev.h"
#include "wlan.h"
#include "icd-common-utils.h"
#include "wpaicd.h"

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

static void wlan_bring_up(const gchar *network_type,
			  const guint network_attrs,
			  const gchar *network_id,
			  icd_nw_link_up_cb_fn link_up_cb,
			  const gpointer link_up_cb_token,
			  gpointer *private);
static gboolean wlan_scan_timeout(void *data);

/* to avoid double free */
#define g_free_z(a) do { g_free(a); (a)=0; } while(0)

int wlan_debug_level = 1;


/* helper struct for remembering adhoc networks */
struct adhoc_helper {
	gchar *ssid;
	guint capability;
};

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
static void disconnect_cb(DBusPendingCall *pending, void *user_data)
{
	struct wlan_context *ctx = get_wlan_context_from_dbus(user_data);

	ENTER;

	/* The actual disconnect is handled by disconnected signal sent
	 * by wlancond so we don't do anything here.
	 */

	EXIT;
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

	ENTER;

	EXIT;
	return;
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

	ENTER;

	EXIT;
	return;
}

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

	EXIT;
	return;
}

static void wlan_search_network_added_cb (BssInfo* info, void* data) {
	struct wlan_context *ctx = get_wlan_context_from_wpaicd(data);

    gchar* ssid = calloc((info->ssid_len+1), sizeof(char));
    memcpy(ssid, info->ssid, info->ssid_len);
    ssid[info->ssid_len] = '\0';

    enum icd_nw_levels signal = map_rssi(info->signal);

    guint network_attrs = 0;


    /* TODO: WEP, WPA-EAP, and many, many more... */
    if (info->rsn.keymgmt_wpa_psk ||
        info->rsn.keymgmt_wpa_psk_sha256) {
        network_attrs |= WLAN_SECURITY_WPA_PSK;
    } else {
        network_attrs |= WLAN_SECURITY_OPEN;
    }


    /* TODO USE INFO */
    ctx->search_cb(ICD_NW_SEARCH_CONTINUE,
                ssid,
                info->infrastructure ? WLAN_TYPE_INFRA : WLAN_TYPE_ADHOC,
				network_attrs, /* network attrs */
                ssid, /* network_id */
                signal, /* signal */
                "AAAAAA", /* TODO station_id */
                info->signal, /* dB */
                ctx->search_cb_token);

    /* XXX: free(ssid); */
}

static void wlan_search_scan_done_cb (int ret, void* data) {
	struct wlan_context *ctx = get_wlan_context_from_wpaicd(data);

    wlan_scan_timeout(data);

    ctx->search_cb = NULL;
    ctx->search_cb_token = NULL;
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

    wpaicd_initiate_scan();

	ctx->search_cb = search_cb;
	ctx->search_cb_token = search_cb_token;

#if 0
    ctx->search_cb(ICD_NW_SEARCH_CONTINUE,
                "Testing 1 2 3",
                WLAN_TYPE_INFRA,
				0, /* network attrs */
                "Testing 1 2 3", /* network_id */
                ICD_NW_LEVEL_5, /* signal */
                "AAAAAA", /* station_id */
                -40, /* dB */
                ctx->search_cb_token);
#endif
                
#if 0
ctx->search_cb(ICD_NW_SEARCH_CONTINUE,
               id->name,
               mode,
               nwattrs | ICD_NW_ATTR_IAPNAME | wlan_get_autoconnect(ctx, cap_bits, id->id),
               id->id,
               level,
               bsshex,
               rssi,
               ctx->search_cb_token);
#endif


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

	ENTER;
	ILOG_DEBUG(WLAN "STOPPING SEARCH");

#if 0
	ctx->search_cb(ICD_NW_SEARCH_COMPLETE,
		       NULL,
		       modestr,
		       ctx->network_attrs,
		       ctx->ssid,
		       ICD_NW_LEVEL_NONE,
		       0,
		       0,
		       ctx->search_cb_token);
#endif

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
 * Clean up wlan module.
 */
static void wlan_destruct(gpointer *private)
{
	ENTER;

    wpaicd_free();
	/* TODO: Free context->gconf_client */

	EXIT;
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

	network_api->search_interval = 10;
	network_api->search_lifetime = 2*network_api->search_interval; // XXX: fixme

    /* TODO: watch_cb is never used? */
	context->watch_cb = watch_cb;
	context->close_cb = close_cb;

	network_api->private = context;

    if (!wpaicd_init()) {
        ILOG_ERR(WLAN "%s", "Failed to set up wpaicd");
        g_free_z(context);
        return FALSE;
	}
    wpaicd_set_network_added_cb(wlan_search_network_added_cb, (void*)context);
    wpaicd_set_scan_done_cb(wlan_search_scan_done_cb, (void*)context);

    if (!wlan_gconf_init(context)) {
        g_free_z(context);
        return FALSE;
    }

    /* TODO: Check if we can communicate with wpa_supplicant? */
	return TRUE;
}

/** @} */
