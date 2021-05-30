#ifndef WLAN_H
#define WLAN_H

/**
 * Copyright (C) 2007 Nokia Corporation. All rights reserved.
 *
 * @author patrik.flykt@nokia.com
 * @author jukka.rissanen@nokia.com
 *
 * @file wlan.h
 */

#include <glib.h>
#include <dbus/dbus.h>
#include <gconf/gconf-client.h>
#include <wpa_ctrl.h>

#include "log-common.h"
#include <icd/network_api.h>

#ifdef DEBUG
#if (__GNUC__ > 2) && ((__GNUC__ > 3) || (__GNUC_MINOR__ > 2))
#define PDEBUG(fmt, args...) do {					\
		if (wlan_debug_level) {					\
			struct timeval tv;				\
			gettimeofday(&tv, 0);				\
			printf("DEBUG[%d]:%ld.%ld:%s:%s():%d: " fmt,	\
			       getpid(),				\
			       tv.tv_sec, tv.tv_usec,			\
			       __FILE__, __FUNCTION__, __LINE__, ##args);	\
			fflush(stdout);					\
		}							\
	}while(0)
#else
#define PDEBUG(fmt, args...) do {					\
		if (wlan_debug_level) {					\
			struct timeval tv;				\
			gettimeofday(&tv, 0);				\
			printf("DEBUG[%d]:%ld.%ld:%s:%s():%d: " fmt,	\
			       getpid(),				\
			       tv.tv_sec, tv.tv_usec, __FILE__,		\
			       __FUNCTION__, __LINE__, ##args);		\
			fflush(stdout);					\
		}							\
	}while(0)
#endif
#else
#define PDEBUG(fmt...)
#endif

#ifdef DEBUG
static int debug_print_level = 0;
#define ENTER {								\
		char spaces[32];					\
		int i, len;						\
		debug_print_level++;					\
		len = debug_print_level<32 ? debug_print_level : 32;	\
		for (i=0; i<len ; i++) {				\
			spaces[i]='-';					\
		}							\
		spaces[i]='\0';						\
		PDEBUG("WLAN:%s> enter\n", spaces);			\
	}

#define EXIT {								\
		char spaces[32];					\
		int i, len;						\
		len = debug_print_level<32 ? debug_print_level : 32;	\
		for (i=0; i<len ; i++) {				\
			spaces[i]='-';					\
		}							\
		spaces[i]='\0';						\
		debug_print_level--;					\
		PDEBUG("WLAN:<%s exit\n", spaces);			\
	}
#else
#define ENTER
#define EXIT
#endif

/** IAP states */
typedef enum {
    /* Not connected */
    STATE_IDLE,

    /* Attempting to connect, set in wlan_bring_up.
       Information available: iap name, iap attr, iap type */
    STATE_CONNECTING,

    /* Connected. Information available: iap name, iap attr, iap type */
    STATE_CONNECTED,

    /* ??? Does this mean we are -trying- to disconnect? */
    STATE_DISCONNECTING,
#if 0
    STATE_SEARCH_SSID,          /* Special state which is used when we need to do
                                 * search in connection phase.
                                 */
    STATE_SEARCH_HIDDEN,        /* Used when we are searching hidden IAP */
#endif
    STATE_MAX_NR
} iap_state;

/* Private stuff for this module, this only supports one wlan
 * connection at a time.
 */

struct wlan_context {
    /* TODO: Completely redo this, document what each var is needed/used for! */

    iap_state state;

    /* Used to notify icd2 that the link is up */
    icd_nw_link_up_cb_fn link_up_cb;
    gpointer link_up_cb_token;

    /* Used to notify icd2 of search results and/or search state */
    icd_nw_search_cb_fn search_cb;
    gpointer search_cb_token;

    /* To be called when interface needs to go down - e.g. we lost AP connection */
    icd_nw_close_fn close_cb;

    /* Handle to GConf client */
    GConfClient *gconf_client;

    gboolean scanning;

    const char *stored_network_type;
    guint stored_network_attrs;
    const char *stored_network_id;

    guint g_association_timer;

    struct wpa_ctrl *wpasup_ctrl;
#if 0
    struct icd_nw_api *network_api;

    gchar *iap_name;
    gchar *ssid;
    gchar *interface;

    time_t last_scan;
    int active_scan_count;      /* -1=no need to scan, 0=scan needed,
                                 * >0 current scan count
                                 */

    iap_state state;            /* connecting, connected etc */
    iap_state prev_state;
    guint network_attrs;        /* capabilities in icd format */
    const gchar *network_type;  /* pointer from icd2, do not free it */
    dbus_uint32_t capabilities; /* these are from wlanconnd */
    gboolean iap_associated;

    int used_channels;

    guint g_scan_timer;

    DBusPendingCall *disconnect_call;
    DBusPendingCall *setup_call;
    DBusError error;
    DBusConnection *system_bus;
    int search_interval;

    GHashTable *ssid_to_iap_table;
    GSList *adhoc_networks;

    struct scanning_delayed *scan_ctx;

    gboolean is_iap_name;       /* Is the iap_name variable IAP name or is it
                                 * ssid. This is needed when calling close_cb()
                                 * in disconnect.
                                 */
#endif
};

/* Note that context is taken differently when icd passes it so there are two
 * functions for this, one for icd and one for dbus usage. Use the correct one
 * depending on who gives the data.
 */
static inline struct wlan_context *get_wlan_context_from_icd(gpointer * private)
{
    return (struct wlan_context *)*private;
}

static inline struct wlan_context *get_wlan_context_from_dbus(void *user_data)
{
    return (struct wlan_context *)user_data;
}

static inline struct wlan_context *get_wlan_context_from_gconf(void *user_data)
{
    return (struct wlan_context *)user_data;
}

static inline struct wlan_context *get_wlan_context_from_wpaicd(void *user_data)
{
    return (struct wlan_context *)user_data;
}

/** @addtogroup wlan
 * @ingroup wlan_network_plugin
 * @{ */

#include <icd/network_api.h>

gboolean icd_nw_init(struct icd_nw_api *network_api,
                     icd_nw_watch_pid_fn watch_cb,
                     gpointer watch_cb_token, icd_nw_close_fn close_cb);

/** @} */

#endif
