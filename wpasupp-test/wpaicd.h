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

#ifndef _ICDWPA_H_
#define _ICDWPA_H_
#include <gio/gio.h>

#include "wpasupplicant-defs.h"

#if 1
#define _WPA_ICD_DEBUG
#endif

typedef struct {
    guint16 frequency;

    /* icd2 network_name */
    gchar* ssid;
    gsize ssid_len;

    /* TODO: icd2 network_type: infra vs ad-hoc, etc */

    /* TODO: network_attrs */

    /* icd2 network_id is also ssid */

    /* icd2: signal (TODO: Map to proper icd2 values) */
    gint16 signal;

    /* icd2 station_id */
    gchar* mac_addr;
    gsize mac_addr_len;

    /* TODO: icd2: dB - just raw signal? */
} BssInfo;

#define _BSS_SIMPLE_INFO_FROM_DICT(gvar, keyname, structname, keytype, keytype2) \
{ \
    GVariant* var = g_variant_dict_lookup_value(gvar, keyname, keytype); \
    g_variant_get(var, keytype2, structname); \
    g_variant_unref(var); \
}

#define _BSS_BYTESTRING_FROM_DICT(gvar, keyname, target, target_len) \
{ \
    GVariant* var = g_variant_dict_lookup_value(gvar, keyname, G_VARIANT_TYPE_BYTESTRING); \
    GBytes* gb = g_variant_get_data_as_bytes(var); \
    const char* data = g_bytes_get_data(gb, &target_len); \
    target = malloc(sizeof(char)*target_len); \
    memcpy(target, data, sizeof(char)*target_len); \
    g_variant_unref(var); \
}

int init_batt(void);
void free_bat(void);

#endif /* _ICDWPA_H_ */
