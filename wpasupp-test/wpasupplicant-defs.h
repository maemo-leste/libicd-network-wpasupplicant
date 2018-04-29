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

#ifndef _WPASUPPLICANT_DEFS_H_
#define _WPASUPPLICANT_DEFS_H_

#define WPA_DBUS_SERVICE "fi.w1.wpa_supplicant1"
#define WPA_DBUS_INTERFACE "fi.w1.wpa_supplicant1"
#define WPA_DBUS_OPATH "/fi/w1/wpa_supplicant1"

#define WPA_DBUS_INTERFACES_INTERFACE "fi.w1.wpa_supplicant1.Interface"
#define WPA_DBUS_INTERFACES_OPATH "/fi/w1/wpa_supplicant1/Interfaces"
#define WPA_DBUS_BSS_INTERFACE "fi.w1.wpa_supplicant1.BSS"

#define DBUS_PROPERTIES_INTERFACE_NAME "org.freedesktop.DBus.Properties"

#endif /* _WPASUPPLICANT_DEFS_H_ */
