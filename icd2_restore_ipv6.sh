#!/bin/sh

# Copyright (C) 2008 Nokia Corporation. All rights reserved.
# Author: jukka.rissanen@nokia.com

DO_CHECK=0

# Removing IPv6 stuff because it is no longer found in fremantle BUT only if
# there is no libicd-network-ipv6 package installed.
dpkg -s libicd-network-ipv6 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    DO_CHECK=1
else
    dpkg -s libicd-network-ipv6 | grep Status: | grep not-installed > /dev/null 2>&1
    if [ $? -eq 0 ]; then
	DO_CHECK=1
    fi
fi

if [ $DO_CHECK = 1 ]; then
    for NETWORK_TYPE in WLAN_INFRA WLAN_ADHOC
    do
      gconftool-2 -g /system/osso/connectivity/network_type/$NETWORK_TYPE/network_modules | grep libicd_network_ipv6.so  > /dev/null 2>&1
      if [ $? -eq 0 ]; then
	  gconftool-2 -u /system/osso/connectivity/network_type/$NETWORK_TYPE/network_modules  > /dev/null 2>&1
      fi
    done
fi

exit 0
