plugindir = @icd_plugin_dir@
plugin_LTLIBRARIES = libicd_network_wpasupplicant.la

# There is no pkgconfig file
WPA_CLIENT_LIBS = /usr/lib/*/libwpa_client.a

libicd_network_wpasupplicant_la_CFLAGS = \
			-DDBUS_API_SUBJECT_TO_CHANGE $(ICDWPA_CFLAGS)

libicd_network_wpasupplicant_la_LIBADD = \
			$(ICDWPA_LIBS) $(DMALLOC_LIBS) $(WPA_CLIENT_LIBS)

libicd_network_wpasupplicant_la_LDFLAGS = \
			-module -avoid-version

libicd_network_wpasupplicant_la_SOURCES = \
			wlan.h wlan.c \
			icd-common-utils.c icd-common-utils.h \
			wpaicd.c wpaicd.h \
			gconfmap.c gconfmap.h \
			wpasupplicant-defs.h log-common.h

MAINTAINERCLEANFILES = \
			Makefile.in
