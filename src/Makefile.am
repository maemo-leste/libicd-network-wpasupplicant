
MAINTAINERCLEANFILES = \
        Makefile.in

DEFS = -DDBUS_API_SUBJECT_TO_CHANGE

INCLUDES = \
	@GLIB_CFLAGS@ \
	@DBUS_GLIB_CFLAGS@ \
	@GCONF_CFLAGS@ \
	@CERTMAN_CFLAGS@ \
	@ICD_CFLAGS@

LDADD = \
	@GLIB_LIBS@ \
	@DBUS_GLIB_LIBS@ \
	@GCONF_LIBS@ \
	@CERTMAN_LIBS@ \
	@ICD_LIBS@ \
	@DMALLOC_LIBS@

CFLAGS = -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Werror
LDFLAGS = -avoid-version
LDADD = /usr/lib/*/libwpa_client.a # There is no pkgconfig file

plugindir = @icd_plugin_dir@
plugin_LTLIBRARIES = libicd_network_wpasupplicant.la

libicd_network_wpasupplicant_la_LIBADD = $(LDADD)
libicd_network_wpasupplicant_la_SOURCES = \
	wlan.h wlan.c icd-common-utils.c icd-common-utils.h wpaicd.c wpaicd.h gconfmap.c gconfmap.h wpasupplicant-defs.h log-common.h

#clean: maintainer-clean
#	-rm -rf *.o *.lo *.la Makefile Makefile.in
