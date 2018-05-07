
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

LDFLAGS = -avoid-version

plugindir = @icd_plugin_dir@
plugin_LTLIBRARIES = libicd_network_wpasupplicant.la

libicd_network_wpasupplicant_la_LIBADD = $(LDADD)
libicd_network_wpasupplicant_la_SOURCES = \
	wlan.h wlan.c icd-common-utils.c icd-common-utils.h wpaicd.c wpaicd.h wpasupplicant-defs.h

#clean: maintainer-clean
#	-rm -rf *.o *.lo *.la Makefile Makefile.in
