AC_INIT([ICD2 WLAN network plugin], patsubst(esyscmd([dpkg-parsechangelog | sed -n '/^Version: \(.*\)$/ {s//\1/;p}']), [
]),[],[libicd-network-wlan])
#AC_INIT([ICD2 WLAN network plugin],[0.1-1],[],[libicd-network-wlan])

AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([foreign])
#AM_MAINTAINER_MODE

AC_CANONICAL_HOST

AC_PREFIX_DEFAULT([/usr])

AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

AC_HEADER_STDC

if test foobar${libicd_network_wlan_use_debug} = foobaryes 
then
    CFLAGS="$CFLAGS -ggdb -O0 -DDEBUG"
else
    CFLAGS="$CFLAGS"
fi

AC_ARG_ENABLE(dmalloc,
	AC_HELP_STRING([--enable-dmalloc],
		[enable Dmalloc support]),
	[ac_dmalloc=$enableval], [ac_dmalloc=no])
AC_MSG_CHECKING([for Dmalloc support])
if test x"$ac_dmalloc" == "xyes"; then
	AC_MSG_RESULT([yes])
	AC_DEFINE([DMALLOC_ENABLE], 1, [Dmalloc support])
	AC_CHECK_LIB(dmalloc, main, DMALLOC_LIBS="-ldmalloc")
	AC_SUBST(DMALLOC_LIBS)
else
	AC_MSG_RESULT([no])
fi

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.8.6)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1 >= 0.61)
AC_SUBST(DBUS_GLIB_CFLAGS)
AC_SUBST(DBUS_GLIB_LIBS)

PKG_CHECK_MODULES(GCONF, gconf-2.0 >= 2.6.4)
AC_SUBST(GCONF_CFLAGS)
AC_SUBST(GCONF_LIBS)

PKG_CHECK_MODULES(CERTMAN, maemosec-certman)
AC_SUBST(CERTMAN_CFLAGS)
AC_SUBST(CERTMAN_LIBS)

AC_CHECK_HEADER(wlancond.h,
	AC_MSG_RESULT(yes),
	AC_MSG_ERROR([wlancond.h not found])) 
AC_CHECK_HEADER(wlancond-dbus.h,
	AC_MSG_RESULT(yes),
	AC_MSG_ERROR([wlancond-dbus.h not found]))

PKG_CHECK_MODULES(ICD, icd2 >= 0.1 libicd2)
AC_SUBST(ICD_CFLAGS)
AC_SUBST(ICD_LIBS)
icd_plugin_dir=$($PKG_CONFIG --variable=icdplugindir icd2)
AC_SUBST(icd_plugin_dir)

AC_MSG_CHECKING([whether to build doxygen documentation])
AC_ARG_ENABLE(doxygen,
	[AS_HELP_STRING([--enable-doxygen],
			[enable doxygen document creation (default=no)]
			)])
if (test x$enable_doxygen = xyes); then
   AC_MSG_RESULT(yes)
   AC_CHECK_PROG(DOXYGEN, doxygen, doxygen, [])
   if (test x$DOXYGEN = x); then
      AC_MSG_WARN([doxygen requested but doxygen not found])
   else
      echo -n
      AC_SUBST(DOXYGEN)
   fi
else
   AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(DOXYGEN_DOCS_ENABLED, [test x$DOXYGEN != x])

AC_ARG_ENABLE(debug, [AC_HELP_STRING([--enable-debug],[Debug (default=no)])])


CFLAGS="$CFLAGS -std=gnu99"
CFLAGS="$CFLAGS -Wall -Wmissing-prototypes -Wmissing-declarations"
CFLAGS="$CFLAGS -include config.h"
LDFLAGS="$GLIB_LIBS $GCONF_LIBS $DBUS_LIBS"

AC_SUBST(CFLAGS)

AC_OUTPUT([
	Makefile
	src/Makefile
	])
