AC_INIT([ICD2 WLAN network plugin],
	patsubst(esyscmd(dpkg-parsechangelog | sed -n '/^Version: \(.*\)$/ {s//\1/;p}'), ),
	[],[libicd-network-wpasupplicant])

AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE([foreign])
#AM_MAINTAINER_MODE

AC_CANONICAL_HOST

AC_PREFIX_DEFAULT([/usr])

AC_PROG_CC
AC_PROG_MAKE_SET
AM_GCONF_SOURCE_2
LT_INIT

AC_ARG_ENABLE(dmalloc,
	AS_HELP_STRING([--enable-dmalloc],[enable Dmalloc support]),
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

PKG_CHECK_MODULES(ICDWPA,
		  glib-2.0 >= 2.8.6
		  gio-2.0
		  dbus-glib-1 >= 0.61
		  gconf-2.0 >= 2.6.4
		  maemosec-certman
		  icd2)

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

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	])
AC_OUTPUT
