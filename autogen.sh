#!/bin/sh

# No need for this any more, AC_INIT seems to work now in configure.ac
#PKG_VER=`dpkg-parsechangelog | sed -n '/^Version: \(.*\)$/ {s//\1/;p}'`
#PKG_VER_AUTO=`sed -n '/^AC_INIT(\[.*\],\[\(.*\)\],\[.*\],\[.*\])/ {s//\1/;p}' configure.ac`
#if [ "$PKG_VER" != "$PKG_VER_AUTO" ]; then
#    # set the version number correctly in file
#    mv configure.ac configure.ac.old
#    sed "/^AC_INIT(\[\(.*\)\],\[.*\],\[\(.*\)\],\[\(.*\)\])/ {s//AC_INIT([\1],[$PKG_VER],[\2],[\3])/}" configure.ac.old > configure.ac
#fi

set -e
#set -x

libtoolize --force --copy
aclocal
autoheader
automake --foreign --add-missing --copy --force-missing -i
autoconf

