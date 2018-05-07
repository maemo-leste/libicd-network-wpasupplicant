SUBDIRS = src

MAINTAINERCLEANFILES = \
        Makefile.in config.h.in configure \
        install-sh ltmain.sh missing mkinstalldirs \
        compile depcomp config.log config.status \
        config.guess config.sub acinclude.m4 aclocal.m4 \
        build-stamp configure-stamp stamp-h.in \
	debian/substvars debian/files \
	debian/libicd-network-wpasupplicant.postinst.debhelper \
	debian/libicd-network-wpasupplicant.postrm.debhelper \
	debian/libicd-network-wpasupplicant.substvars

DEPCLEANFILES = config.log configure

EXTRA_DIST = \
	autogen.sh \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/rules \
	debian/libicd-network-wpasupplicant.install \
	debian/libicd-network-wpasupplicant-dev.install \
	debian/icd2-network-wpasupplicant-config.install \
	debian/icd2-network-wpasupplicant-config.postinst

# dh_gconf does not work due to missing scripts, add schema manually
gconfschemasdir = $(sysconfdir)/gconf/schemas
dist_gconfschemas_DATA = libicd-network-wpasupplicant.schemas

libicdnetworkwpasupplicantdevincludedir = $(includedir)
libicdnetworkwpasupplicantdevinclude_HEADERS = src/libicd-network-wpasupplicant-dev.h

# backup should really provide its directory in its .pc file
backuprestoredir = $(sysconfdir)/osso-backup/restore.d/always
dist_backuprestore_SCRIPTS = \
        icd2_restore_ipv6.sh

.PHONY: doxygen-doc

doxygen-doc:
if DOXYGEN_DOCS_ENABLED
	@DOXYGEN@ Doxyfile
endif

# get rid of debian build dirs
maintainer-clean-local:
	-rm -rf debian/build debian/tmp \
		debian/libicd-network-wpasupplicant \
		debian/libicd-network-wpasupplicant-dbg \
		debian/icd2-network-wpasupplicant-config

deb: dist
	-mkdir $(top_builddir)/debian-build
	cd $(top_builddir)/debian-build && tar zxf ../$(top_builddir)/$(PACKAGE)-$(VERSION).tar.gz
	cd $(top_builddir)/debian-build/$(PACKAGE)-$(VERSION) && dpkg-buildpackage -rfakeroot 
