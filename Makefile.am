## Process this file with automake to produce Makefile.in
SUBDIRS = compat doc

DIST_SUBDIRS = $(SUBDIRS)

LIBICONV = @LIBICONV@

AM_CPPFLAGS = -DFUSE_USE_VERSION=26
AM_LDFLAGS = $(LIBICONV)

bin_PROGRAMS = viaphpfs

viaphpfs_SOURCES = viapfs.c
if FUSE_OPT_COMPAT
viaphpfs_LDADD = libviaphpfs.a compat/libcompat.la
else
viaphpfs_LDADD = libviaphpfs.a
endif

noinst_LIBRARIES = libviaphpfs.a

libviaphpfs_a_SOURCES =	 charset_utils.c charset_utils.h \
			 viapfs.h
