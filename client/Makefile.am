## Process this file with automake to produce Makefile.in
SUBDIRS = compat doc

DIST_SUBDIRS = $(SUBDIRS)

LIBICONV = @LIBICONV@

AM_CPPFLAGS = -DFUSE_USE_VERSION=26
AM_LDFLAGS = $(LIBICONV)

bin_PROGRAMS = httpostfs

httpostfs_SOURCES = httpostfs.c
if FUSE_OPT_COMPAT
httpostfs_LDADD = libhttpostfs.a compat/libcompat.la
else
httpostfs_LDADD = libhttpostfs.a
endif

noinst_LIBRARIES = libhttpostfs.a

libhttpostfs_a_SOURCES = charset_utils.c charset_utils.h httpostfs.h
