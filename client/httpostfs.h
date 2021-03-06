#ifndef __HTTPOSTFS_HTTPOSTFS_H__
#define __HTTPOSTFS_HTTPOSTFS_H__

/*
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>
    Copyright (C) 2013 Mehdi Bouaziz <mehdi@bouaziz.org>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <curl/curl.h>
#include <curl/easy.h>
#include <pthread.h>
#include <fuse.h>
#include <fuse_opt.h>

#ifndef FUSE_VERSION
#define FUSE_VERSION (FUSE_MAJOR_VERSION * 10 + FUSE_MINOR_VERSION)
#endif

struct buffer {
  char* p;
  size_t len;
  size_t size;
  off_t begin_offset;
};

struct httpostfs {
  char* host;
  char* mountpoint;
  pthread_mutex_t lock;
  CURL* connection;
  blksize_t blksize;
  int verbose;
  int debug;
  int transform_symlinks;
  int tcp_nodelay;
  int connect_timeout;
  char* interface;
  char* proxy;
  int proxytunnel;
  int proxyanyauth;
  int proxybasic;
  int proxydigest;
  int proxyntlm;
  int proxytype;
  char* user;
  char* proxy_user;
  int ip_version;
  char symlink_prefix[PATH_MAX+1];
  size_t symlink_prefix_len;
  curl_version_info_data* curl_version;
  char *codepage;
  char *iocharset;

  char* readdir_cache_path;
  struct buffer readdir_cache_buf;
  char* readdir_cache_curpos;
  int readdir_cache_curoffset;
};

extern struct httpostfs httpostfs;

#define DEBUG(level, args...) \
        do { if (level <= httpostfs.debug) {\
               int i = 0; \
               while (++i < level) fprintf(stderr, " "); \
               fprintf(stderr, "%ld ", time(NULL));\
               fprintf(stderr, __FILE__ ":%d ", __LINE__);\
               fprintf(stderr, args);\
             }\
           } while(0)

#endif   /* __HTTPOSTFS_HTTPOSTFS_H__ */
