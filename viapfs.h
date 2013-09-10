#ifndef __VIAPHPFS_VIAPFS_H__
#define __VIAPHPFS_VIAPFS_H__

/*
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>
    2013 Mehdi Bouaziz <mehdi@bouaziz.me>

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

struct viapfs {
  char* host;
  char* mountpoint;
  pthread_mutex_t lock;
  CURL* connection;
  CURLM* multi;
  int attached_to_multi;
  struct viapfs_file* current_fh;
  unsigned blksize;
  int verbose;
  int debug;
  int transform_symlinks;
  char* custom_list;
  int tcp_nodelay;
  char* http_port;
  int connect_timeout;
  char* interface;
  char* krb4;
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
  int multiconn;
};

extern struct viapfs viapfs;

#define DEBUG(level, args...) \
        do { if (level <= viapfs.debug) {\
               int i = 0; \
               while (++i < level) fprintf(stderr, " "); \
               fprintf(stderr, "%ld ", time(NULL));\
               fprintf(stderr, __FILE__ ":%d ", __LINE__);\
               fprintf(stderr, args);\
             }\
           } while(0)

#endif   /* __VIAPHPFS_VIAPFS_H__ */
