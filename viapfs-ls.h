#ifndef __VIAPHPFS_VIAPFS_LS_H__
#define __VIAPHPFS_VIAPFS_LS_H__

/*
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>
    2013 Mehdi Bouaziz <mehdi@bouaziz.me>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "cache.h"

int parse_dir(const char* list, const char* dir,
              const char* name, struct stat* sbuf,
              char* linkbuf, int linklen,
              fuse_cache_dirh_t h, fuse_cache_dirfil_t filler);

int parse_stat(const char* s, struct stat* sbuf);

#endif  /* __VIAPHPFS_VIAPFS_LS_H__ */
