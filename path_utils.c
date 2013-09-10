/*
    Copyright (C) 2007 Robson Braga Araujo <robsonbraga@gmail.com>
    2013 Mehdi Bouaziz <mehdi@bouaziz.me>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "path_utils.h"
#include "charset_utils.h"
#include "viapfs.h"

#include <string.h>
#include <stdlib.h>
#include <glib.h>

char* get_file_name(const char* path) {
  const char* filename = strrchr(path, '/');
  if (filename == NULL) filename = path;
  else ++filename;

  char* ret = strdup(filename);
  if (viapfs.codepage) {
    convert_charsets(viapfs.iocharset, viapfs.codepage, &ret);
  }
  
  return ret;
}

char* get_dir_path(const char* path) {
  char* ret;
  char* converted_path = NULL;
  const char *lastdir;

  ++path;
  
  lastdir = strrchr(path, '/');
  if (lastdir == NULL) lastdir = path;

  if (viapfs.codepage && (lastdir - path > 0)) {
    converted_path = g_strndup(path, lastdir - path);
    convert_charsets(viapfs.iocharset, viapfs.codepage, &converted_path);
    path = converted_path;
    lastdir = path + strlen(path);
  }

  ret = g_strdup_printf("%s%.*s%s",
                        viapfs.host,
                        lastdir - path,
                        path,
                        lastdir - path ? "/" : "");

  free(converted_path);

  return ret;
}
