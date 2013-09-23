/*
    Httpost file system
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>
    Copyright (C) 2013 Mehdi Bouaziz <mehdi@bouaziz.org>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <glib.h>
#include <semaphore.h>
#include <assert.h>

#include "charset_utils.h"
#include "httpostfs.h"

struct httpostfs httpostfs;
static char error_buf[CURL_ERROR_SIZE];

static void usage(const char* progname);

static void buf_init(struct buffer* buf)
{
    buf->p = NULL;
    buf->begin_offset = 0;
    buf->len = 0;
    buf->size = 0;
}

static inline void buf_free(struct buffer* buf)
{
  if (buf->p)
    free(buf->p);
}

static inline void buf_clear(struct buffer *buf)
{
    buf_free(buf);
    buf_init(buf);
}

static int buf_resize(struct buffer *buf, size_t len)
{
    buf->size = (buf->len + len + 63) & ~31;
    buf->p = realloc(buf->p, buf->size);
    if (!buf->p) {
        fprintf(stderr, "httpostfs: memory allocation failed\n");
        return -1;
    }
    return 0;
}

static int buf_add_mem(struct buffer *buf, const void *data, size_t len)
{
    if (buf->len + len > buf->size && buf_resize(buf, len) == -1)
        return -1;

    memcpy(buf->p + buf->len, data, len);
    buf->len += len;
    return 0;
}

static void buf_null_terminate(struct buffer *buf)
{
    if (buf_add_mem(buf, "\0", 1) == -1)
        exit(1);
}

enum {
  KEY_HELP,
  KEY_VERBOSE,
  KEY_VERSION,
};

#define HTTPOSTFS_OPT(t, p, v) { t, offsetof(struct httpostfs, p), v }

static struct fuse_opt httpostfs_opts[] = {
  HTTPOSTFS_OPT("httpostfs_debug=%u", debug, 0),
  HTTPOSTFS_OPT("transform_symlinks", transform_symlinks, 1),
  HTTPOSTFS_OPT("tcp_nodelay",        tcp_nodelay, 1),
  HTTPOSTFS_OPT("connect_timeout=%u", connect_timeout, 0),
  HTTPOSTFS_OPT("interface=%s",       interface, 0),
  HTTPOSTFS_OPT("proxy=%s",           proxy, 0),
  HTTPOSTFS_OPT("proxytunnel",        proxytunnel, 1),
  HTTPOSTFS_OPT("proxy_anyauth",      proxyanyauth, 1),
  HTTPOSTFS_OPT("proxy_basic",        proxybasic, 1),
  HTTPOSTFS_OPT("proxy_digest",       proxydigest, 1),
  HTTPOSTFS_OPT("proxy_ntlm",         proxyntlm, 1),
  HTTPOSTFS_OPT("httpproxy",          proxytype, CURLPROXY_HTTP),
  HTTPOSTFS_OPT("socks4",             proxytype, CURLPROXY_SOCKS4),
  HTTPOSTFS_OPT("socks5",             proxytype, CURLPROXY_SOCKS5),
  HTTPOSTFS_OPT("user=%s",            user, 0),
  HTTPOSTFS_OPT("proxy_user=%s",      proxy_user, 0),
  HTTPOSTFS_OPT("ipv4",               ip_version, CURL_IPRESOLVE_V4),
  HTTPOSTFS_OPT("ipv6",               ip_version, CURL_IPRESOLVE_V6),
  HTTPOSTFS_OPT("codepage=%s",        codepage, 0),
  HTTPOSTFS_OPT("iocharset=%s",       iocharset, 0),

  FUSE_OPT_KEY("-h",             KEY_HELP),
  FUSE_OPT_KEY("--help",         KEY_HELP),
  FUSE_OPT_KEY("-v",             KEY_VERBOSE),
  FUSE_OPT_KEY("--verbose",      KEY_VERBOSE),
  FUSE_OPT_KEY("-V",             KEY_VERSION),
  FUSE_OPT_KEY("--version",      KEY_VERSION),
  FUSE_OPT_END
};

static int op_return(int err, char * operation)
{
	if(!err)
	{
		DEBUG(2, "%s successful\n", operation);
		return 0;
	}
        DEBUG(2, "%s failed because %s\n", operation, strerror(-err));
	fprintf(stderr, "httpostfs: operation %s failed because %s\n", operation, strerror(-err));
	return err;
}

static size_t read_data(void *ptr, size_t size, size_t nmemb, void *data) {
  struct buffer* buf = (struct buffer*)data;
  if (buf == NULL) return size * nmemb;
  if (buf_add_mem(buf, ptr, size * nmemb) == -1)
    return 0;

  DEBUG(2, "read_data: %zu\n", size * nmemb);
  DEBUG(3, "%*s\n", (int)(size * nmemb), (char*)ptr);
  return size * nmemb;
}

#define curl_easy_setopt_or_die(handle, option, ...) \
  do {\
    CURLcode res = curl_easy_setopt(handle, option, __VA_ARGS__);\
    if (res != CURLE_OK) {\
      fprintf(stderr, "Error setting curl: %s\n", error_buf);\
      exit(1);\
    }\
  }while(0)

static int post(gchar *postdata, const void *writedata) {
  pthread_mutex_lock(&httpostfs.lock);
  curl_easy_setopt_or_die(httpostfs.connection, CURLOPT_POSTFIELDS, postdata);
  curl_easy_setopt_or_die(httpostfs.connection, CURLOPT_POSTFIELDSIZE, strlen(postdata));
  curl_easy_setopt_or_die(httpostfs.connection, CURLOPT_WRITEDATA, writedata);
  CURLcode curl_res = curl_easy_perform(httpostfs.connection);
  pthread_mutex_unlock(&httpostfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
  }

  g_free(postdata);
  return curl_res;
}

static void invalidate_cache() {
  if (httpostfs.readdir_cache_path) {
    httpostfs.readdir_cache_path = NULL;
    buf_clear(&httpostfs.readdir_cache_buf);
    httpostfs.readdir_cache_curpos = NULL;
    httpostfs.readdir_cache_curoffset = 0;
  }
}

static int parse_stat(const char* s, struct stat* sbuf) {
  unsigned long long int rdev;
  unsigned long int ino, nlink;
  long int size, blocks, atime, mtime, ctime;
  unsigned int mode, uid, gid;

  if (sscanf(s, "%lu%u%lu%u%u%llu%ld%ld%ld%ld%ld", &ino, &mode, &nlink, &uid, &gid, &rdev, &size, &blocks, &atime, &mtime, &ctime) != 11)
    return 0;

  memset(sbuf, 0, sizeof(struct stat));
  sbuf->st_ino = ino;
  sbuf->st_mode = mode;
  sbuf->st_nlink = nlink;
  sbuf->st_uid = uid;
  sbuf->st_gid = gid;
  sbuf->st_rdev = rdev;
  sbuf->st_size = size;
  sbuf->st_blocks = blocks;
  sbuf->st_atime = atime;
  sbuf->st_mtime = mtime;
  sbuf->st_ctime = ctime;

  return 1;
}

static int httpostfs_readdir(const char* path, void *rbuf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  (void) offset; (void) fi;
  DEBUG(1, "httpostfs_readdir: %s from %ld\n", path, offset);

  int err = 0;

  // Check if reading continuation of the same dir
  if (offset != httpostfs.readdir_cache_curoffset) {
    httpostfs.readdir_cache_curoffset = 0;
    httpostfs.readdir_cache_curpos = httpostfs.readdir_cache_buf.p;
  }
  if (!httpostfs.readdir_cache_path || strcmp(path, httpostfs.readdir_cache_path)) {
    invalidate_cache();
    httpostfs.readdir_cache_path = strdup(path);

    CURLcode curl_res = post(g_strdup_printf("readdir\n%s\n", path), &httpostfs.readdir_cache_buf);

    if (curl_res) {
      err = -EIO;
    }
    else {
      buf_null_terminate(&httpostfs.readdir_cache_buf);
      httpostfs.readdir_cache_curoffset = 0;
      httpostfs.readdir_cache_curpos = httpostfs.readdir_cache_buf.p;
    }
  }

  if (!err) {
    struct stat sbuf;
    while (*httpostfs.readdir_cache_curpos) {
      if (httpostfs.readdir_cache_curoffset < offset) {
        while (*httpostfs.readdir_cache_curpos && *httpostfs.readdir_cache_curpos != '\n')
          httpostfs.readdir_cache_curpos++;
        if (!*httpostfs.readdir_cache_curpos)
          break;
        httpostfs.readdir_cache_curpos++;
        httpostfs.readdir_cache_curoffset++;
      }
      else {
        char* entry = httpostfs.readdir_cache_curpos;
        while (*httpostfs.readdir_cache_curpos && *httpostfs.readdir_cache_curpos != '\t')
          httpostfs.readdir_cache_curpos++;
        if (!*httpostfs.readdir_cache_curpos)
          break;
        *httpostfs.readdir_cache_curpos = 0;
        char* entrystat = ++httpostfs.readdir_cache_curpos;
        while (*httpostfs.readdir_cache_curpos && *httpostfs.readdir_cache_curpos != '\n')
          httpostfs.readdir_cache_curpos++;
        if (!*httpostfs.readdir_cache_curpos)
          break;
        *httpostfs.readdir_cache_curpos = 0;
        if (!parse_stat(entrystat, &sbuf))
          break;
        int rbuf_full = filler(rbuf, entry, &sbuf, httpostfs.readdir_cache_curoffset);
        httpostfs.readdir_cache_curpos++;
        httpostfs.readdir_cache_curoffset++;
        if (entry > httpostfs.readdir_cache_buf.p)
          *(entry-1) = '\n';
        *(entrystat-1) = '\t';
        if (rbuf_full)
          break;
      }
    }
  }

  return op_return(err, "httpostfs_readdir");
}

static int httpostfs_getattr(const char* path, struct stat* sbuf) {
  DEBUG(2, "httpostfs_getattr: %s\n", path);
  struct buffer buf;
  buf_init(&buf);

  CURLcode curl_res = post(g_strdup_printf("stat\n%s\n", path), &buf);

  int err = 0;
  if (curl_res) {
    err = -ENOENT;
  }
  else {
    buf_null_terminate(&buf);

    if (!parse_stat(buf.p, sbuf)) err = -ENOENT;
  }

  buf_free(&buf);
  return op_return(err, "httpostfs_getattr");
}

static int httpostfs_open_common(const char* path, mode_t mode,
                              struct fuse_file_info* fi) {
  DEBUG(2, "httpostfs_open_common: %s mode=%u flags=%o\n", path, mode, fi->flags);

  invalidate_cache();

  // TODO: handle append correctly
  CURLcode curl_res = post(g_strdup_printf("open\n%s\n%u\n%d\n", path, mode, fi->flags), NULL);

  int err = curl_res ? -EIO : 0;  

  return op_return(err, "httpostfs_open");
}

static int httpostfs_open(const char* path, struct fuse_file_info* fi) {
  return httpostfs_open_common(path, 0, fi);
}

#if FUSE_VERSION >= 25
static int httpostfs_create(const char* path, mode_t mode,
                        struct fuse_file_info* fi) {
  return httpostfs_open_common(path, mode, fi);
}
#endif

static int httpostfs_read(const char* path, char* rbuf, size_t size, off_t offset,
                      struct fuse_file_info* fi) {
  (void) fi;
  DEBUG(1, "httpostfs_read: %s size=%zu offset=%ld\n", path, size, offset);

  struct buffer buf;
  buf_init(&buf);

  CURLcode curl_res = post(g_strdup_printf("read\n%s\n%zu\n%ld\n", path, size, offset), &buf);

  int ret = 0;
  if (curl_res) {
    ret = -EIO;
  }
  else {
    ret = size < buf.len ? size : buf.len;
    memcpy(rbuf, buf.p, ret);
  }
  buf_free(&buf);

  if (ret < 0) op_return(ret, "httpostfs_read");
  return ret;
}

static int httpostfs_mknod(const char* path, mode_t mode, dev_t rdev) {
  DEBUG(1, "httpostfs_mknode: mode=%u\n", mode);

  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("mknod\n%s\n%u\n%llu\n", path, mode, (unsigned long long)rdev), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_mknod");
}

static int httpostfs_chmod(const char* path, mode_t mode) {
  DEBUG(1, "httpostfs_chmod: %u\n", mode);

  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("chmod\n%s\n%u\n", path, mode), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_chmod");
}

static int httpostfs_chown(const char* path, uid_t uid, gid_t gid) {
  DEBUG(1, "httpostfs_chown: %u %u\n", uid, gid);

  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("chown\n%s\n%u\n%u\n", path, uid, gid), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_chown");
}

static int httpostfs_truncate(const char* path, off_t offset) {
  DEBUG(1, "httpostfs_truncate: %s len=%ld\n", path, offset);

  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("truncate\n%s\n%ld\n", path, offset), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_truncate");
}

static int httpostfs_utime(const char* path, struct utimbuf* time) {
  invalidate_cache();

  char *postdata = time ? g_strdup_printf("utime\n%s\n%ld\n%ld\n", path, time->actime, time->modtime) : g_strdup_printf("utimenow\n%s\n", path);
  CURLcode curl_res = post(postdata, NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_utime");
}

static int httpostfs_rmdir(const char* path) {
  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("rmdir\n%s\n", path), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_rmdir");
}

static int httpostfs_mkdir(const char* path, mode_t mode) {
  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("mkdir\n%s\n%u\n", path, mode), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_mkdir");
}

static int httpostfs_unlink(const char* path) {
  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("unlink\n%s\n", path), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_unlink");
}

static int httpostfs_write(const char *path, const char *wbuf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
  (void) fi;
  invalidate_cache();

  gchar* wbufb64 = g_base64_encode((guchar*)wbuf, size);
  
  CURLcode curl_res = post(g_strdup_printf("write\n%s\n%ld\n%zu\n%s\n", path, offset, size, wbufb64), NULL);

  g_free(wbufb64);

  int err = curl_res ? -EIO : 0;
  return op_return(err, "httpostfs_write");
}

static int httpostfs_release(const char* path, struct fuse_file_info* fi) {
  (void) fi;
  invalidate_cache();

  DEBUG(1, "httpostfs_release %s\n", path);

  return op_return(0, "httpostfs_release"); 
}


static int httpostfs_rename(const char* from, const char* to) {
  DEBUG(1, "httpostfs_rename from %s to %s\n", from, to);

  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("rename\n%s\n%s\n", from, to), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_rename");
}

static int httpostfs_symlink(const char* target, const char* link) {
  DEBUG(1, "httpostfs_symlink from %s to %s\n", link, target);

  // todo: transform_symlink with symlink_prefix

  invalidate_cache();

  CURLcode curl_res = post(g_strdup_printf("symlink\n%s\n%s\n", link, target), NULL);

  int err = curl_res ? -EPERM : 0;
  return op_return(err, "httpostfs_symlink");
}

static int httpostfs_readlink(const char *path, char *linkbuf, size_t size) {
  DEBUG(2, "readlink: %s\n", path);
  struct buffer buf;
  buf_init(&buf);

  CURLcode curl_res = post(g_strdup_printf("readlink\n%s\n", path), &buf);

  int err = curl_res || buf.len > (size+1);

  if (!err) {
    memcpy(linkbuf, buf.p, buf.len);
    linkbuf[buf.len] = 0;
  }

  buf_free(&buf);
  if (err) return op_return(-ENOENT, "httpostfs_readlink");
  return op_return(0, "httpostfs_readlink");
}

#if FUSE_VERSION >= 25
static int httpostfs_statfs(const char *path, struct statvfs *buf)
{
    (void) path;

    buf->f_namemax = 255;
    buf->f_bsize = httpostfs.blksize;
    buf->f_frsize = 512;
    buf->f_blocks = 999999999 * 2;
    buf->f_bfree =  999999999 * 2;
    buf->f_bavail = 999999999 * 2;
    buf->f_files =  999999999;
    buf->f_ffree =  999999999;
    return op_return(0, "httpostfs_statfs");
}
#else
static int httpostfs_statfs(const char *path, struct statfs *buf)
{
    (void) path;

    buf->f_namelen = 255;
    buf->f_bsize = httpostfs.blksize;
    buf->f_blocks = 999999999 * 2;
    buf->f_bfree =  999999999 * 2;
    buf->f_bavail = 999999999 * 2;
    buf->f_files =  999999999;
    buf->f_ffree =  999999999;
    return op_return(0, "httpostfs_statfs");
}
#endif

static struct fuse_operations httpostfs_oper = {
    .readdir    = httpostfs_readdir,
    .getattr    = httpostfs_getattr,
    .readlink   = httpostfs_readlink,
    .mknod      = httpostfs_mknod,
    .mkdir      = httpostfs_mkdir,
    .symlink    = httpostfs_symlink,
    .unlink     = httpostfs_unlink,
    .rmdir      = httpostfs_rmdir,
    .rename     = httpostfs_rename,
    .chmod      = httpostfs_chmod,
    .chown      = httpostfs_chown,
    .truncate   = httpostfs_truncate,
    .utime      = httpostfs_utime,
    .open       = httpostfs_open,
    .release    = httpostfs_release,
    .read       = httpostfs_read,
    .write      = httpostfs_write,
    .statfs     = httpostfs_statfs,
#if FUSE_VERSION >= 25
    .create     = httpostfs_create,
#endif
};

static int httpostfs_fuse_main(struct fuse_args *args)
{
#if FUSE_VERSION >= 26
    return fuse_main(args->argc, args->argv, &httpostfs_oper, NULL);
#else
    return fuse_main(args->argc, args->argv, &httpostfs_oper);
#endif
}

static int httpostfs_opt_proc(void* data, const char* arg, int key,
                          struct fuse_args* outargs) {
  (void) data;
  (void) outargs;

  switch (key) {
    case FUSE_OPT_KEY_OPT:
      return 1;
    case FUSE_OPT_KEY_NONOPT:
      if (!httpostfs.host) {
        if (strncmp(arg, "http://", 6) && strncmp(arg, "https://", 7))
          httpostfs.host = g_strdup_printf("http://%s", arg);
        else
          httpostfs.host = strdup(arg);
        return 0;
      } else if (!httpostfs.mountpoint)
        httpostfs.mountpoint = strdup(arg);
      return 1;
    case KEY_HELP:
      usage(outargs->argv[0]);
      fuse_opt_add_arg(outargs, "-ho");
      httpostfs_fuse_main(outargs);
      exit(1);
    case KEY_VERBOSE:
      httpostfs.verbose = 1;
      return 0;
    case KEY_VERSION:
      fprintf(stderr, "httpostfs %s libcurl/%s fuse/%u.%u\n",
              VERSION,
              httpostfs.curl_version->version,
              FUSE_MAJOR_VERSION,
              FUSE_MINOR_VERSION);
      exit(1);
    default:
      exit(1);
  }
}

static void usage(const char* progname) {
  fprintf(stderr,
"usage: %s <httphost> <mountpoint>\n"
"\n"
"HttpostFS options:\n"
"    -o opt,[opt...]        http options\n"
"    -v   --verbose         make libcurl print verbose debug\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"HTTP options:\n"
"    httpostfs_debug     print some debugging information\n"
"    transform_symlinks  prepend mountpoint to absolute symlink targets\n"
"    tcp_nodelay         use the TCP_NODELAY option\n"
"    connect_timeout=N   maximum time allowed for connection in seconds\n"
"    interface=STR       specify network interface/address to use\n"
"    proxy=STR           use host:port HTTP proxy\n"
"    proxytunnel         operate through a HTTP proxy tunnel (using CONNECT)\n"
"    proxy_anyauth       pick \"any\" proxy authentication method\n"
"    proxy_basic         use Basic authentication on the proxy\n"
"    proxy_digest        use Digest authentication on the proxy\n"
"    proxy_ntlm          use NTLM authentication on the proxy\n"
"    httpproxy           use a HTTP proxy (default)\n"
"    socks4              use a SOCKS4 proxy\n"
"    socks5              use a SOCKS5 proxy\n"
"    user=STR            set server user and password\n"
"    proxy_user=STR      set proxy user and password\n"
"    ipv4                resolve name to IPv4 address\n"
"    ipv6                resolve name to IPv6 address\n"
"    codepage=STR        set the codepage the server uses\n"
"    iocharset=STR       set the charset used by the client\n"
"\n", progname);
}

static void set_common_curl_stuff(CURL* easy) {
  curl_easy_setopt_or_die(easy, CURLOPT_WRITEFUNCTION, read_data);
  curl_easy_setopt_or_die(easy, CURLOPT_ERRORBUFFER, error_buf);
  curl_easy_setopt_or_die(easy, CURLOPT_URL, httpostfs.host);
  curl_easy_setopt_or_die(easy, CURLOPT_POST, 1);
  curl_easy_setopt_or_die(easy, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
  curl_easy_setopt_or_die(easy, CURLOPT_NOSIGNAL, 1);

  if (httpostfs.verbose) {
    curl_easy_setopt_or_die(easy, CURLOPT_VERBOSE, TRUE);
  }

  if (httpostfs.tcp_nodelay) {
    /* CURLOPT_TCP_NODELAY is not defined in older versions */
    curl_easy_setopt_or_die(easy, CURLOPT_TCP_NODELAY, 1);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_CONNECTTIMEOUT, httpostfs.connect_timeout);

  curl_easy_setopt_or_die(easy, CURLOPT_INTERFACE, httpostfs.interface);
  
  if (httpostfs.proxy) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXY, httpostfs.proxy);
  }

  /* The default proxy type is HTTP */
  if (!httpostfs.proxytype) {
    httpostfs.proxytype = CURLPROXY_HTTP;
  }
  curl_easy_setopt_or_die(easy, CURLOPT_PROXYTYPE, httpostfs.proxytype);
  
  /* Connection to HTTP servers only make sense with a HTTP tunnel proxy */
  if (httpostfs.proxytype == CURLPROXY_HTTP || httpostfs.proxytunnel) {
    curl_easy_setopt_or_die(easy, CURLOPT_HTTPPROXYTUNNEL, TRUE);
  }

  if (httpostfs.proxyanyauth) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  } else if (httpostfs.proxyntlm) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
  } else if (httpostfs.proxydigest) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
  } else if (httpostfs.proxybasic) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
  }

  //  curl_easy_setopt_or_die(easy, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
  curl_easy_setopt_or_die(easy, CURLOPT_USERPWD, httpostfs.user);
  curl_easy_setopt_or_die(easy, CURLOPT_PROXYUSERPWD, httpostfs.proxy_user);
  curl_easy_setopt_or_die(easy, CURLOPT_IPRESOLVE, httpostfs.ip_version);
}

static void checkpasswd(const char *kind, /* for what purpose */
                        char **userpwd) /* pointer to allocated string */
{
  char *ptr;
  if(!*userpwd)
    return;

  ptr = strchr(*userpwd, ':');
  if(!ptr) {
    /* no password present, prompt for one */
    char *passwd;
    char prompt[256];
    size_t passwdlen;
    size_t userlen = strlen(*userpwd);
    char *passptr;

    /* build a nice-looking prompt */
    snprintf(prompt, sizeof(prompt),
        "Enter %s password for user '%s':",
        kind, *userpwd);

    /* get password */
    passwd = getpass(prompt);
    passwdlen = strlen(passwd);

    /* extend the allocated memory area to fit the password too */
    passptr = realloc(*userpwd,
        passwdlen + 1 + /* an extra for the colon */
        userlen + 1);   /* an extra for the zero */

    if(passptr) {
      /* append the password separated with a colon */
      passptr[userlen]=':';
      memcpy(&passptr[userlen+1], passwd, passwdlen+1);
      *userpwd = passptr;
    }
  }
}

#if FUSE_VERSION == 25
static int fuse_opt_insert_arg(struct fuse_args *args, int pos,
                               const char *arg)
{
    assert(pos <= args->argc);
    if (fuse_opt_add_arg(args, arg) == -1)
        return -1;

    if (pos != args->argc - 1) {
        char *newarg = args->argv[args->argc - 1];
        memmove(&args->argv[pos + 1], &args->argv[pos],
                sizeof(char *) * (args->argc - pos - 1));
        args->argv[pos] = newarg;
    }
    return 0;
}
#endif

int main(int argc, char** argv) {
  int res;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  CURLcode curl_res;
  CURL* easy;
  char *tmp;

  // Initialize curl library before we are a multithreaded program
  curl_global_init(CURL_GLOBAL_ALL);
  
  memset(&httpostfs, 0, sizeof(httpostfs));

  // Set some default values
  httpostfs.curl_version = curl_version_info(CURLVERSION_NOW);
  httpostfs.blksize = 4096;
  
  if (fuse_opt_parse(&args, &httpostfs, httpostfs_opts, httpostfs_opt_proc) == -1)
    exit(1);

  if (!httpostfs.host) {
    fprintf(stderr, "missing host\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  }

  if (!httpostfs.iocharset) {
    httpostfs.iocharset = "UTF8";
  }

  if (httpostfs.codepage) {
    convert_charsets(httpostfs.iocharset, httpostfs.codepage, &httpostfs.host);
  }

  easy = curl_easy_init();
  if (easy == NULL) {
    fprintf(stderr, "Error initializing libcurl\n");
    exit(1);
  }

  checkpasswd("host", &httpostfs.user);
  checkpasswd("proxy", &httpostfs.proxy_user);

  if (httpostfs.transform_symlinks && !httpostfs.mountpoint) {
    fprintf(stderr, "cannot transform symlinks: no mountpoint given\n");
    exit(1);
  }
  if (!httpostfs.transform_symlinks)
    httpostfs.symlink_prefix_len = 0;
  else if (realpath(httpostfs.mountpoint, httpostfs.symlink_prefix) != NULL)
    httpostfs.symlink_prefix_len = strlen(httpostfs.symlink_prefix);
  else {
    perror("unable to normalize mount path");
    exit(1);
  }

  set_common_curl_stuff(easy);
  
  struct buffer buf;
  buf_init(&buf);
  curl_easy_setopt_or_die(easy, CURLOPT_POSTFIELDSIZE, 0);
  curl_easy_setopt_or_die(easy, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(easy);
  if (curl_res != 0) {
    fprintf(stderr, "Error connecting to http: %s\n", error_buf);
    exit(1);
  }

  blksize_t blksize = -1;
  if (sscanf(buf.p, "%ld", &blksize) != 1 || blksize <= 0) {
    fprintf(stderr, "Wrong blocksize (%ld), maybe the host is not a right httpostfs server\n", blksize);
    exit(1);
  }
  httpostfs.blksize = blksize;

  httpostfs.connection = easy;
  pthread_mutex_init(&httpostfs.lock, NULL);

  // Set the filesystem name to show the current server
  tmp = g_strdup_printf("-ofsname=httpostfs#%s", httpostfs.host);
  fuse_opt_insert_arg(&args, 1, tmp);
  g_free(tmp);

  res = httpostfs_fuse_main(&args);

  curl_easy_cleanup(easy);
  curl_global_cleanup();
  fuse_opt_free_args(&args);

  return res;
}
