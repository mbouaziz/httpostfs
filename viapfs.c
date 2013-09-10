/*
    VIAPHP file system
    Copyright (C) 2006 Robson Braga Araujo <robsonbraga@gmail.com>
    2013 Mehdi Bouaziz <mehdi@bouaziz.me>

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
#include "path_utils.h"
#include "viapfs-ls.h"
#include "cache.h"
#include "viapfs.h"

#define VIAPHPFS_BAD_READ ((size_t)-1)

#define MAX_BUFFER_LEN (300*1024)

struct viapfs viapfs;
static char error_buf[CURL_ERROR_SIZE];

struct buffer {
  uint8_t* p;
  size_t len;
  size_t size;
  off_t begin_offset;
};

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
    buf->p = (uint8_t *) realloc(buf->p, buf->size);
    if (!buf->p) {
        fprintf(stderr, "viapfs: memory allocation failed\n");
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

struct viapfs_file {
  struct buffer buf;
  int dirty;
  int copied;
  off_t last_offset;
  int can_shrink;
  pthread_t thread_id;
  mode_t mode;
  char * open_path;
  char * full_path;
  struct buffer stream_buf;
  CURL *write_conn;
  sem_t data_avail;
  sem_t data_need;
  sem_t data_written;
  sem_t ready;
  int isready;
  int eof;
  int written_flag;
  int write_fail_cause;
  int write_may_start;
  char curl_error_buffer[CURL_ERROR_SIZE];
  off_t pos;
};

enum {
  KEY_HELP,
  KEY_VERBOSE,
  KEY_VERSION,
};

#define VIAPFS_OPT(t, p, v) { t, offsetof(struct viapfs, p), v }

static struct fuse_opt viapfs_opts[] = {
  VIAPFS_OPT("viapfs_debug=%u",     debug, 0),
  VIAPFS_OPT("transform_symlinks", transform_symlinks, 1),
  VIAPFS_OPT("custom_list=%s",     custom_list, 0),
  VIAPFS_OPT("tcp_nodelay",        tcp_nodelay, 1),
  VIAPFS_OPT("connect_timeout=%u", connect_timeout, 0),
  VIAPFS_OPT("interface=%s",       interface, 0),
  VIAPFS_OPT("krb4=%s",            krb4, 0),
  VIAPFS_OPT("proxy=%s",           proxy, 0),
  VIAPFS_OPT("proxytunnel",        proxytunnel, 1),
  VIAPFS_OPT("proxy_anyauth",      proxyanyauth, 1),
  VIAPFS_OPT("proxy_basic",        proxybasic, 1),
  VIAPFS_OPT("proxy_digest",       proxydigest, 1),
  VIAPFS_OPT("proxy_ntlm",         proxyntlm, 1),
  VIAPFS_OPT("httpproxy",          proxytype, CURLPROXY_HTTP),
  VIAPFS_OPT("socks4",             proxytype, CURLPROXY_SOCKS4),
  VIAPFS_OPT("socks5",             proxytype, CURLPROXY_SOCKS5),
  VIAPFS_OPT("user=%s",            user, 0),
  VIAPFS_OPT("proxy_user=%s",      proxy_user, 0),
  VIAPFS_OPT("ipv4",               ip_version, CURL_IPRESOLVE_V4),
  VIAPFS_OPT("ipv6",               ip_version, CURL_IPRESOLVE_V6),
  VIAPFS_OPT("codepage=%s",        codepage, 0),
  VIAPFS_OPT("iocharset=%s",       iocharset, 0),
  VIAPFS_OPT("nomulticonn",        multiconn, 0),

  FUSE_OPT_KEY("-h",             KEY_HELP),
  FUSE_OPT_KEY("--help",         KEY_HELP),
  FUSE_OPT_KEY("-v",             KEY_VERBOSE),
  FUSE_OPT_KEY("--verbose",      KEY_VERBOSE),
  FUSE_OPT_KEY("-V",             KEY_VERSION),
  FUSE_OPT_KEY("--version",      KEY_VERSION),
  FUSE_OPT_END
};

static struct viapfs_file *get_viapfs_file(struct fuse_file_info *fi)
{
  return (struct viapfs_file *) (uintptr_t) fi->fh;
}

static void cancel_previous_multi()
{
  //curl_multi_cleanup(viapfs.multi);
  
  if (!viapfs.attached_to_multi) return;
  
  DEBUG(1, "cancel previous multi\n");
  
  CURLMcode curlMCode = curl_multi_remove_handle(viapfs.multi, viapfs.connection);
  if (curlMCode != CURLE_OK)
  {
      fprintf(stderr, "curl_multi_remove_handle problem: %d\n", curlMCode);
      exit(1);
  }
  viapfs.attached_to_multi = 0;  
}

static int op_return(int err, char * operation)
{
	if(!err)
	{
		DEBUG(2, "%s successful\n", operation);
		return 0;
	}
	fprintf(stderr, "viapfs: operation %s failed because %s\n", operation, strerror(-err));
	return err;
}


static size_t write_data(void *ptr, size_t size, size_t nmemb, void *data) {
  struct viapfs_file* fh = (struct viapfs_file*)data;
  if (fh == NULL) return 0;
  size_t to_copy = size * nmemb;
  if (to_copy > fh->buf.len - fh->copied) {
    to_copy = fh->buf.len - fh->copied;
  }
  DEBUG(2, "write_data: %zu\n", to_copy);
  DEBUG(3, "%*s\n", (int)to_copy, (char*)ptr);
  memcpy(ptr, fh->buf.p + fh->copied, to_copy);
  fh->copied += to_copy;
  return to_copy;
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

static int viapfs_getdir(const char* path, fuse_cache_dirh_t h,
                        fuse_cache_dirfil_t filler) {
  int err = 0;
  CURLcode curl_res;
  char* dir_path = get_fulldir_path(path);

  DEBUG(1, "viapfs_getdir: %s\n", dir_path);
  struct buffer buf;
  buf_init(&buf);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(viapfs.connection);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
    err = -EIO;
  } else {
    buf_null_terminate(&buf);
    parse_dir((char*)buf.p, dir_path + strlen(viapfs.host) - 1,
              NULL, NULL, NULL, 0, h, filler); 
  }

  free(dir_path);
  buf_free(&buf);
  return op_return(err, "viapfs_getdir");
}

static int viapfs_getattr(const char* path, struct stat* sbuf) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path);

  DEBUG(2, "viapfs_getattr: %s dir_path=%s\n", path, dir_path);
  struct buffer buf;
  buf_init(&buf);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(viapfs.connection);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
  }
  buf_null_terminate(&buf);

  char* name = strrchr(path, '/');
  ++name;
  err = parse_dir((char*)buf.p, dir_path + strlen(viapfs.host) - 1,
                  name, sbuf, NULL, 0, NULL, NULL); 

  free(dir_path);
  buf_free(&buf);
  if (err) return op_return(-ENOENT, "viapfs_getattr");
  return 0;
}


static int check_running() {
  int running_handles = 0;
  curl_multi_perform(viapfs.multi, &running_handles);
  return running_handles;
}

static size_t viapfs_read_chunk(const char* full_path, char* rbuf,
                               size_t size, off_t offset,
                               struct fuse_file_info* fi,
                               int update_offset) {
  int running_handles = 0;
  int err = 0;
  struct viapfs_file* fh = get_viapfs_file(fi);

  DEBUG(2, "viapfs_read_chunk: %s %p %zu %lld %p %p\n",
        full_path, rbuf, size, offset, fi, fh);

  pthread_mutex_lock(&viapfs.lock);

  DEBUG(2, "buffer size: %zu %lld\n", fh->buf.len, fh->buf.begin_offset);

  if ((fh->buf.len < size + offset - fh->buf.begin_offset) ||
      offset < fh->buf.begin_offset ||
      offset > fh->buf.begin_offset + fh->buf.len) {
    // We can't answer this from cache
    if (viapfs.current_fh != fh ||
        offset < fh->buf.begin_offset ||
        offset > fh->buf.begin_offset + fh->buf.len ||
        !check_running()) {
      DEBUG(1, "We need to restart the connection %p\n", viapfs.connection);
      DEBUG(2, "current_fh=%p fh=%p\n", viapfs.current_fh, fh);
      DEBUG(2, "buf.begin_offset=%lld offset=%lld\n", fh->buf.begin_offset, offset);

      buf_clear(&fh->buf);
      fh->buf.begin_offset = offset;
      viapfs.current_fh = fh;

      cancel_previous_multi();
      
      curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, full_path);
      curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &fh->buf);
      if (offset) {
        char range[15];
        snprintf(range, 15, "%lld-", (long long) offset);
        curl_easy_setopt_or_die(viapfs.connection, CURLOPT_RANGE, range);
      }
      
      CURLMcode curlMCode =  curl_multi_add_handle(viapfs.multi, viapfs.connection);
      if (curlMCode != CURLE_OK)
      {
          fprintf(stderr, "curl_multi_add_handle problem: %d\n", curlMCode);
          exit(1);
      }
      viapfs.attached_to_multi = 1;
    }

    while(CURLM_CALL_MULTI_PERFORM ==
        curl_multi_perform(viapfs.multi, &running_handles));

    curl_easy_setopt_or_die(viapfs.connection, CURLOPT_RANGE, NULL);

    while ((fh->buf.len < size + offset - fh->buf.begin_offset) &&
        running_handles) {
      struct timeval timeout;
      int rc; /* select() return code */

      fd_set fdread;
      fd_set fdwrite;
      fd_set fdexcep;
      int maxfd;

      FD_ZERO(&fdread);
      FD_ZERO(&fdwrite);
      FD_ZERO(&fdexcep);

      /* set a suitable timeout to play around with */
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      /* get file descriptors from the transfers */
      curl_multi_fdset(viapfs.multi, &fdread, &fdwrite, &fdexcep, &maxfd);

      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
      if (rc == -1) {
          err = 1;
          break;
      }
      while(CURLM_CALL_MULTI_PERFORM ==
            curl_multi_perform(viapfs.multi, &running_handles));
    }

    if (running_handles == 0) {
      int msgs_left = 1;
      while (msgs_left) {
        CURLMsg* msg = curl_multi_info_read(viapfs.multi, &msgs_left);
        if (msg == NULL ||
            msg->msg != CURLMSG_DONE ||
            msg->data.result != CURLE_OK) {
          DEBUG(1, "error: curl_multi_info %d\n", msg->msg);
          err = 1;
        }
      }
    }
  }

  size_t to_copy = fh->buf.len + fh->buf.begin_offset - offset;
  size = size > to_copy ? to_copy : size;
  if (rbuf) {
    memcpy(rbuf, fh->buf.p + offset - fh->buf.begin_offset, size);
  }

  if (update_offset) {
    fh->last_offset = offset + size;
  }

  // Check if the buffer is growing and we can delete a part of it
  if (fh->can_shrink && fh->buf.len > MAX_BUFFER_LEN) {
    DEBUG(2, "Shrinking buffer from %zu to %zu bytes\n",
          fh->buf.len, to_copy - size);
    memmove(fh->buf.p,
            fh->buf.p + offset - fh->buf.begin_offset + size,
            to_copy - size);
    fh->buf.len = to_copy - size;
    fh->buf.begin_offset = offset + size;
  }

  pthread_mutex_unlock(&viapfs.lock);

  if (err) return VIAPHPFS_BAD_READ;
  return size;
}

static void set_common_curl_stuff(CURL* easy);

static size_t write_data_bg(void *ptr, size_t size, size_t nmemb, void *data) {
  struct viapfs_file *fh = data;
  unsigned to_copy = size * nmemb;

  if (!fh->isready) {
    sem_post(&fh->ready);
    fh->isready = 1;
  }

  if (fh->stream_buf.len == 0 && fh->written_flag) {
    sem_post(&fh->data_written); /* viapfs_write can return */
  }
  
  sem_wait(&fh->data_avail); 
  
  DEBUG(2, "write_data_bg: data_avail eof=%d\n", fh->eof);
  
  if (fh->eof)
    return 0;

  DEBUG(2, "write_data_bg: %d %zd\n", to_copy, fh->stream_buf.len);
  if (to_copy > fh->stream_buf.len)
    to_copy = fh->stream_buf.len;

  memcpy(ptr, fh->stream_buf.p, to_copy);
  if (fh->stream_buf.len > to_copy) {
    size_t newlen = fh->stream_buf.len - to_copy;
    memmove(fh->stream_buf.p, fh->stream_buf.p + to_copy, newlen);
    fh->stream_buf.len = newlen;
    sem_post(&fh->data_avail);
    DEBUG(2, "write_data_bg: data_avail\n");    
    
  } else {
    fh->stream_buf.len = 0;
    fh->written_flag = 1;
    sem_post(&fh->data_need);
    DEBUG(2, "write_data_bg: data_need\n");
  }

  return to_copy;
}

int write_thread_ctr = 0;

static void *viapfs_write_thread(void *data) {
  struct viapfs_file *fh = data;
  char range[15];
  
  DEBUG(2, "enter streaming write thread #%d path=%s pos=%lld\n", ++write_thread_ctr, fh->full_path, fh->pos);
  
  
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_URL, fh->full_path);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_UPLOAD, 1);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_INFILESIZE, -1);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_READFUNCTION, write_data_bg);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_READDATA, fh);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_LOW_SPEED_LIMIT, 1);
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_LOW_SPEED_TIME, 60);
  
  fh->curl_error_buffer[0] = '\0';
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_ERRORBUFFER, fh->curl_error_buffer);

  if (fh->pos > 0) {
    /* resuming a streaming write */
    //snprintf(range, 15, "%lld-", (long long) fh->pos);
    //curl_easy_setopt_or_die(fh->write_conn, CURLOPT_RANGE, range);
	  
	curl_easy_setopt_or_die(fh->write_conn, CURLOPT_APPEND, 1);
	  
	//curl_easy_setopt_or_die(fh->write_conn, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)fh->pos);
  }   
  
  CURLcode curl_res = curl_easy_perform(fh->write_conn);
  
  curl_easy_setopt_or_die(fh->write_conn, CURLOPT_UPLOAD, 0);

  if (!fh->isready)
    sem_post(&fh->ready);

  if (curl_res != CURLE_OK)
  {  
	  DEBUG(1, "write problem: %d(%s) text=%s\n", curl_res, curl_easy_strerror(curl_res), fh->curl_error_buffer);
	  fh->write_fail_cause = curl_res;
	  /* problem - let viapfs_write continue to avoid hang */ 
	  sem_post(&fh->data_need);
  }
  
  DEBUG(2, "leaving streaming write thread #%d curl_res=%d\n", write_thread_ctr--, curl_res);
  
  sem_post(&fh->data_written); /* viapfs_write may return */

  return NULL;
}

/* returns 1 on success, 0 on failure */
static int start_write_thread(struct viapfs_file *fh)
{
	if (fh->write_conn != NULL)
	{
		fprintf(stderr, "assert fh->write_conn == NULL failed!\n");
		exit(1);
	}
	
	fh->written_flag=0;
	fh->isready=0;
	fh->eof=0;
	sem_init(&fh->data_avail, 0, 0);
	sem_init(&fh->data_need, 0, 0);
	sem_init(&fh->data_written, 0, 0);
	sem_init(&fh->ready, 0, 0);	
	
    fh->write_conn = curl_easy_init();
    if (fh->write_conn == NULL) {
      fprintf(stderr, "Error initializing libcurl\n");
      return 0;
    } else {
      int err;
      set_common_curl_stuff(fh->write_conn);
      err = pthread_create(&fh->thread_id, NULL, viapfs_write_thread, fh);
      if (err) {
        fprintf(stderr, "failed to create thread: %s\n", strerror(err));
        /* FIXME: destroy curl_easy */
        return 0;	
      }
    }
	return 1;
}

static int finish_write_thread(struct viapfs_file *fh)
{
    if (fh->write_fail_cause == CURLE_OK)
    {
      sem_wait(&fh->data_need);  /* only wait when there has been no error */
    }
    sem_post(&fh->data_avail);
    fh->eof = 1;
    
    pthread_join(fh->thread_id, NULL);
    DEBUG(2, "finish_write_thread after pthread_join. write_fail_cause=%d\n", fh->write_fail_cause);

    curl_easy_cleanup(fh->write_conn);    
    fh->write_conn = NULL;
    
    sem_destroy(&fh->data_avail);
    sem_destroy(&fh->data_need);
    sem_destroy(&fh->data_written);
    sem_destroy(&fh->ready);    
    
    if (fh->write_fail_cause != CURLE_OK)
    {
      return -EIO;
    }	
    return 0;
}


static void free_viapfs_file(struct viapfs_file *fh) {
  if (fh->write_conn)
    curl_easy_cleanup(fh->write_conn);
  g_free(fh->full_path);
  g_free(fh->open_path);
  sem_destroy(&fh->data_avail);
  sem_destroy(&fh->data_need);
  sem_destroy(&fh->data_written);
  sem_destroy(&fh->ready);
  free(fh);
}

static int buffer_file(struct viapfs_file *fh) {
  // If we want to write to the file, we have to load it all at once,
  // modify it in memory and then upload it as a whole as most FTP servers
  // don't support resume for uploads.
  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, fh->full_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &fh->buf);
  CURLcode curl_res = curl_easy_perform(viapfs.connection);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    return -EACCES;
  }

  return 0;
}

static int create_empty_file(const char * path)
{
  int err = 0;

  char *full_path = get_full_path(path);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_INFILESIZE, 0);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_UPLOAD, 1);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_READDATA, NULL);
  CURLcode curl_res = curl_easy_perform(viapfs.connection);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_UPLOAD, 0);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }	
  free(full_path);
  return err;
}

static int viapfs_mknod(const char* path, mode_t mode, dev_t rdev);
static int viapfs_chmod(const char* path, mode_t mode);

static char * flags_to_string(int flags)
{
	char * access_mode_str = NULL;
	if ((flags & O_ACCMODE) == O_WRONLY)
		access_mode_str = "O_WRONLY";
	else if ((flags & O_ACCMODE) == O_RDWR) 
		access_mode_str = "O_RDWR";
	else if ((flags & O_ACCMODE) == O_RDONLY)
		access_mode_str = "O_RDONLY";
	
	return g_strdup_printf("access_mode=%s, flags=%s%s%s%s",
			access_mode_str,
			(flags & O_CREAT) ? "O_CREAT " : "",
			(flags & O_TRUNC) ? "O_TRUNC " : "",
			(flags & O_EXCL) ? "O_EXCL " : "",
			(flags & O_APPEND) ? "O_APPEND " : "");
	
}

static int test_exists(const char* path)
{
	struct stat sbuf;
	return viapfs_getattr(path, &sbuf);
}

static __off_t test_size(const char* path)
{
	struct stat sbuf;
	int err = viapfs_getattr(path, &sbuf);
	if (err)
		return err;
	return sbuf.st_size;
}

static int viapfs_open_common(const char* path, mode_t mode,
                             struct fuse_file_info* fi) {
	
  char * flagsAsStr = flags_to_string(fi->flags);
  DEBUG(2, "viapfs_open_common: %s\n", flagsAsStr);
  int err = 0;

  struct viapfs_file* fh =
    (struct viapfs_file*) malloc(sizeof(struct viapfs_file));

  memset(fh, 0, sizeof(*fh));
  buf_init(&fh->buf);
  fh->mode = mode;
  fh->dirty = 0;
  fh->copied = 0;
  fh->last_offset = 0;
  fh->can_shrink = 0;
  buf_init(&fh->stream_buf);
  /* sem_init(&fh->data_avail, 0, 0);
  sem_init(&fh->data_need, 0, 0);
  sem_init(&fh->data_written, 0, 0);
  sem_init(&fh->ready, 0, 0); */
  fh->open_path = strdup(path);
  fh->full_path = get_full_path(path);
  fh->written_flag = 0;
  fh->write_fail_cause = CURLE_OK;
  fh->curl_error_buffer[0] = '\0';
  fh->write_may_start = 0;
  fi->fh = (unsigned long) fh;

  if ((fi->flags & O_ACCMODE) == O_RDONLY) {
    if (fi->flags & O_CREAT) {
      err = viapfs_mknod(path, (mode & 07777) | S_IFREG, 0);
    } else {
      // If it's read-only, we can load the file a bit at a time, as necessary.
      DEBUG(1, "opening %s O_RDONLY\n", path);
      fh->can_shrink = 1;
      size_t size = viapfs_read_chunk(fh->full_path, NULL, 1, 0, fi, 0);

      if (size == VIAPHPFS_BAD_READ) {
        DEBUG(1, "initial read failed size=%d\n", size);
        err = -EACCES;
      }
    }
  }

  else if ((fi->flags & O_ACCMODE) == O_RDWR || (fi->flags & O_ACCMODE) == O_WRONLY)
  {
#ifndef VIAPHPFS_O_RW_WORKAROUND
	  if ((fi->flags & O_ACCMODE) == O_RDWR)
	  {
		  err = -ENOTSUP;
		  goto fin;
	  }
#endif
	  
	  
	  if ((fi->flags & O_APPEND))
	  {
		DEBUG(1, "opening %s with O_APPEND - not supported!\n", path);
		err = -ENOTSUP;
	  }
	  
	  if ((fi->flags & O_EXCL))
	  {
		DEBUG(1, "opening %s with O_EXCL - testing existence\n", path);
		int exists_r = test_exists(path);
		if (exists_r != -ENOENT)
			err = -EACCES;
	  }
	  
	  if (!err)
	  {
		  if ((fi->flags & O_CREAT) || (fi->flags & O_TRUNC))
	      {
	        DEBUG(1, "opening %s for writing with O_CREAT or O_TRUNC. write thread will start now\n", path);
	    	  
	    	  
	    	fh->write_may_start=1;
	    	  
	        if (start_write_thread(fh))
	        {
	          sem_wait(&fh->ready);
	          /* chmod makes only sense on O_CREAT */ 
	          if (fi->flags & O_CREAT) viapfs_chmod(path, mode);  
	          sem_post(&fh->data_need);
	        }
	        else
	        {
	          err = -EIO;
	        }
	      }
	      else
	      {
	    	/* in this case we have to start writing later */
	        DEBUG(1, "opening %s for writing without O_CREAT or O_TRUNC. write thread will start after ftruncate\n", path);
	        /* expecting ftruncate */
	        fh->write_may_start=0;
	      }
	  }
      
  } else {
      err = -EIO;
  }

  fin:
  if (err)
    free_viapfs_file(fh);

  g_free(flagsAsStr);
  return op_return(err, "viapfs_open");
}

static int viapfs_open(const char* path, struct fuse_file_info* fi) {
  return viapfs_open_common(path, 0, fi);
}

#if FUSE_VERSION >= 25
static int viapfs_create(const char* path, mode_t mode,
                        struct fuse_file_info* fi) {
  return viapfs_open_common(path, mode, fi);
}
#endif

static int viapfs_read(const char* path, char* rbuf, size_t size, off_t offset,
                      struct fuse_file_info* fi) {
  int ret;
  struct viapfs_file *fh = get_viapfs_file(fi);
  
  DEBUG(1, "viapfs_read: %s size=%zu offset=%lld has_write_conn=%d pos=%lld\n", path, size, (long long) offset, fh->write_conn!=0, fh->pos);
  
  if (fh->pos>0 || fh->write_conn!=NULL)
  {
	  fprintf(stderr, "in read/write mode we cannot read from a file that has already been written to\n");
	  return op_return(-EIO, "viapfs_read");
  }
  
  char *full_path = get_full_path(path);
  size_t size_read = viapfs_read_chunk(full_path, rbuf, size, offset, fi, 1);
  free(full_path);
  if (size_read == VIAPHPFS_BAD_READ) {
    ret = -EIO;
  } else {
    ret = size_read;
  }
  
  if (ret<0) op_return(ret, "viapfs_read");
  return ret;
}

static int viapfs_mknod(const char* path, mode_t mode, dev_t rdev) {
  (void) rdev;

  int err = 0;

  DEBUG(1, "viapfs_mknode: mode=%d\n", (int)mode);
  
  if ((mode & S_IFMT) != S_IFREG)
    return -EPERM;

  err = create_empty_file(path);
 
  if (!err)
      viapfs_chmod(path, mode);

  return op_return(err, "viapfs_mknod");
}

static int viapfs_chmod(const char* path, mode_t mode) {
  int err = 0;

  // We can only process a subset of the mode - so strip
  // to supported subset
  int mode_c = mode - (mode / 0x1000 * 0x1000);
  
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("SITE CHMOD %.3o %s", mode_c, filename);
  struct buffer buf;
  buf_init(&buf);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(viapfs.connection);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, NULL);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd); 
  return op_return(err, "viapfs_chmod");
}

static int viapfs_chown(const char* path, uid_t uid, gid_t gid) {
  int err = 0;
  
  DEBUG(1, "viapfs_chown: %d %d\n", (int)uid, (int)gid);
  
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("SITE CHUID %i %s", uid, filename);
  char* cmd2 = g_strdup_printf("SITE CHGID %i %s", gid, filename);
  struct buffer buf;
  buf_init(&buf);

  header = curl_slist_append(header, cmd);
  header = curl_slist_append(header, cmd2);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(viapfs.connection);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, NULL);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd); 
  free(cmd2); 
  return op_return(err, "viapfs_chown");
}

static int viapfs_truncate(const char* path, off_t offset) {
  DEBUG(1, "viapfs_truncate: %s len=%lld\n", path, offset);
  /* we can't use viapfs_mknod here, because we don't know the right permissions */
  if (offset == 0) return op_return(create_empty_file(path), "viapfs_truncate");

  /* fix openoffice problem, truncating exactly to file length */
  
  __off_t size = (long long int)test_size(path); 
  DEBUG(1, "viapfs_truncate: %s check filesize=%lld\n", path, (long long int)size);
  
  if (offset == size)  
	  return op_return(0, "viapfs_ftruncate");
  
  DEBUG(1, "viapfs_truncate problem: %s offset != 0 or filesize=%lld != offset\n", path, (long long int)size);
  
  
  return op_return(-EPERM, "viapfs_truncate");
}

static int viapfs_ftruncate(const char * path , off_t offset, struct fuse_file_info * fi)
{
  DEBUG(1, "viapfs_ftruncate: %s len=%lld\n", path, offset);
  struct viapfs_file *fh = get_viapfs_file(fi);

  if (offset == 0) 
  {
	 if (fh->pos == 0)
	 {
		 fh->write_may_start=1;
		 return op_return(create_empty_file(fh->open_path), "viapfs_ftruncate");
	 }
	 return op_return(-EPERM, "viapfs_ftruncate");
  }
  /* fix openoffice problem, truncating exactly to file length */
  
  __off_t size = test_size(path); 
  DEBUG(1, "viapfs_ftruncate: %s check filesize=%lld\n", path, (long long int)size);
  
  if (offset == size)  
	  return op_return(0, "viapfs_ftruncate");
  
  DEBUG(1, "viapfs_ftruncate problem: %s offset != 0 or filesize(=%lld) != offset(=%lld)\n", path, (long long int)size, (long long int) offset);
  
  return op_return(-EPERM, "viapfs_ftruncate");
}

static int viapfs_utime(const char* path, struct utimbuf* time) {
  (void) path;
  (void) time;
  return op_return(0, "viapfs_utime");
}

static int viapfs_rmdir(const char* path) {
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("RMD %s", filename);
  struct buffer buf;
  buf_init(&buf);

  DEBUG(2, "%s\n", full_path);
  DEBUG(2, "%s\n", cmd);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(viapfs.connection);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, NULL);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);
  return op_return(err, "viapfs_rmdir");
}

static int viapfs_mkdir(const char* path, mode_t mode) {
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("MKD %s", filename);
  struct buffer buf;
  buf_init(&buf);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(viapfs.connection);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, NULL);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);

  if (!err)
    viapfs_chmod(path, mode);

  return op_return(err, "viapfs_mkdir");
}

static int viapfs_unlink(const char* path) {
  int err = 0;
  struct curl_slist* header = NULL;
  char* full_path = get_dir_path(path);
  char* filename = get_file_name(path);
  char* cmd = g_strdup_printf("DELE %s", filename);
  struct buffer buf;
  buf_init(&buf);

  header = curl_slist_append(header, cmd);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, full_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(viapfs.connection);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, NULL);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(full_path);
  free(filename);
  free(cmd);
  return op_return(err, "viapfs_unlink");
}

static int viapfs_write(const char *path, const char *wbuf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
  (void) path;
  struct viapfs_file *fh = get_viapfs_file(fi);

  DEBUG(1, "viapfs_write: %s size=%zu offset=%lld has_write_conn=%d pos=%lld\n", path, size, (long long) offset, fh->write_conn!=0, fh->pos);

  if (fh->write_fail_cause != CURLE_OK)
  {
    DEBUG(1, "previous write failed. cause=%d\n", fh->write_fail_cause);
    return -EIO;
  }    
  
  if (!fh->write_conn && fh->pos == 0 && offset == 0)
  {
    DEBUG(1, "viapfs_write: starting a streaming write at pos=%lld\n", fh->pos);
    
    /* check if the file has been truncated to zero or has been newly created */
    if (!fh->write_may_start)
    {
    	long long size = (long long int)test_size(path); 
    	if (size != 0)
    	{
    		fprintf(stderr, "viapfs_write: start writing with no previous truncate not allowed! size check rval=%lld\n", size);
    		return op_return(-EIO, "viapfs_write");
    	}
    }
    
	int success = start_write_thread(fh);
    if (!success)
    {
      return op_return(-EIO, "viapfs_write");
    }
    sem_wait(&fh->ready);
	sem_post(&fh->data_need);    
  }
  
  if (!fh->write_conn && fh->pos >0 && offset == fh->pos)
  {
    /* resume a streaming write */
    DEBUG(1, "viapfs_write: resuming a streaming write at pos=%lld\n", fh->pos);
	  
    int success = start_write_thread(fh);
    if (!success)
    {
      return op_return(-EIO, "viapfs_write");
    }
    sem_wait(&fh->ready);
    sem_post(&fh->data_need);    
  }
  
  if (fh->write_conn) {
    sem_wait(&fh->data_need);
    
    if (offset != fh->pos) {
      DEBUG(1, "non-sequential write detected -> fail\n");

      sem_post(&fh->data_avail);      
      finish_write_thread(fh);      
      return op_return(-EIO, "viapfs_write");
      
      
    } else {
      if (buf_add_mem(&fh->stream_buf, wbuf, size) == -1) {
        sem_post(&fh->data_need);
        return op_return(-ENOMEM, "viapfs_write");
      }
      fh->pos += size;
      /* wake up write_data_bg */
      sem_post(&fh->data_avail);
      /* wait until libcurl has completely written the current chunk or finished/failed */
      sem_wait(&fh->data_written);  
      fh->written_flag = 0;
      
      if (fh->write_fail_cause != CURLE_OK)
      {
    	/* TODO: on error we should problably unlink the target file  */ 
        DEBUG(1, "writing failed. cause=%d\n", fh->write_fail_cause);
        return op_return(-EIO, "viapfs_write");
      }    
    }
    
  }

  return size;

}

static int viapfs_flush(const char *path, struct fuse_file_info *fi) {
  int err = 0;
  struct viapfs_file* fh = get_viapfs_file(fi);

  DEBUG(1, "viapfs_flush: buf.len=%zu buf.pos=%lld write_conn=%d\n", fh->buf.len, fh->pos, fh->write_conn!=0);
  
  if (fh->write_conn) {
    err = finish_write_thread(fh);
    if (err) return op_return(err, "viapfs_flush");
    
    struct stat sbuf;
    
    /* check if the resulting file has the correct size
     this is important, because we use APPE for continuing
     writing after a premature flush */
    err = viapfs_getattr(path, &sbuf);   
    if (err) return op_return(err, "viapfs_flush");
    
    if (sbuf.st_size != fh->pos)
    {
    	fh->write_fail_cause = -999;
    	fprintf(stderr, "viapfs_flush: check filesize problem: size=%lld expected=%lld\n", sbuf.st_size, fh->pos);
    	return op_return(-EIO, "viapfs_flush");
    }
    
    return 0;
  }
  
 
  if (!fh->dirty) return 0;

  return op_return(-EIO, "viapfs_flush");
  
}

static int viapfs_fsync(const char *path, int isdatasync,
                      struct fuse_file_info *fi) {
	DEBUG(1, "viapfs_fsync %s\n", path);
  (void) isdatasync;
  return viapfs_flush(path, fi);
}

static int viapfs_release(const char* path, struct fuse_file_info* fi) {

  DEBUG(1, "viapfs_release %s\n", path);
  struct viapfs_file* fh = get_viapfs_file(fi);
  viapfs_flush(path, fi);
  pthread_mutex_lock(&viapfs.lock);
  if (viapfs.current_fh == fh) {
    viapfs.current_fh = NULL;
  }
  pthread_mutex_unlock(&viapfs.lock);

  /*
  if (fh->write_conn) {
	  finish_write_thread(fh);
  }
  */
  free_viapfs_file(fh);
  return op_return(0, "viapfs_release"); 
}


static int viapfs_rename(const char* from, const char* to) {
  DEBUG(1, "viapfs_rename from %s to %s\n", from, to);
  int err = 0;
  char* rnfr = g_strdup_printf("RNFR %s", from + 1);
  char* rnto = g_strdup_printf("RNTO %s", to + 1);
  struct buffer buf;
  buf_init(&buf);
  struct curl_slist* header = NULL;

  if (viapfs.codepage) {
    convert_charsets(viapfs.iocharset, viapfs.codepage, &rnfr);
    convert_charsets(viapfs.iocharset, viapfs.codepage, &rnto);
  }

  header = curl_slist_append(header, rnfr);
  header = curl_slist_append(header, rnto);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, header);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, viapfs.host);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  CURLcode curl_res = curl_easy_perform(viapfs.connection);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_POSTQUOTE, NULL);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    err = -EPERM;
  }
  
  buf_free(&buf);
  curl_slist_free_all(header);
  free(rnfr);
  free(rnto);

  return op_return(err, "viapfs_rename");
}

static int viapfs_readlink(const char *path, char *linkbuf, size_t size) {
  int err;
  CURLcode curl_res;
  char* dir_path = get_dir_path(path);

  DEBUG(2, "dir_path: %s %s\n", path, dir_path);
  struct buffer buf;
  buf_init(&buf);

  pthread_mutex_lock(&viapfs.lock);
  cancel_previous_multi();
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_URL, dir_path);
  curl_easy_setopt_or_die(viapfs.connection, CURLOPT_WRITEDATA, &buf);
  curl_res = curl_easy_perform(viapfs.connection);
  pthread_mutex_unlock(&viapfs.lock);

  if (curl_res != 0) {
    DEBUG(1, "%s\n", error_buf);
  }
  buf_null_terminate(&buf);

  char* name = strrchr(path, '/');
  ++name;
  err = parse_dir((char*)buf.p, dir_path + strlen(viapfs.host) - 1,
                  name, NULL, linkbuf, size, NULL, NULL); 

  free(dir_path);
  buf_free(&buf);
  if (err) return op_return(-ENOENT, "viapfs_readlink");
  return op_return(0, "viapfs_readlink");
}

#if FUSE_VERSION >= 25
static int viapfs_statfs(const char *path, struct statvfs *buf)
{
    (void) path;

    buf->f_namemax = 255;
    buf->f_bsize = viapfs.blksize;
    buf->f_frsize = 512;
    buf->f_blocks = 999999999 * 2;
    buf->f_bfree =  999999999 * 2;
    buf->f_bavail = 999999999 * 2;
    buf->f_files =  999999999;
    buf->f_ffree =  999999999;
    return op_return(0, "viapfs_statfs");
}
#else
static int viapfs_statfs(const char *path, struct statfs *buf)
{
    (void) path;

    buf->f_namelen = 255;
    buf->f_bsize = viapfs.blksize;
    buf->f_blocks = 999999999 * 2;
    buf->f_bfree =  999999999 * 2;
    buf->f_bavail = 999999999 * 2;
    buf->f_files =  999999999;
    buf->f_ffree =  999999999;
    return op_return(0, "viapfs_statfs");
}
#endif

static struct fuse_cache_operations viapfs_oper = {
  .oper = {
//    .init       = viapfs_init,
    .getattr    = viapfs_getattr,
    .readlink   = viapfs_readlink,
    .mknod      = viapfs_mknod,
    .mkdir      = viapfs_mkdir,
//    .symlink    = viapfs_symlink,
    .unlink     = viapfs_unlink,
    .rmdir      = viapfs_rmdir,
    .rename     = viapfs_rename,
    .chmod      = viapfs_chmod,
    .chown      = viapfs_chown,
    .truncate   = viapfs_truncate,
    .utime      = viapfs_utime,
    .open       = viapfs_open,
    .flush      = viapfs_flush,
    .fsync      = viapfs_fsync,
    .release    = viapfs_release,
    .read       = viapfs_read,
    .write      = viapfs_write,
    .statfs     = viapfs_statfs,
#if FUSE_VERSION >= 25
    .create     = viapfs_create,
    .ftruncate  = viapfs_ftruncate,
//    .fgetattr   = viapfs_fgetattr,
#endif
  },
  .cache_getdir = viapfs_getdir,
};

static int viaphpfs_fuse_main(struct fuse_args *args)
{
#if FUSE_VERSION >= 26
    return fuse_main(args->argc, args->argv, cache_init(&viapfs_oper), NULL);
#else
    return fuse_main(args->argc, args->argv, cache_init(&viapfs_oper));
#endif
}

static int viapfs_opt_proc(void* data, const char* arg, int key,
                          struct fuse_args* outargs) {
  (void) data;
  (void) outargs;

  switch (key) {
    case FUSE_OPT_KEY_OPT:
      return 1;
    case FUSE_OPT_KEY_NONOPT:
      if (!viapfs.host) {
        const char* prefix = "";
        if (strncmp(arg, "http://", 6) && strncmp(arg, "https://", 7))
          viapfs.host = g_strdup_printf("http://%s", arg);
        else
          viapfs.host = strdup(arg);
        return 0;
      } else if (!viapfs.mountpoint)
        viapfs.mountpoint = strdup(arg);
      return 1;
    case KEY_HELP:
      usage(outargs->argv[0]);
      fuse_opt_add_arg(outargs, "-ho");
      viaphpfs_fuse_main(outargs);
      exit(1);
    case KEY_VERBOSE:
      viapfs.verbose = 1;
      return 0;
    case KEY_VERSION:
      fprintf(stderr, "viaphpfs %s libcurl/%s fuse/%u.%u\n",
              VERSION,
              viapfs.curl_version->version,
              FUSE_MAJOR_VERSION,
              FUSE_MINOR_VERSION);
      exit(1);
    default:
      exit(1);
  }
}

static void usage(const char* progname) {
  fprintf(stderr,
"usage: %s <viaphphost> <mountpoint>\n"
"\n"
"ViaPhpFS options:\n"
"    -o opt,[opt...]        http options\n"
"    -v   --verbose         make libcurl print verbose debug\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"HTTP options:\n"
"    viapfs_debug         print some debugging information\n"
"    transform_symlinks  prepend mountpoint to absolute symlink targets\n"
"    custom_list=STR     Command used to list files. Defaults to \"LIST -a\"\n"
"    tcp_nodelay         use the TCP_NODELAY option\n"
"    connect_timeout=N   maximum time allowed for connection in seconds\n"
"    interface=STR       specify network interface/address to use\n"
"    krb4=STR            enable krb4 with specified security level\n"
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
"\n"
"ViaPhpFS cache options:  \n"
"    cache=yes|no              enable/disable cache (default: yes)\n"
"    cache_timeout=SECS        set timeout for stat, dir, link at once\n"
"                              default is %d seconds\n"
"    cache_stat_timeout=SECS   set stat timeout\n"
"    cache_dir_timeout=SECS    set dir timeout\n"
"    cache_link_timeout=SECS   set link timeout\n"          
"\n", progname, DEFAULT_CACHE_TIMEOUT);
}

static void set_common_curl_stuff(CURL* easy) {
  curl_easy_setopt_or_die(easy, CURLOPT_WRITEFUNCTION, read_data);
  curl_easy_setopt_or_die(easy, CURLOPT_READFUNCTION, write_data);
  curl_easy_setopt_or_die(easy, CURLOPT_ERRORBUFFER, error_buf);
  curl_easy_setopt_or_die(easy, CURLOPT_URL, viapfs.host);
  curl_easy_setopt_or_die(easy, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
  curl_easy_setopt_or_die(easy, CURLOPT_NOSIGNAL, 1);

  if (viapfs.custom_list) {
    curl_easy_setopt_or_die(easy, CURLOPT_CUSTOMREQUEST, viapfs.custom_list);
  }

  if (viapfs.verbose) {
    curl_easy_setopt_or_die(easy, CURLOPT_VERBOSE, TRUE);
  }

  if (viapfs.tcp_nodelay) {
    /* CURLOPT_TCP_NODELAY is not defined in older versions */
    curl_easy_setopt_or_die(easy, CURLOPT_TCP_NODELAY, 1);
  }

  curl_easy_setopt_or_die(easy, CURLOPT_CONNECTTIMEOUT, viapfs.connect_timeout);

  curl_easy_setopt_or_die(easy, CURLOPT_INTERFACE, viapfs.interface);
  curl_easy_setopt_or_die(easy, CURLOPT_KRB4LEVEL, viapfs.krb4);
  
  if (viapfs.proxy) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXY, viapfs.proxy);
  }

  /* The default proxy type is HTTP */
  if (!viapfs.proxytype) {
    viapfs.proxytype = CURLPROXY_HTTP;
  }
  curl_easy_setopt_or_die(easy, CURLOPT_PROXYTYPE, viapfs.proxytype);
  
  /* Connection to HTTP servers only make sense with a HTTP tunnel proxy */
  if (viapfs.proxytype == CURLPROXY_HTTP || viapfs.proxytunnel) {
    curl_easy_setopt_or_die(easy, CURLOPT_HTTPPROXYTUNNEL, TRUE);
  }

  if (viapfs.proxyanyauth) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
  } else if (viapfs.proxyntlm) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
  } else if (viapfs.proxydigest) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
  } else if (viapfs.proxybasic) {
    curl_easy_setopt_or_die(easy, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
  }

  // MB: maybe use CURLOPT_HTTPAUTH
  curl_easy_setopt_or_die(easy, CURLOPT_USERPWD, viapfs.user);
  curl_easy_setopt_or_die(easy, CURLOPT_PROXYUSERPWD, viapfs.proxy_user);
  curl_easy_setopt_or_die(easy, CURLOPT_IPRESOLVE, viapfs.ip_version);
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
  
  memset(&viapfs, 0, sizeof(viapfs));

  // Set some default values
  viapfs.curl_version = curl_version_info(CURLVERSION_NOW);
  viapfs.blksize = 4096;
  viapfs.multiconn = 1;
  viapfs.attached_to_multi = 0;
  
  if (fuse_opt_parse(&args, &viapfs, viapfs_opts, viapfs_opt_proc) == -1)
    exit(1);

  if (!viapfs.host) {
    fprintf(stderr, "missing host\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  }

  if (!viapfs.iocharset) {
    viapfs.iocharset = "UTF8";
  }

  if (viapfs.codepage) {
    convert_charsets(viapfs.iocharset, viapfs.codepage, &viapfs.host);
  }

  easy = curl_easy_init();
  if (easy == NULL) {
    fprintf(stderr, "Error initializing libcurl\n");
    exit(1);
  }

  res = cache_parse_options(&args);
  if (res == -1)
    exit(1);

  checkpasswd("host", &viapfs.user);
  checkpasswd("proxy", &viapfs.proxy_user);

  if (viapfs.transform_symlinks && !viapfs.mountpoint) {
    fprintf(stderr, "cannot transform symlinks: no mountpoint given\n");
    exit(1);
  }
  if (!viapfs.transform_symlinks)
    viapfs.symlink_prefix_len = 0;
  else if (realpath(viapfs.mountpoint, viapfs.symlink_prefix) != NULL)
    viapfs.symlink_prefix_len = strlen(viapfs.symlink_prefix);
  else {
    perror("unable to normalize mount path");
    exit(1);
  }

  set_common_curl_stuff(easy);
  curl_easy_setopt_or_die(easy, CURLOPT_WRITEDATA, NULL);
  curl_res = curl_easy_perform(easy);
  if (curl_res != 0) {
    fprintf(stderr, "Error connecting to http: %s\n", error_buf);
    exit(1);
  }

  viapfs.multi = curl_multi_init();
  if (viapfs.multi == NULL) {
    fprintf(stderr, "Error initializing libcurl multi\n");
    exit(1);
  }

  viapfs.connection = easy;
  pthread_mutex_init(&viapfs.lock, NULL);

  // Set the filesystem name to show the current server
  tmp = g_strdup_printf("-ofsname=viaphpfs#%s", viapfs.host);
  fuse_opt_insert_arg(&args, 1, tmp);
  g_free(tmp);

  res = viaphpfs_fuse_main(&args);

  cancel_previous_multi();
  curl_multi_cleanup(viapfs.multi);
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  fuse_opt_free_args(&args);

  return res;
}
