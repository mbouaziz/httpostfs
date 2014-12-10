
typedef struct fuse_cache_dirhandle *fuse_cache_dirh_t;
typedef int (*fuse_cache_dirfil_t) (fuse_cache_dirh_t h, const char *name,
                                    const struct stat *stbuf);

struct fuse_cache_operations {
    struct fuse_operations oper;
    int (*cache_getdir) (const char *, fuse_cache_dirh_t, fuse_cache_dirfil_t);
};

struct fuse_operations *cache_init(struct fuse_cache_operations *oper);
int cache_parse_options(struct fuse_args *args);
void cache_add_attr(const char *path, const struct stat *stbuf);
void cache_add_dir(const char *path, char **dir);
void cache_add_link(const char *path, const char *link, size_t size);

#endif   /* __VIAPHPFS_CACHE_H__ */
