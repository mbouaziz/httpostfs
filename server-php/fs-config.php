<?
/* Directory considered as the root of the mounted file system */
define('HTTPOSTFS_ROOT', realpath(getcwd()));

/* In readonly mode, only stat, readlink, readdir, read, and open are permitted */
define('HTTPOSTFS_READONLY', false);

/* In symlink mode, only readlink and symlink are permitted */
define('HTTPOSTFS_SYMLINKONLY', false);

/* Log every request and response */
define('HTTPOSTFS_LOG', true);

/* Filename where to log */
define('HTTPOSTFS_LOGFILE', 'log.log');

?>