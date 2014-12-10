<?
/*  Httpost file system - PHP5 server
    Copyright (C) 2013 Mehdi Bouaziz <mehdi@bouaziz.org>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

define('O_ACCMODE', 3);
define('O_RDONLY', 0);
define('O_WRONLY', 1);
define('O_RDWR', 2);
define('O_CREAT', 0100);
define('O_EXCL', 0200);
define('O_TRUNC', 01000);
define('O_APPEND', 02000);

if (HTTPOSTFS_LOG) {
  $httpostfs_logh = fopen(HTTPOSTFS_LOGFILE, 'a') or die;
}
else {
  $httpostfs_logh = FALSE;
}

function httpostfs_log($msg) {
  global $httpostfs_logh;
  if (HTTPOSTFS_LOG)
    fwrite($httpostfs_logh, $msg);
}

function die_error($msg) {
  httpostfs_log('Error: ' . $msg . "\n");
  die; // TODO
}
function die_success($echo = '') {
  httpostfs_log('Success: ' . $echo . "\n");
  die($echo);
}
function die_with($b, $msg) {
  if ($b === FALSE) die_error($msg);
  else die_success();
}
function die_blksize() {
  $s = @stat('.');
  die_success($s['blksize'] . "\n");
}

ini_set('open_basedir', HTTPOSTFS_ROOT);

if (@chroot(HTTPOSTFS_ROOT)) {
  define('HTTPOSTFS_PREFIX', '/');
}
else {
  $trailing_slash = substr(HTTPOSTFS_ROOT, -1, 1) == '/' ? '' : '/';
  define('HTTPOSTFS_PREFIX', HTTPOSTFS_ROOT.$trailing_slash);
}

function mk_f($f, $optional_heading_slash = false) {
  if (!$f) die_error('Empty file name');
  $hs = ($f[0] == '/');
  if (!$hs && !$optional_heading_slash) die_error('Invalid file name');
  return HTTPOSTFS_PREFIX . substr($f, $hs ? 1 : 0);
}

function format_stat($stat) {
  return "{$stat['ino']}\t{$stat['mode']}\t{$stat['nlink']}\t{$stat['uid']}\t{$stat['gid']}\t{$stat['rdev']}\t{$stat['size']}\t{$stat['blocks']}\t{$stat['atime']}\t{$stat['mtime']}\t{$stat['ctime']}\n";
}

function mk_dir_entry($fi) {
  global $f;
  $stat = @lstat($f . $fi) or die_error('Cannot lstat ' . $f . $fi);
  return $fi . "\t" . format_stat($stat);
}


$postdata = file('php://input', FILE_IGNORE_NEW_LINES);

httpostfs_log('Got: ' . implode("\t", $postdata) . "\n");

isset($postdata[0]) or die_blksize();
isset($postdata[1]) or die_error('No file specified');

$action = $postdata[0];
$f = mk_f($postdata[1]);

HTTPOSTFS_SYMLINKONLY and $action != 'symlink' and $action != 'readlink' and die_error('Symlinkonly mode in effect. Cannot '.$action);

switch ($action)
{
  case 'stat':
    $stat = @lstat($f) or die_error('Cannot lstat ' . $f);
    die_success(format_stat($stat));
  case 'readlink':
    $c = readlink($f) or die_error('Cannot readlink');
    die_success($c);
  case 'readdir':
    $a = @scandir($f) or die_error('Cannot scandir');
    die_success(implode(array_map('mk_dir_entry', $a)));
  case 'read':
    $size = @$postdata[2];
    $offset = @$postdata[3];
    $c = file_get_contents($f, false, NULL, $offset, $size);
    if ($c === FALSE) die_error('Cannot file_get_contents');
    die_success($c);
  case 'open':
    $mode = @$postdata[2];
    $flags = @$postdata[3];
    if (HTTPOSTFS_READONLY &&
         (($flags & O_ACCMODE != O_RDONLY)
       || ($flags & O_APPEND == O_APPEND)
       || ($flags & O_TRUNC == O_TRUNC)
       || ($flags & O_CREAT == O_CREAT)))
       break;
    $dotrunc = $flags & O_TRUNC == O_TRUNC;
    if ($flags & O_CREAT == O_CREAT) {
      if ($flags & O_EXCL == O_EXCL)
        $omode = 'x';
      else if ($flags & O_APPEND == O_APPEND)
        $omode = 'a';
      else if ($dotrunc)
        $omode = 'w';
      else
        $omode = 'c';
      if ($flags & O_ACCMODE != O_WRONLY)
        $omode .= '+';
    }
    else {
      if ($flags & O_ACCMODE == O_RDONLY)
        $omode = 'r';
      else
        $omode = 'r+';
      // append?
    }
    $omode .= 'b';
    $h = fopen($f, $omode) or die_error('Cannot fopen');
    if ($dotrunc)
      ftruncate($h, 0) or die_error('Cannot ftruncate');
    fclose($h) or die_error('Cannot fclose');
    if ($flags & O_CREAT == O_CREAT)
      chmod($f, $mode) or die_error('Cannot chmod'); // TODO: only do it if file created
    die_success();
}

HTTPOSTFS_READONLY and die_error('Readonly mode in effect. Cannot '.$action);

switch ($action)
{
  case 'mknod':
    $mode = @$postdata[2];
    $h = @fopen($f, 'w') or die_error('Cannot open');
    fclose($h) or die_error('Cannot fclose');
    die_with(chmod($f, $mode), 'Cannot chmod');
  case 'chmod':
    $mode = @$postdata[2];
    die_with(chmod($f, $mode), 'Cannot chmod');
  case 'chown':
    $uid = @$postdata[2];
    $gid = @$postdata[3];
    chown($f, $uid) or die_error('Cannot chown');
    die_with(chgrp($f, $gid), 'Cannot chgrp');
  case 'truncate':
    $offset = @$postdata[2];
    $h = @fopen($f, 'c') or @fopen($f, 'x') or die_error('Cannot open');
    ftruncate($h, $offset) or die_error('Cannot ftruncate');
    die_with(fclose($h), 'Cannot fclose');
  case 'utime':
    $actime = @$postdata[2];
    $modtime = @$postdata[3];
    die_with(touch($f, $modtime, $actime), 'Cannot touch');
  case 'utimenow':
    die_with(touch($f), 'Cannot touch');
  case 'rmdir':
    die_with(rmdir($f), 'Cannot rmdir');
  case 'mkdir':
    $mode = @$postdata[2];
    die_with(mkdir($f, $mode), 'Cannot mkdir');
  case 'unlink':
    die_with(@unlink($f), 'Cannot unlink');
  case 'rename':
    $f2 = mk_f(@$postdata[2]);
    die_with(rename($f, $f2), 'Cannot rename');
  case 'symlink':
    $target = @$postdata[2];
    if (function_exists('symlink_hook'))
      die_with(symlink_hook($target, $f), 'Cannot symlink_hook');
    else
      die_with(symlink($target, $f), 'Cannot symlink');
  case 'write':
    $offset = @$postdata[2];
    $size = @$postdata[3];
    $wbufb64 = @$postdata[4];
    $h = fopen($f, 'cb') or die_error('Cannot fopen');
    fseek($f, $offset) and die_error('Cannot fseek');
    $wbuf = base64_decode($wbufb64, true);
    if ($wbuf === FALSE) die_error('Cannot base64_decode');
    fwrite($h, $wbuf, $size) or die_error('Cannot fwrite');
    fflush($h) or die_error('Cannot fflush');
    die_with(fclose($h), 'Cannot fclose');
}

die_error('Unknown operation "' . $action . '"');

?>