<?

define('VIAPHPFS_ROOT', getcwd()); // without last slash
define('VIAPHPFS_READONLY', false);
define('O_ACCMODE', 3);
define('O_RDONLY', 0);
define('O_WRONLY', 1);
define('O_RDWR', 2);
define('O_CREAT', 0100);
define('O_EXCL', 0200);
define('O_TRUNC', 01000);
define('O_APPEND', 02000);

function die_error($msg) {
  die; // TODO
}
function die_success($echo = '') {
  die $echo;
}
function die_with($b, $msg) {
  if ($b) die_error($msg);
  else die_success();
}

ini_set('open_basedir', VIAPHPFS_ROOT);

if (@chroot(VIAPHPFS_ROOT)) {
  define('VIAPHPFS_PREFIX', '');
}
else {
  $trailing_slash = substring(VIAPHPFS_ROOT, -1, 1) == '/' ? '' : '/';
  define('VIAPHPFS_PREFIX', VIAPHPFS_ROOT.$trailing_slash);
}

function mk_f($f) {
  if (!$f) die_error('Empty file name');
  if ($f[0] != '/') die_error('Invalid file name');
  return VIAPHPFS_PREFIX . $f;
}


$postdata = file('php://input');

isset($postdata[0]) or die_success();
isset($postdata[1]) or die_error('No file specified');

$action = $postdata[0];
$f = mk_f($postdata[1]);

switch ($action)
{
  case 'stat':
    $stat = @lstat($f) or die_error('Cannot stat');
    die_success(implode("\n", $stat)."\n");
  case 'readlink':
    $c = readlink($f) or die_error('Cannot readlink');
    die_success($c);
  case 'readdir':
    $a = @scandir($f) or die_error('Cannot scandir');
    die_success(implode("\n", $a));
  case 'read':
    $size = @$postdata[2];
    $offset = @$postdata[3];
    $c = file_get_contents($f, false, NULL, $offset, $size);
    if ($c === FALSE) die_error('Cannot file_get_contents');
    die_success($c);
  case 'open':
    $mode = @$postdata[2];
    $flags = @$postdata[3];
    if (VIAPHPFS_READONLY &&
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

VIAPHPFS_READONLY and die_error('Readonly mode in effect. Cannot '.$action);

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
    $link = mk_f(@$postdata[2]);
    die_with(symlink($f, $link), 'Cannot symlink');
  case 'write':
    $offset = @$postdata[2];
    $size = @$postdata[3];
    $wbufb64 = @$postdata[4];
    $h = fopen($f, 'cb') or die_error('Cannot fopen');
    fseek($f, $offset) and die_error('Cannot fseek');
    $wbuf = base64_decode($wbufb64, true);
    if ($wbuf === FALSE) die_error('Cannot base64_decode');
    fwrite($h, $wbuf, $size) or die_error('Cannot fwrite');
    die_with(fclose($h), 'Cannot fclose');
}

die_error('Unknown operation');

?>