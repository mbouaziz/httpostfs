<?

define('VIAPHPFS_ROOT', getcwd()); // without last slash

function die_error($msg)
{
  die; // TODO
}
function die_success($echo = '')
{
  die $echo;
}
function die_with($b, $msg)
{
  if ($b) die_error($msg);
  else die_success();
}
function mk_f($f)
{
  if (!$f) die_error('Empty file name');
  return VIAPHPFS_ROOT . $f;
}


$postdata = file('php://input');

isset($postdata[0]) or die;
isset($postdata[1]) or die_error('No file specified');

$f = mk_f($postdata[1]);

switch ($postdata[0])
{
  case 'mknod':
    $mode = @$postdata[2];
    $h = @fopen($f, 'w') or die_error('Cannot open');
    fclose($h);
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

  case 'stat':
    $stat = @lstat($f) or die_error('Cannot stat');
    die_success(implode("\n", $stat)."\n");
  case 'readlink':
    $c = readlink($f) or die_error('Cannot readlink');
    die_success($c);
}

die_error('Unknown operation');

?>