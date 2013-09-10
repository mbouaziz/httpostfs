<?

define('VIAPHPFS_ROOT', '/');

function mk_f($f)
{
  return VIAPHPFS_ROOT . $f;
}

function die_error($msg)
{
  die; // TODO
}
function die_success($echo = '')
{
  die $echo;
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
    chmod($f, $mode) or die_error('Cannot chmod');
    die_success();
  case 'chmod':
    $mode = @$postdata[2];
    chmod($f, $mode) or die_error('Cannot chmod');
    die_success();
  case 'chown':
    $uid = @$postdata[2];
    $gid = @$postdata[3];
    chown($f, $uid) or die_error('Cannot chown');
    chgrp($f, $gid) or die_error('Cannot chgrp');
    die_success();
  case 'truncate':
    $offset = @$postdata[2];
    $h = @fopen($f, 'c') or @fopen($f, 'x') or die_error('Cannot open');
    ftruncate($h, $offset) or die_error('Cannot ftruncate');
    fclose($h);
    die_success();
  case 'stat':
    $stat = @lstat($f);
    if (!$stat)
      die_error('Cannot stat');
    die_success(implode("\n", $stat));
}

die_error('Unknown operation');

?>