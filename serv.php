<?

define('VIAPHPFS_ROOT', '/');

function mk_f($f)
{
  return VIAPHPFS_ROOT . $f;
}

$postdata = file('php://input');

if (!isset($postdata[0]))
  die;

switch ($postdata[0])
{
  case 'stat':
    if (!isset($postdata[1]))
      die;
    $f = mk_f($postdata[1]);
    $stat = @lstat($f);
    if (!$stat)
      die;
    die implode("\n", $stat);
    break;
  default:
    die;
}

?>