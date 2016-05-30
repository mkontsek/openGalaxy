<?php

if(!defined('INCLUDE_CHECK')) die();

$dbHost = 'mysql.dungeon.lan';
$dbName = 'Galaxy';
$dbUser = 'GMS';
$dbPass = 'topsecret';

if(!defined('NO_OPEN_DB')) {
  $dbLink = @new mysqli($dbHost, $dbUser, $dbPass, $dbName);
  if( @$dbLink->connect_error ) myDie('MySQL: '.'Connect Error ('.@$dbLink->connect_errno.') '.@$dbLink->connect_error);
  if (!$dbLink->set_charset('utf8')) {
    myDie('MySQL: Error loading character set utf8: '.@mysqli_error($dbLink));
  } 
}

?>
