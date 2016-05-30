<?php
/////////////////////////////////////////////////////////////////////
// settings.php - Changes settings for the webinterface            //
//                                                                 //
// settings.php?theme=<THEME>                                      //
//                                                                 //
// THEME = Name of the JQueryUI theme to use.                      //
//                                                                 //
// Output: None                                                    //
/////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////
// myDie() functtion for AJAX transports //
///////////////////////////////////////////
//
function myDie($tekst,$status = '403 Forbidden') {
  echo $tekst; // jqXHR.responseText
  header("HTTP/1.0 $status"); // jqXHR.status jqXHR.statusText
  exit();
}
//
//////////////////////////////////////
// Connect to our database (or die) //
//////////////////////////////////////
//
if(!defined('INCLUDE_CHECK')) define('INCLUDE_CHECK', true);
require 'dbconnect.php';
//
///////////////////////////////////////////////////
// Make sure we have the parameters from the URL //
///////////////////////////////////////////////////
//
if (!isset($_GET['theme'])) {
  // No `theme` in post data!
  myDie( 'Missing parameter','400 Bad Request' );
}
//
//////////////////////
// Update the theme //
//////////////////////
//
$result = $dbLink->query("UPDATE `GMS Settings` SET `jqui_theme` = '${_GET['theme']}'");
if( $result == FALSE ){
  myDie( 'MySQL: '.@mysqli_error($dbLink) );
}
?>

