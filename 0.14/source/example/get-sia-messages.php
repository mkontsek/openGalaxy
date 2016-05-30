<?php
//
//////////////////////////////////////////////////////////////////////////////////
// get-sia-messages.php - Provides an AJAX transport for pending alarm messages //
//                                                                              //
// get-sia-messages.php?id=<ID>                                                 //
//                                                                              //
// ID = Starting index of the entries in table `SIA-Messages` to retrieve       //
//                                                                              //
// Output: JSON encoded object                                                  //
//////////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////
// myDie() functtion for AJAX transports //
///////////////////////////////////////////
//
function myDie( $tekst, $status = '403 Forbidden' ) {
  echo $tekst; // jqXHR.responseText
  header( "HTTP/1.0 $status" ); // jqXHR.status jqXHR.statusText
  exit();
}
//
///////////////////////////////////////////////////
// Make sure we have the parameters from the URL //
///////////////////////////////////////////////////
//
if( ! isset( $_GET['id'] ) ) {
  myDie( 'PHP: No starting index in post data!', '400 Bad Request' );
}
//
//////////////////////////////////////
// Connect to our database (or die) //
//////////////////////////////////////
//
if( ! defined( 'INCLUDE_CHECK' ) ) define( 'INCLUDE_CHECK', true );
require_once 'dbconnect.php';
//
//////////////////////////////////////////////////////////
// Get all (100max) messages starting from a certain id //
//////////////////////////////////////////////////////////
//
$result = $dbLink->query( "SELECT * FROM `SIA-Messages` WHERE `SIA-Messages`.id >= ${_GET['id']} ORDER BY id LIMIT 100" );
if( $result == FALSE ){
  myDie( 'MySQL: '.@mysqli_error( $dbLink ) );
}
//
// Put all the results in an array
$rows = array();
while( $row = $result->fetch_array() ) {
  $rows[] = $row;
}
//
// free result set
$result->close();
//
// close db connection
$dbLink->close();
//
// output all rows as JSON object
echo json_encode( $rows );
//
?>

