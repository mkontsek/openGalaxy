/*
  This file is part of openGalaxy.

  opengalaxy - a SIA receiver for Galaxy security control panels.
  Copyright (C) 2015 - 2016 Alexander Bruines <alexander.bruines@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as
  as published by the Free Software Foundation, or (at your option)
  any later version.

  In addition, as a special exception, the author of this program
  gives permission to link the code of its release with the OpenSSL
  project's "OpenSSL" library (or with modified versions of it that
  use the same license as the "OpenSSL" library), and distribute the
  linked executables. You must obey the GNU General Public License
  in all respects for all of the code used other than "OpenSSL".
  If you modify this file, you may extend this exception to your
  version of the file, but you are not obligated to do so.
  If you do not wish to do so, delete this exception statement
  from your version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Global variables

var socket_commander = null; // Websocket
var session_id = 0;          // Our session ID

var Pending_alarms_empty_string = ''; // String used for empty table fields
var Pending_alarms_x_filler = 0;      // width to make the Pending-Alarms-Dialog-??_x_filler classes (dynamicly initialised)

//
// All possible 'typeId' values returned by an openGalaxy-command-protocol websocket
//
var JSON_SIA_MESSAGE             = 0;
var JSON_STANDARD_REPLY          = 1;
var JSON_HELP_REPLY              = 2;
var JSON_AREA_ARMED_STATE        = 3;
var JSON_ALL_AREA_ARMED_STATE    = 4;
var JSON_AREA_ALARM_STATE        = 5;
var JSON_ALL_AREA_ALARM_STATE    = 6;
var JSON_AREA_READY_STATE        = 7;
var JSON_ALL_AREA_READY_STATE    = 8;
var JSON_ZONE_OMIT_STATE         = 9;
var JSON_ZONE_STATE              = 10;
var JSON_ALL_ZONE_READY_STATE    = 11;
var JSON_ALL_ZONE_ALARM_STATE    = 12;
var JSON_ALL_ZONE_OPEN_STATE     = 13;
var JSON_ALL_ZONE_TAMPER_STATE   = 14;
var JSON_ALL_ZONE_R_STATE        = 15;
var JSON_ALL_ZONE_OMIT_STATE     = 16;
var JSON_ALL_OUTPUT_STATE        = 17;
var JSON_POLL_REPLY              = 18;
var JSON_AUTHORIZATION_REQUIRED  = 19;
var JSON_AUTHENTICATION_ACCEPTED = 20;

var sia_inner_table_height; // Used to store the calculated inner table height of SIA-Messages-Table
var sia_outer_table_height; // Used to store the calculated inner table height of SIA-Messages-Table

var SocketStatus_default_position = { my: "right bottom", at: "right bottom", of: $('#Desktop') };

var selectedAreas = new Array();  // Used by the Areas tab to keep track of selected areas (Set by parseSelectedAreas())
var selectedAllAreas = false;     // True when all areas are selected (Set by parseSelectedAreas())

function printObject(o) {
  var out = '';
  for (var p in o) {
    out += p + ': ' + o[p] + '\n';
  }
  alert(out);
}

/////////////////////////////////////////////////////////////
// Converts a 4 digit zone number to a 3 digit zone number //
/////////////////////////////////////////////////////////////
function GalaxyZone4to3( nr )
{
  var line = 1 + (((nr / 1000) - 1) & 3),
      rio = ((nr - (line * 1000)) / 10) & 15,
      zn = 1 + ((nr - (line * 1000) - (rio * 10) - 1) & 7);
  return ((line - 1) << 7) + (rio << 3) + zn;
}

/////////////////////////////////////////////////////////////////
// Converts a 4 digit output number to a 3 digit output number //
/////////////////////////////////////////////////////////////////
function GalaxyOutput4to3( nr )
{
  var line = 1 + (((nr / 1000) - 1) & 3),
      rio = ((nr - (line * 1000)) / 10) & 15,
      op = 1 + ((nr - (line * 1000) - (rio * 10) - 1) & 3);
  return ((line - 1) << 6) + (rio << 2) + op;
}

////////////////////////////////////////////////////////
// This function returns the URL for our websocket(s) //
////////////////////////////////////////////////////////
function get_socket_url() {
  var pcol;
  var u = document.URL;
  if( u.substring( 0, 5 ) == "https" ) {
    pcol = "wss://";
    u = u.substr( 8 );
  }
  else {
    pcol = "ws://";
    if( u.substring( 0, 4 ) == "http" ) u = u.substr( 7 );
  }
  u = u.split( '/' );
  return pcol + u[ 0 ] + "/cli"; // + "/cli" bit is for IE10 workaround
}

/////////////////////////////////////////////////
// This function sends a command to the server //
/////////////////////////////////////////////////
function send( cmd ) {
 var e = "";
 if( cmd.toString() != e.toString() ) {
  SocketStatus_SetCommandStatus( cmd, "ui-state-active", "blue", 2000 );
  socket_commander.send( cmd.toString() );
 }
}

///////////////////////////////////////////////////////////////////
// This function adds a SIA message to the table of SIA messages //
///////////////////////////////////////////////////////////////////
function table_prepend( obj ){
  if( obj ) {
    if( ! obj.EventAddressNumber ) obj.EventAddressNumber = '';
    if( ! obj.SubscriberID       ) obj.SubscriberID = '';
    if( ! obj.AreaID             ) obj.AreaID = '';
    if( ! obj.PeripheralID       ) obj.PeripheralID = '';

    var table  = document.getElementById( "SIA-Messages-Table" );
    var row    = table.insertRow( 0 );
    var cell1  = row.insertCell( 0 );
    var cell2  = row.insertCell( 1 );
    var cell3  = row.insertCell( 2 );
    var cell4  = row.insertCell( 3 );
    var cell5  = row.insertCell( 4 );
    var cell6  = row.insertCell( 5 );
    var cell7  = row.insertCell( 6 );
    var cell8  = row.insertCell( 7 );
    var cell9  = row.insertCell( 8 );
    var cell10 = row.insertCell( 9 );
    var cell11 = row.insertCell( 10 );

    row.className    = '';
    cell1.className  = 'sia-table-td1';
    cell2.className  = 'hide';
    cell3.className  = 'sia-table-td3';
    cell4.className  = 'sia-table-td4';
    cell5.className  = 'sia-table-td5';
    cell6.className  = 'sia-table-td6';
    cell7.className  = 'sia-table-td7';
    cell8.className  = 'sia-table-td8';
    cell9.className  = 'sia-table-td9';
    cell10.className = 'sia-table-td10';
    cell11.className = 'sia-table-td11';

    cell1.innerHTML = obj.Time.toString();
    cell2.innerHTML = obj.AccountID.toString();
    cell3.innerHTML = obj.EventCode.toString();
    cell4.innerHTML = obj.EventName.toString();
    cell5.innerHTML = obj.ASCII.toString();
    cell6.innerHTML = obj.EventDesc.toString();
    cell7.innerHTML = obj.EventAddressType.toString();
    cell8.innerHTML = obj.EventAddressNumber.toString();
    cell9.innerHTML = obj.SubscriberID.toString();
    cell10.innerHTML = obj.AreaID.toString();
    cell11.innerHTML = obj.PeripheralID.toString();
  }
}

//////////////////////////////////////////////////////////////////////
// This function gets called when the ccs styles need to be updated //
//////////////////////////////////////////////////////////////////////
function resize_me_too() {
  var Xmax = $( window ).width();
  var Ymax = $( window ).height();
  var Xcenter = Xmax / 2;
  var Ycenter = Ymax / 2;

  // Recompute and set the heights that are not ajusted automaticly
  //
  $( "#Desktop" ).css( "height", Ymax );
  $( "#Toolbox" ).css( "height", Ymax - parseInt( $( "#Spacer" ).css( "height" ) ) - parseInt( $( "#SIA-Messages" ).css( "height" ) ) );

  // Refresh the accordion widgets to apply the new sizes
  $( "#Toolbox" ).accordion( "refresh" );
  $( "#SIA-Messages" ).accordion( "refresh" );

}

/////////////////////////////////////////////////////////////
// This function gets called in response to a resize event //
/////////////////////////////////////////////////////////////
function resize_me() {
  resize_me_too();
  $( "#SocketStatus" ).dialog( "option", "position", SocketStatus_default_position ); // reposition the SocketStatus dialog
}

//////////////////////////////////////////////////////////////////////////////////////
// This function gets called when the 'Spacer' is stopped being dragged up or down. //
//////////////////////////////////////////////////////////////////////////////////////
function resizeToolbox( event, ui ) {
  var adjust    = 0;
  var Ymin      = 0;
  var Ymax      = parseInt( $( window ).height() ) - 200;
  var delta     = parseInt( $( "#Spacer" ).css( "top" ) );
  var newHeight = parseInt( $( "#SIA-Messages" ).css( "height" ) ) - delta;

  if( newHeight > Ymax ) {
    adjust = newHeight - Ymax;
    newHeight = Ymax;
  }
  else if( newHeight < Ymin ) {
    adjust = newHeight - Ymin;
    newHeight = Ymin;
  }

  sia_outer_table_height = sia_outer_table_height - delta - adjust;
  sia_inner_table_height = sia_inner_table_height - delta - adjust;

  $( "#SIA-Messages"          ).css( "height", newHeight );
  $( ".sia-table-outer_table" ).css( "height", sia_outer_table_height );
  $( ".sia-table-inner_div"   ).css( "height", sia_inner_table_height );

  $( "#Desktop" ).css( "top", 0 );
  $( "#Toolbox" ).css( "top", 0 );
  $( "#Spacer"  ).css( "top", 0 );

  resize_me_too();
}

// INFO DIALOG ////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
// This function gets called in response to click on a menuitem in //
// the menu of dialog #SocketStatus                                //
/////////////////////////////////////////////////////////////////////
function SocketStatus_MenuSelectEvent( event, ui ) {
  var handled = 0;
  switch( ui.item.context.id.toString() ) {
    case 'SocketStatus-Menu-Commandline':
      $( "#openGalaxy-cli" ).dialog("open");
      handled = 1;
      break;
    case 'SocketStatus-Menu-Resources-Homepage':
    case 'SocketStatus-Menu-Resources-SIA':
      handled = 1;
      break;
    case 'SocketStatus-Menu-Help-About':
      var h = 600; if( $( window ).height() < h ) h = $( window ).height();
      if( $( "#openGalaxy-About" ).dialog( "isOpen" ) == false ) {
        $( "#openGalaxy-About" ).dialog( "option", "position", { my: "center", at: "center", of: "#Desktop" } );
        $( "#openGalaxy-About" ).dialog("option", "height", h );
        $( "#openGalaxy-About" ).dialog("open");
      }
      handled = 1;
      break;
  }

  // hide the menu
  if( handled ) $( "#SocketStatus-Menu" ).menu( "collapseAll", null, true ).menu( "blur" ).toggleClass( "show" );
}

///////////////////////////////////////////////////////////////////////////////////////
// This function sets the command status in the #SocketStatus dialog                 //
//  - if timeoutMs is nonzero the text resets to 'Idle' after timeoutMs milliseconds //
///////////////////////////////////////////////////////////////////////////////////////
function SocketStatus_SetCommandStatus( textStr, classStr, colorStr, timeoutMs ) {
  if( $( "#ws_cmd_status" ).hasClass( "ui-state-default" ) ) $( "#ws_cmd_status" ).removeClass( "ui-state-default" );
  if( $( "#ws_cmd_status" ).hasClass( "ui-state-error"   ) ) $( "#ws_cmd_status" ).removeClass( "ui-state-error" );
  if( $( "#ws_cmd_status" ).hasClass( "ui-state-active"  ) ) $( "#ws_cmd_status" ).removeClass( "ui-state-active" );
  if( $( "#ws_cmd_status" ).hasClass( classStr           ) ) $( "#ws_cmd_status" ).removeClass( classStr );

  $( "#ws_cmd_status" ).html( textStr );
  $( "#ws_cmd_status" ).addClass( classStr );
  $( "#ws_cmd_status" ).css( "color", colorStr );

  if( timeoutMs ) {
    setTimeout(
      function() {
        if( $( "#ws_cmd_status" ).hasClass( "ui-state-default" ) ) $( "#ws_cmd_status" ).removeClass( "ui-state-default" );
        if( $( "#ws_cmd_status" ).hasClass( "ui-state-error"   ) ) $( "#ws_cmd_status" ).removeClass( "ui-state-error" );
        if( $( "#ws_cmd_status" ).hasClass( "ui-state-active"  ) ) $( "#ws_cmd_status" ).removeClass( "ui-state-active" );
        if( $( "#ws_cmd_status" ).hasClass( classStr           ) ) $( "#ws_cmd_status" ).removeClass( classStr );
        $( "#ws_cmd_status" ).html( "Idle" );
        $( "#ws_cmd_status" ).addClass( "ui-state-active" );
        $( "#ws_cmd_status" ).css( "color", "green" );
      },
      timeoutMs
    );
  }
}

// AREAS //////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////
// Callback for clicking on a button in the Arm/Disarm Area tab //
//////////////////////////////////////////////////////////////////
function sendAreaCommand( button ) {
  var cmd;
  var number;
  var action;
  var oldSelectedAllAreas = selectedAllAreas; // for restoration after STATE/READY/ALARM
  switch( button.id ) {
    case "buttonArm":
      action = " SET";
      break;
    case "buttonDisarm":
      action = " UNSET";
      break;
    case "buttonPartial":
      action = " PARTIAL";
      break;
    case "buttonForce":
      action = " FORCE";
      break;
    case "buttonAbort":
      action = " ABORT";
      break;
    case "buttonReset":
      action = " RESET";
      break;
    case "buttonState":
      action = " STATE";
      selectedAllAreas = true;
      clearAllAreaStates();
      break;
    case "buttonReady":
      action = " READY";
      selectedAllAreas = true;
      clearAllAreaStates();
      break;
    case "buttonAlarm":
      action = " ALARM";
      selectedAllAreas = true;
      clearAllAreaStates();
      break;
  }
  if( selectedAllAreas == true ) {
    cmd = "AREA 0 " + action;
    send( cmd );
  }
  else {
    for( i = 0; i < 32; i++ ) {
      if( selectedAreas[ i ] == true ) {
        cmd = "AREA " + (i + 1) + action;
        send( cmd );
      }
    }
  }
  selectedAllAreas = oldSelectedAllAreas;
}

//////////////////////////////////////////////////////////////////////////
// Callback for when the user has finished selecting areas              //
//  - sets SelectedAreas and selectedAllAreas based on #selectableAreas //
//////////////////////////////////////////////////////////////////////////
function parseSelectedAreas( obj ) {
  for( i = 0; i < 32; i++ ) selectedAreas[ i ] = false;
  selectedAllAreas = true;
  $( ".ui-selected", obj ).each( function() {
    var index = $( "#selectableAreas li" ).index( this );
    selectedAreas[ index ] = true;
  });
  for( i = 0; i < 32; i++ ) {
    if( selectedAreas[ i ] == false ) {
      selectedAllAreas = false;
      break;
    }
  }
}

///////////////////////////////////////////////////
// Helper function for clearAllAreaStates()      //
//  - clears 'color state' class from li element //
///////////////////////////////////////////////////
function clearAreaState( obj ) {
  if( $( obj ).hasClass( "disarmedAreaState"      ) ) $( obj ).removeClass( "disarmedAreaState"      );
  if( $( obj ).hasClass( "armedAreaState"         ) ) $( obj ).removeClass( "armedAreaState"         );
  if( $( obj ).hasClass( "partialAreaState"       ) ) $( obj ).removeClass( "partialAreaState"       );
  if( $( obj ).hasClass( "readyAreaState"         ) ) $( obj ).removeClass( "readyAreaState"         );
  if( $( obj ).hasClass( "timeLockedAreaState"    ) ) $( obj ).removeClass( "timeLockedAreaState"    );
  if( $( obj ).hasClass( "normalAreaState"        ) ) $( obj ).removeClass( "normalAreaState"        );
  if( $( obj ).hasClass( "alarmAreaState"         ) ) $( obj ).removeClass( "alarmAreaState"         );
  if( $( obj ).hasClass( "resetRequiredAreaState" ) ) $( obj ).removeClass( "resetRequiredAreaState" );
  if( $( obj ).hasClass( "stateAreaStateText"     ) ) $( obj ).removeClass( "stateAreaStateText"     );
  if( $( obj ).hasClass( "readyAreaStateText"     ) ) $( obj ).removeClass( "readyAreaStateText"     );
  if( $( obj ).hasClass( "alarmAreaStateText"     ) ) $( obj ).removeClass( "alarmAreaStateText"     );
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Returns the #statusAreas .statusArea elements (on the Areas:Status tab) to their default 'unknown' state //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
function clearAllAreaStates()
{
  $( ".statusArea", "#statusAreas" ).each( function(){
    clearAreaState( this );
  });
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// This function is called by SocketCommander_OnMessage() when a 'AREA 0 STATE/READY/ALARM'     //
//  command has returned a valid reply                                                          //
//////////////////////////////////////////////////////////////////////////////////////////////////
function displayAllAreaStates( galaxy ) {
  // For each element with class .statusArea (in context #statusAreas), do:
  $( ".statusArea", "#statusAreas" ).each( function() {
    // Clear the current area status
    clearAreaState( this );
    // Get the index of the current li element
    var index = $( "#statusAreas li" ).index( this );
    // Set the correct xxxAreaState class of this li element based on galaxy.areaState[index]
    switch( galaxy.typeId ) {
     case JSON_ALL_AREA_ARMED_STATE:
       SocketStatus_SetCommandStatus( "AREA 0 STATE (success)", "ui-state-active", "blue", 2000 );
       if( galaxy.typeId == JSON_ALL_AREA_ARMED_STATE ) $( this ).addClass( "stateAreaStateText" );
       else $( this ).addClass( "readyAreaStateText" );
       switch( galaxy.areaState[index] ) {
         case 0:
           $( this ).addClass( "disarmedAreaState" );
           break;
         case 1:
           $( this ).addClass( "armedAreaState" );
           break;
         case 2:
           $( this ).addClass( "partialAreaState" );
           break;
       }
       break;
     case JSON_ALL_AREA_READY_STATE:
       SocketStatus_SetCommandStatus( "AREA 0 READY (success)", "ui-state-active", "blue", 2000 );
       if( galaxy.typeId == JSON_ALL_AREA_ARMED_STATE ) $( this ).addClass( "stateAreaStateText" );
       else $( this ).addClass( "readyAreaStateText" );
       switch( galaxy.areaState[index] ) {
         case 0:
           $( this ).addClass( "disarmedAreaState" );
           break;
         case 1:
           $( this ).addClass( "armedAreaState" );
           break;
         case 2:
           $( this ).addClass( "partialAreaState" );
           break;
         case 3:
           $( this ).addClass( "readyAreaState" );
           break;
         case 4:
           $( this ).addClass( "timeLockedAreaState" );
           break;
       }
       break;
     case JSON_ALL_AREA_ALARM_STATE:
       SocketStatus_SetCommandStatus( "AREA 0 ALARM (success)", "ui-state-active", "blue", 2000 );
       $( this ).addClass( "alarmAreaStateText" );
       switch( galaxy.areaState[index] ) {
         case 0:
           $( this ).addClass( "normalAreaState" );
           break;
         case 1:
           $( this ).addClass( "alarmAreaState" );
           break;
         case 2:
           $( this ).addClass( "resetRequiredAreaState" );
           break;
       }
       break;
    }
  });
}

// ZONES OMIT //////////////////////////////////////////////////////////////////////

var omitZonesHasStart = false;
var omitZonesHasEnd = false;
var omitZonesHasType = false;

function omitZonesOnMenuSelect( menu, ui )
{
  var startZone = parseInt( $( "#omitBusStart" ).val() ) + parseInt( $( "#omitRioStart" ).val() ) + parseInt( $( "#omitZoneStart" ).val() );
  var endZone = parseInt( $( "#omitBusEnd" ).val() ) + parseInt( $( "#omitRioEnd" ).val() ) + parseInt( $( "#omitZoneEnd" ).val() );
  var zoneType = $( "#omitByType" ).val();

  switch( menu.id ) {
    case "omitBusStart":
    case "omitRioStart":
    case "omitZoneStart":
      if( omitZonesHasStart == false ) {
        $( "#omitBusEnd, #omitRioEnd, #omitZoneEnd" ).selectmenu( "enable" );
        omitZonesHasStart = true;
      }
      omitZonesHasEnd = false;
      omitZonesHasType = false;
      break;

    case "omitBusEnd":
    case "omitRioEnd":
    case "omitZoneEnd":
      omitZonesHasEnd = true;
      break;

    case "omitByType":
      if( omitZonesHasStart == true ) {
        $( "#omitBusEnd, #omitRioEnd, #omitZoneEnd" ).selectmenu( "disable" );
        omitZonesHasStart = false;
        omitZonesHasEnd = false;
      }
      omitZonesHasType = true;
      break;
  }

  if( omitZonesHasType == true ) {
    $( "#omitZonesSelectedByType" ).html( zoneType.toString() );
    $( "#omitZonesSelectedStart, #omitZonesSelectedSeparator, #omitZonesSelectedEnd" ).html( "" );
  }
  else {
    $( "#omitZonesSelectedByType" ).html( "" );
    if( omitZonesHasStart == true ) {
      $( "#omitZonesSelectedStart" ).html( startZone.toString() );
    }
    else {
      $( "#omitZonesSelectedStart" ).html( "" );
    }
    if( omitZonesHasEnd == true ) {
      $( "#omitZonesSelectedSeparator" ).html( " - " );
      $( "#omitZonesSelectedEnd" ).html( endZone.toString() );
    }
    else {
      $( "#omitZonesSelectedSeparator, #omitZonesSelectedEnd" ).html( "" );
    }
  }
}

function omitZonesSendCommand( omit )
{
  var cmd;

  var action;
  if( omit == true ) action = " OMIT";
  else action = " UNOMIT";

  if( omitZonesHasType == true ) {
    var zoneType = $( "#omitByType" ).val();
    cmd = "ZONE " + zoneType.toString() + action;
    send( cmd );
  }
  else if( omitZonesHasStart == true ) {
    var t;
    var startZone = parseInt( $( "#omitBusStart" ).val() ) + parseInt( $( "#omitRioStart" ).val() ) + parseInt( $( "#omitZoneStart" ).val() );
    var endZone = parseInt( $( "#omitBusEnd" ).val() ) + parseInt( $( "#omitRioEnd" ).val() ) + parseInt( $( "#omitZoneEnd" ).val() );
    if( omitZonesHasEnd == true ) {
      if( startZone > endZone ) startZone = endZone + ((endZone = startZone) - startZone);
    }
    else {
      endZone = startZone;
    }

    t = startZone;
    while( t <= endZone ) {
      var line = 1 + ( ( ( t / 1000 ) - 1 ) & 3 );
      var rio  = ( ( t - ( line * 1000 ) ) / 10 ) & 15;
      var zn   = 1 + ( ( t - ( line * 1000 ) - ( rio * 10 ) - 1 ) & 7 );

      cmd = "ZONE " + t.toString() + action;
      send( cmd );

      // move to next zone
      t++;
      if( zn == 8 ) {
        t += 2; // move to next rio
        if( rio == 15 ) t += 840; // move to next bus
      }
    }

  }
}

// ZONES GET STATUS ///////////////////////////////////////////////////////////

var displayRioZonessRio; // The current RIO to get the zones status for.

///////////////////////////////////////////////////
// Helper function for clearRioZoneStates()    //
//  - clears 'color state' class from li element //
///////////////////////////////////////////////////
function clearZoneState( obj ) {
  if( $( obj ).hasClass( "tamperScZoneState"       ) ) $( obj ).removeClass( "tamperScZoneState"       );
  if( $( obj ).hasClass( "tamperOcZoneState"       ) ) $( obj ).removeClass( "tamperOcZoneState"       );
  if( $( obj ).hasClass( "tamperCvZoneState"       ) ) $( obj ).removeClass( "tamperCvZoneState"       );
  if( $( obj ).hasClass( "tamperAnyZoneState"      ) ) $( obj ).removeClass( "tamperAnyZoneState"      );
  if( $( obj ).hasClass( "resistanceLowZoneState"  ) ) $( obj ).removeClass( "resistanceLowZoneState"  );
  if( $( obj ).hasClass( "resistanceHighZoneState" ) ) $( obj ).removeClass( "resistanceHighZoneState" );
  if( $( obj ).hasClass( "resistanceAnyZoneState"  ) ) $( obj ).removeClass( "resistanceAnyZoneState"  );
  if( $( obj ).hasClass( "maskedZoneState"         ) ) $( obj ).removeClass( "maskedZoneState"         );
  if( $( obj ).hasClass( "faultZoneState"          ) ) $( obj ).removeClass( "faultZoneState"          );
  if( $( obj ).hasClass( "closedZoneState"         ) ) $( obj ).removeClass( "closedZoneState"         );
  if( $( obj ).hasClass( "openZoneState"           ) ) $( obj ).removeClass( "openZoneState"           );
  if( $( obj ).hasClass( "alarmZoneState"          ) ) $( obj ).removeClass( "alarmZoneState"          );
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Returns the #statusZones .statusZones elements (on the Zones:Status tab) to their default 'unknown' state //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
function clearRioZoneStates()
{
  $( ".statusZone", "#statusZones" ).each( function(){
    clearZoneState( this );
    $( this ).find('.statusZoneOmitted').text( '' );
  });
}

/////////////////////////////////////////////////////////////////////////////////////
// This function is called by SocketCommander_OnMessage() when a 'ZONE xxxx STATE' //
//  command has returned a valid reply                                             //
/////////////////////////////////////////////////////////////////////////////////////
function displayRioSingleZoneState( galaxy ) {
  var nr = GalaxyZone4to3( parseInt( galaxy['zoneNumber'] ) ) % 8; // 1...8

  if( nr == 0 ) {
    nr = 8;
  }

  // Locate the .statusZone for this zone number
  $( ".statusZone", "#statusZones" ).each( function(){
    if( $(this).text() == nr ){
      // Found it, set the correct attributes
      clearZoneState( $(this) );
      switch( galaxy['typeId'] ){
        case JSON_ZONE_OMIT_STATE:
           if( galaxy['omitState'] ) $( this ).find('.statusZoneOmitted').text( '*' );
           return false;
        case JSON_ZONE_STATE:
          switch( galaxy['zoneState'] ){
            case 0: // Tamper S/C
              $( this ).addClass( 'tamperScZoneState' );
              return false;
            case 1: // Low resistance
              $( this ).addClass( 'resistanceLowZoneState' );
              return false;
            case 2: // Zone closed
              $( this ).addClass( 'closedZoneState' );
              return false;
            case 3: // High resistance
              $( this ).addClass( 'resistanceHighZoneState' );
              return false;
            case 4: // Open
              $( this ).addClass( 'openZoneState' );
              return false;
            case 5: // Tamper O/C
              $( this ).addClass( 'tamperOcZoneState' );
              return false;
            case 6: // Masked
              $( this ).addClass( 'maskedZoneState' );
              return false;
            case 7: // Tamper CV
              $( this ).addClass( 'tamperCvZoneState' );
              return false;
            case 8: // Fault
              $( this ).addClass( 'faultZoneState' );
              return false;
           }
           return false;
        default:
          return false; // 'break'
      }
    }
  });
}

/////////////////////////////////////////////////////////////////////////////////////
// This function is called by SocketCommander_OnMessage() when a 'ZONES xxxx' //
//  command has returned a valid reply                                             //
/////////////////////////////////////////////////////////////////////////////////////
function displayRioZoneStates( galaxy ) {

  var line = 1 + (((displayRioZonessRio / 100) - 1) & 3),
      rio = (displayRioZonessRio - (line * 100)) & 15,
      idx = ((line - 1) << 4) + rio + 1,
      zn = galaxy.zoneState[ idx ];

  // for each .statusZone found in the context of #statusZones do
  $( ".statusZone", "#statusZones" ).each( function(){
    var nr = parseInt($(this).text()); // 1...8
    var msk = 1 << (nr - 1); 
    // Found it, set the correct attributes
    switch( galaxy['typeId'] ){
      case JSON_ALL_ZONE_ALARM_STATE:
        if(zn & msk){
          clearZoneState( $(this) );
          $( this ).addClass( 'alarmZoneState' );
        }
        else {
          clearZoneState( $(this) );
          $( this ).addClass( 'closedZoneState' );
        }
        break;
      case JSON_ALL_ZONE_READY_STATE:
      case JSON_ALL_ZONE_OPEN_STATE:
        if(zn & msk){
          clearZoneState( $(this) );
          $( this ).addClass( 'openZoneState' );
        }
        else {
          clearZoneState( $(this) );
          $( this ).addClass( 'closedZoneState' );
        }
        break;
      case JSON_ALL_ZONE_TAMPER_STATE:
        if(zn & msk){
          clearZoneState( $(this) );
          $( this ).addClass( 'tamperAnyZoneState' );
        }
        break;
      case JSON_ALL_ZONE_R_STATE:
        if(zn & msk){
          clearZoneState( $(this) );
          $( this ).addClass( 'resistanceAnyZoneState' );
        }
        break;
      case JSON_ALL_ZONE_OMIT_STATE:
        if(zn & msk){
          $( this ).find('.statusZoneOmitted').text('*');
        }
        else {
          $( this ).find('.statusZoneOmitted').text( '' );
        }
        break;

      default:
        return false; // 'break'
    }
  });

}

////////////////////////////////////////////////////////////////
// Called when the button on the zones status page is clicked //
////////////////////////////////////////////////////////////////
function displayRioZoneStatesSendCommand( galaxy ) {
  displayRioZonessRio = parseInt( $( "#statusZonesBusStart" ).val() ) + parseInt( $( "#statusZonesRioStart" ).val() );

  if( $(galaxy).hasClass("statusZonesButtonUpdateReady") ){
    send( 'ZONES READY' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateAlarm") ){
    send( 'ZONES ALARM' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateOpen") ){
    send( 'ZONES OPEN' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateTamper") ){
    send( 'ZONES TAMPER' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateRstate") ){
    send( 'ZONES RSTATE' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateOmit") ){
    send( 'ZONES OMITTED' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateZone1") ){
    var zn = ( displayRioZonessRio * 10 ) + 1;
    send( 'ZONE ' + zn + ' STATE' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateZone2") ){
    var zn = ( displayRioZonessRio * 10 ) + 2;
    send( 'ZONE ' + zn + ' STATE' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateZone3") ){
    var zn = ( displayRioZonessRio * 10 ) + 3;
    send( 'ZONE ' + zn + ' STATE' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateZone4") ){
    var zn = ( displayRioZonessRio * 10 ) + 4;
    send( 'ZONE ' + zn + ' STATE' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateZone5") ){
    var zn = ( displayRioZonessRio * 10 ) + 5;
    send( 'ZONE ' + zn + ' STATE' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateZone6") ){
    var zn = ( displayRioZonessRio * 10 ) + 6;
    send( 'ZONE ' + zn + ' STATE' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateZone7") ){
    var zn = ( displayRioZonessRio * 10 ) + 7;
    send( 'ZONE ' + zn + ' STATE' );
  }
  else if( $(galaxy).hasClass("statusZonesButtonUpdateZone8") ){
    var zn = ( displayRioZonessRio * 10 ) + 8;
    send( 'ZONE ' + zn + ' STATE' );
  }
}


// ZONES PARAMETERS ////////////////////////////////////////////////////////////////

var parametersZonesHasStart = false;
var parametersZonesHasType = false;

function parametersZonesOnMenuSelect( menu, ui )
{
  var startZone = parseInt( $( "#parametersBusStart" ).val() ) + parseInt( $( "#parametersRioStart" ).val() ) + parseInt( $( "#parametersZoneStart" ).val() );
  var zoneType = $( "#parametersByType" ).val();

  switch( menu.id ) {
    case "parametersBusStart":
    case "parametersRioStart":
    case "parametersZoneStart":
      if( parametersZonesHasStart == false ) {
        parametersZonesHasStart = true;
      }
      parametersZonesHasType = false;
      break;

    case "parametersByType":
      if( parametersZonesHasStart == true ) {
        parametersZonesHasStart = false;
      }
      parametersZonesHasType = true;
      break;
  }

  if( parametersZonesHasType == true ) {
    $( "#parametersZonesSelectedByType" ).html( zoneType.toString() );
    $( "#parametersZonesSelectedStart" ).html( "" );
  }
  else {
    $( "#parametersZonesSelectedByType" ).html( "" );
    if( parametersZonesHasStart == true ) {
      $( "#parametersZonesSelectedStart" ).html( startZone.toString() );
    }
    else {
      $( "#parametersZonesSelectedStart" ).html( "" );
    }
  }
}

function parametersZonesSendCommand( button )
{
  var cmd;
  var flag;
  var option;
  switch( button.id ) {
    case "buttonSoakTestOn":
      option = "SOAK-TEST "
      flag = "ON"
      break;
    case "buttonSoakTestOff":
      option = "SOAK-TEST "
      flag = "OFF"
      break;
    case "buttonPartSetOn":
      option = "PART-SET "
      flag = "ON"
      break;
    case "buttonPartSetOff":
      option = "PART-SET "
      flag = "OFF"
      break;
    default:
      return;
  }
  if( parametersZonesHasType == true ) {
    var zoneType = $( "#parametersByType" ).val();
    cmd = "ZONE " + zoneType.toString() + " PARAMETER " + option + flag;
  }
  else if( parametersZonesHasStart == true ) {
    var startZone = parseInt( $( "#parametersBusStart" ).val() ) + parseInt( $( "#parametersRioStart" ).val() ) + parseInt( $( "#parametersZoneStart" ).val() );
    cmd = "ZONE " + startZone.toString() + " PARAMETER " + option + flag;
  }
  send( cmd );
}

// ZONES PROGRAMMING ///////////////////////////////////////////////////////////////

function programZonesSendCommand( button )
{
  var zone = parseInt( $( "#programBusStart" ).val() ) + parseInt( $( "#programRioStart" ).val() ) + parseInt( $( "#programZoneStart" ).val() );
  var state = $( "#programState" ).val();
  var area = $( "#programArea" ).val();
  var type = $( "#programType" ).val();
  var desc = $( "#programDescInput" ).val();
  var cmd = "ZONE " + zone + " SET " + state + " " + area + " " + type;
  if( desc.length != 0 ) cmd = cmd + " " + desc;
  send( cmd );
}

// OUTPUT SET/RESET ///////////////////////////////////////////////////////////

var outputsSetHasStart = false;
var outputsSetHasEnd = false;
var outputsSetHasType = false;

function outputsSetOnMenuSelect( menu, ui )
{
  var startOutput = parseInt( $( "#outputBusStart" ).val() ) + parseInt( $( "#outputRioStart" ).val() ) + parseInt( $( "#outputOpStart" ).val() );
  var endOutput = parseInt( $( "#outputBusEnd" ).val() ) + parseInt( $( "#outputRioEnd" ).val() ) + parseInt( $( "#outputOpEnd" ).val() );
  var outputType = $( "#outputByType" ).val();
  var outputTypeArea = $( "#outputByTypeArea" ).val();

  switch( menu.id ) {
    case "outputBusStart":
    case "outputRioStart":
    case "outputOpStart":
      if( outputsSetHasStart == false ) {
        $( "#outputBusEnd, #outputRioEnd, #outputOpEnd" ).selectmenu( "enable" );
        outputsSetHasStart = true;
      }
      outputsSetHasEnd = false;
      outputsSetHasType = false;
      break;

    case "outputBusEnd":
    case "outputRioEnd":
    case "outputOpEnd":
      outputsSetHasEnd = true;
      break;

    case "outputByType":
    case "outputByTypeArea":
      if( outputsSetHasStart == true ) {
        $( "#outputBusEnd, #outputRioEnd, #outputOpEnd" ).selectmenu( "disable" );
        outputsSetHasStart = false;
        outputsSetHasEnd = false;
      }
      outputsSetHasType = true;
      break;
  }

  if( outputsSetHasType == true ) {
    $( "#outputsSetSelectedStart, #outputsSetSelectedEnd" ).html( "" );
    $( "#outputsSetSelectedByType" ).html( "Type " + outputType.toString() );
    $( "#outputsSetSelectedSeparator" ).html( " - " );
    $( "#outputsSetSelectedByTypeArea" ).html( "Area " + outputTypeArea.toString() );
  }
  else {
    $( "#outputsSetSelectedByType, #outputsSetSelectedByTypeArea" ).html( "" );
    if( outputsSetHasStart == true ) {
      $( "#outputsSetSelectedStart" ).html( startOutput.toString() );
    }
    else {
      $( "#outputsSetSelectedStart" ).html( "" );
    }
    if( outputsSetHasEnd == true ) {
      $( "#outputsSetSelectedSeparator" ).html( " - " );
      $( "#outputsSetSelectedEnd" ).html( endOutput.toString() );
    }
    else {
      $( "#outputsSetSelectedSeparator, #outputsSetSelectedEnd" ).html( "" );
    }    
  }
}

function outputsSetSendCommand( state )
{
  var cmd;

  var action;
  if( state == true ) action = " ON";
  else action = " OFF";

  if( outputsSetHasType == true ) {
    var outputType = $( "#outputByType" ).val();
    var outputTypeArea = $( "#outputByTypeArea" ).val();
    cmd = "OUTPUT " + outputType.toString() + action + " " + outputTypeArea.toString();
    send( cmd );
  }
  else if( outputsSetHasStart == true ) {
    var t;
    var startOutput = parseInt( $( "#outputBusStart" ).val() ) + parseInt( $( "#outputRioStart" ).val() ) + parseInt( $( "#outputOpStart" ).val() );
    var endOutput = parseInt( $( "#outputBusEnd" ).val() ) + parseInt( $( "#outputRioEnd" ).val() ) + parseInt( $( "#outputOpEnd" ).val() );
    if( outputsSetHasEnd == true ) {
      if( startOutput > endOutput ) startOutput = endOutput + ((endOutput = startOutput) - startOutput);
    }
    else {
      endOutput = startOutput;
    }

    t = startOutput;
    while( t <= endOutput ) {
      var line = 1 + ( ( ( t / 1000 ) - 1 ) & 3 );
      var rio  = ( ( t - ( line * 1000 ) ) / 10 ) & 15;
      var op   = 1 + ( ( t - ( line * 1000 ) - ( rio * 10 ) - 1 ) & 3 );

      cmd = "OUTPUT " + t.toString() + action;
      send( cmd );

      // move to next output
      t++;
      if( op == 4 ) {
        t += 6; // move to next rio
        if( rio == 15 ) t += 840; // move to next bus
      }
    }

  }
}

// OUTPUT STATUS //////////////////////////////////////////////////////////////

var displayRioOutputsRio; // The current RIO to get the output status for.

///////////////////////////////////////////////////
// Helper function for clearRioOutputStates()    //
//  - clears 'color state' class from li element //
///////////////////////////////////////////////////
function clearOutputState( obj ) {
  if( $( obj ).hasClass( "onOutputState"  ) ) $( obj ).removeClass( "onOutputState"  );
  if( $( obj ).hasClass( "offOutputState" ) ) $( obj ).removeClass( "offOutputState" );
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Returns the #statusZones .statusZones elements (on the Zones:Status tab) to their default 'unknown' state //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
function clearRioOutputStates()
{
  $( ".statusOutputs", "#statusOutputs" ).each( function(){
    clearOutputState( this );
  });
}

///////////////////////////////////////////////////////////////////////////////////
// This function is called by SocketCommander_OnMessage() when a 'OUTPUT GETALL' //
//  command has returned a valid reply                                           //
///////////////////////////////////////////////////////////////////////////////////
function displayRioOutputStates( galaxy ) {

  var line = 1 + (((displayRioOutputsRio / 100) - 1) & 3),
      rio = (displayRioOutputsRio - (line * 100)) & 15,
      op = galaxy.outputState[ ((line - 1) << 3) + (rio >> 1) ];

  if( rio & 1 ) op >>= 4;
  else op &= 15;

  if( op & 1 ) $( "#statusOutput1" ).addClass( 'onOutputState' );
  else  $( "#statusOutput1" ).addClass( 'offOutputState' );
  if( op & 2 ) $( "#statusOutput2" ).addClass( 'onOutputState' );
  else  $( "#statusOutput2" ).addClass( 'offOutputState' );
  if( op & 4 ) $( "#statusOutput3" ).addClass( 'onOutputState' );
  else  $( "#statusOutput3" ).addClass( 'offOutputState' );
  if( op & 8 ) $( "#statusOutput4" ).addClass( 'onOutputState' );
  else  $( "#statusOutput4" ).addClass( 'offOutputState' );

}

////////////////////////////////////////////////////////////////
// Called when the button on the output status page is clicked //
////////////////////////////////////////////////////////////////
function displayRioOutputStatesSendCommand( galaxy ) {
  displayRioOutputsRio = parseInt( $( "#statusOutputsBusStart" ).val() ) + parseInt( $( "#statusOutputsRioStart" ).val() );
  clearRioOutputStates();
  send( 'OUTPUT GETALL' );
}

// WEBSOCKETS /////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////
// Open event callback function for the commander protocol //
/////////////////////////////////////////////////////////////
function SocketCommander_OnOpen()
{
  // Set websockets connection status to 'connected'
  $( "#ws_url_status" ).html( "Connected to server" );
  if( $( "#ws_url_status" ).hasClass( "ui-state-default" ) ) $( "#ws_url_status" ).removeClass( "ui-state-default" );
  if( $( "#ws_url_status" ).hasClass( "ui-state-error" ) ) $( "#ws_url_status" ).removeClass( "ui-state-error" );
  $( "#ws_url_status" ).addClass( "ui-state-active" );
  $( "#ws_url_status" ).css( "color", "green" );
  // Set command status to 'idle'
  SocketStatus_SetCommandStatus( "Idle", "ui-state-active", "green", 0 );
} 

//////////////////////////////////////////////////////////////
// Close event callback function for the commander protocol //
//////////////////////////////////////////////////////////////
function SocketCommander_OnClose()
{
  // Set websockets connection status to 'disconnected'
  $( "#ws_url_status" ).html( "Disconnected from server!" );
  if( $( "#ws_url_status" ).hasClass( "ui-state-default" ) ) $( "#ws_url_status" ).removeClass( "ui-state-default" );
  if( $( "#ws_url_status" ).hasClass( "ui-state-active" ) ) $( "#ws_url_status" ).removeClass( "ui-state-active" );
  $( "#ws_url_status" ).addClass( "ui-state-error" );
  $( "#ws_url_status" ).css( "color", "red" );
  // Set command status to '---'
  SocketStatus_SetCommandStatus( "---", "ui-state-error", "red", 0 );
  // Try to reconnect
  Websocket_Connect();
}

////////////////////////////////////////////////////////////////
// Message event callback function for the commander protocol //
////////////////////////////////////////////////////////////////
function SocketCommander_OnMessage(msg)
{
  $( "#json" ).html( msg.data );
  var result = jQuery.parseJSON( $( "#json" ).html() );

  switch( result.typeId ) {

    case JSON_SIA_MESSAGE:
      table_prepend( result.sia );
      break;

    case JSON_HELP_REPLY:
      $( "#defaultDialog" ).html( result.helpText )
                           .dialog( "option", "title", "Help" )
                           .dialog( "option", "show", true )
                           .dialog( "open" );
      break;

    // Standard reply, displays error message for failed commands
    case JSON_STANDARD_REPLY:
      if(result.success) {
        SocketStatus_SetCommandStatus( result.command + " (success)", "ui-state-active", "blue", 2000 );
      } else {
        SocketStatus_SetCommandStatus( result.command + " (error)", "ui-state-error", "red", 2000 );
        $( "#defaultDialog" ).html( '<p>Failed to execute command: ' + result.command + '<br><span class="red">' + result.replyText + '</span></p>' )
                             .dialog( "option", "title", "Command Error" )
                             .dialog( "option", "show", true )
                             .dialog( "open" );
      }
      break;

    // Display area states
    case JSON_ALL_AREA_ARMED_STATE:
    case JSON_ALL_AREA_ALARM_STATE:
    case JSON_ALL_AREA_READY_STATE:
      displayAllAreaStates( result );
      break;

    // Display zone states
    case JSON_ZONE_STATE:
      SocketStatus_SetCommandStatus( "ZONE x STATE (success)", "ui-state-active", "blue", 2000 );
      displayRioSingleZoneState( result );
      break;
    case JSON_ALL_ZONE_READY_STATE:
      SocketStatus_SetCommandStatus( "ZONES READY (success)", "ui-state-active", "blue", 2000 );
      displayRioZoneStates( result );
      break;
    case JSON_ALL_ZONE_ALARM_STATE:
      SocketStatus_SetCommandStatus( "ZONES ALARM (success)", "ui-state-active", "blue", 2000 );
      displayRioZoneStates( result );
      break;
    case JSON_ALL_ZONE_OPEN_STATE:
      SocketStatus_SetCommandStatus( "ZONES OPEN (success)", "ui-state-active", "blue", 2000 );
      displayRioZoneStates( result );
      break;
    case JSON_ALL_ZONE_TAMPER_STATE:
      SocketStatus_SetCommandStatus( "ZONES TAMPER (success)", "ui-state-active", "blue", 2000 );
      displayRioZoneStates( result );
      break;
    case JSON_ALL_ZONE_R_STATE:
      SocketStatus_SetCommandStatus( "ZONES RSTATE (success)", "ui-state-active", "blue", 2000 );
      displayRioZoneStates( result );
      break;
    case JSON_ALL_ZONE_OMIT_STATE:
      SocketStatus_SetCommandStatus( "ZONES OMITTED (success)", "ui-state-active", "blue", 2000 );
      displayRioZoneStates( result );
      break;

    // Display output states
    case JSON_ALL_OUTPUT_STATE:
      SocketStatus_SetCommandStatus( "OUTPUT GETALL (success)", "ui-state-active", "blue", 2000 );
      displayRioOutputStates( result );
      break;

    // This means that we cannot send any commands untill we (re)authenticate
    case JSON_AUTHORIZATION_REQUIRED:
      if( session_id == 0 ){
        session_id = result.typeDesc;
      }
      else if( session_id != result.typeDesc ){
        // session mismatch, must reload page to get a new session id
        $( "#reloadDialog" ).dialog( "option", "show", true ).dialog( "open" );
        break;
      }
      // Session matches, ask for credentials
      SocketStatus_SetCommandStatus( "Login required!", "ui-state-active", "red", 2000 );
      $( "#loginDialog" ).dialog( "option", "show", true ).dialog( "open" );
      break;

    case JSON_AUTHENTICATION_ACCEPTED:
      SocketStatus_SetCommandStatus( "Login successfull!", "ui-state-active", "green", 2000 );
      break;

    // Dump unhandled messages to screen
    default:
      printObject( result );
      break;
  }
}

///////////////////////////////////////////////////////////////
// Connect to the websocket (and retry after 5sec if failed) //
///////////////////////////////////////////////////////////////
function Websocket_Connect()
{
  // Display the location of the server
  // Connect to the websocket
  if( socket_commander == null ){
    if (typeof MozWebSocket != "undefined") {
      socket_commander = new MozWebSocket(get_socket_url(), "openGalaxy-websocket-protocol");
    } else {
      socket_commander = new WebSocket(get_socket_url(), "openGalaxy-websocket-protocol");
    }
    socket_commander.onopen = SocketCommander_OnOpen;
    socket_commander.onclose = SocketCommander_OnClose;
    socket_commander.onmessage = SocketCommander_OnMessage;
  }
  // Check connection status
  if( socket_commander != null ){
    switch( socket_commander.readyState ){
      case 0: // CONNECTING
        setTimeout( Websocket_Connect, 5000 );
        break;
      case 1: // OPEN
        break;
      case 2: // CLOSING
        setTimeout( Websocket_Connect, 5000 );
        break;
      case 3: // CLOSED
        socket_commander = null;
        setTimeout( Websocket_Connect, 5000 );
        break;
    }
  }
}

///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////
// Executed when the entire page has been loaded //
///////////////////////////////////////////////////

function document_ready() {} // Here so that gedit's codeview plugin can find this spot

$( document ).ready( function() {
  //
  var Xmax = $( window ).width();
  var Ymax = $( window ).height();
  //
  // Enable tooltips
  $( document ).tooltip( { track: true } );
  $( document ).tooltip().off( "focusin focusout" ); // display tooltips on mouse hover only
  //
  // Adjust the CSS sizes for #Desktop, #Toolbox and #SIA-Messages to fit the available screen size
  $( "#Desktop" ).css( "height", Ymax );
  $( "#Toolbox" ).css( "height", Ymax - parseInt( $( "#Spacer" ).css( "height" ) ) - parseInt( $( "#SIA-Messages" ).css( "height" ) ) );
  //
  // Create Accordion Widgets from #Toolbox and #SIA-Messages
  $( "#Toolbox, #SIA-Messages" ).accordion( { heightStyle: "fill" } );
  //
  // Create the tabs widgets #tabsAreas, #tabsZones and #tabsOutput
  $( "#tabsAreas, #tabsZones, #tabsOutput" ).tabs();
  //
  // Fixups to the CSS of the SIA messages table to adjust for actual screen size
  $( ".sia-table-outer_table" ).css( "height", parseInt( $( ".sia-table-outer_table" ).parent().css( "height" ) ) );
  $( ".sia-table-inner_div"   ).css( "height", parseInt( $( ".sia-table-inner_div"   ).parent().css( "height" ) ) );
  //
  // Readback the computed values of the SIA table height for useage while resizing by the user...
  sia_outer_table_height = parseInt( $( ".sia-table-outer_table" ).css( "height" ) );
  sia_inner_table_height = parseInt( $( ".sia-table-inner_div"   ).css( "height" ) );
  //
  // Make #Spacer draggable and set resizeToolbox() as callback when #Spacer is stopped being dragged
  $( "#Spacer" ).draggable( { axis: "y" } );
  $( "#Spacer" ).on( "dragstop", resizeToolbox );
  //
  //////////////////////
  // Initialize Areas //
  //////////////////////
  //
  // Init the widgets for the Areas tab
  $( "#selectableAreas" ).selectable();
  $( "#selectableAreas" ).on( "selectablestop", function( event, ui ) { parseSelectedAreas( this ); } );
  $( "#buttonArm, #buttonDisarm, #buttonPartial, #buttonForce, #buttonAbort, #buttonReset, #buttonState, #buttonReady, #buttonAlarm" ).button().click( function(){ sendAreaCommand( this ); } );
  //
  // Clear area status when the Areas(:Status) tab is clicked
  $( "#anchorStatusArea" ).on( "click", function() { clearAllAreaStates(); });
  $( "#anchorAreas" ).on( "click", function() { clearAllAreaStates(); });
  //
  ///////////////////////////////
  // Initialize Zones Omit tab //
  ///////////////////////////////
  //
  // Create selectmenus and buttons for the omit tab
  $( "#omitBusStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#omitRioStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                       .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#omitZoneStart" ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#omitBusEnd"    ).selectmenu( { disabled: true, position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#omitRioEnd"    ).selectmenu( { disabled: true, position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                       .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#omitZoneEnd"   ).selectmenu( { disabled: true, position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#omitByType"    ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                       .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#buttonOmit"    ).button().click( function(){ omitZonesSendCommand( true ); } );
  $( "#buttonUnomit"  ).button().click( function(){ omitZonesSendCommand( false ); } );
  //
  // Set the callbacks for the selectmenu's on the omit tab
  $( "#omitBusStart"  ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); omitZonesOnMenuSelect( this, ui ); } );
  $( "#omitRioStart"  ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); omitZonesOnMenuSelect( this, ui ); } );
  $( "#omitZoneStart" ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); omitZonesOnMenuSelect( this, ui ); } );
  $( "#omitBusEnd"    ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); omitZonesOnMenuSelect( this, ui ); } );
  $( "#omitRioEnd"    ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); omitZonesOnMenuSelect( this, ui ); } );
  $( "#omitZoneEnd"   ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); omitZonesOnMenuSelect( this, ui ); } );
  $( "#omitByType"    ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); omitZonesOnMenuSelect( this, ui ); } );
  //
  // Display the initialy selected zone from the selectmenus
  $( "#omitZonesSelectedStart" ).html( parseInt( $( "#omitBusStart" ).val() ) + parseInt( $( "#omitRioStart" ).val() ) + parseInt( $( "#omitZoneStart" ).val() ) );
  $( "#omitBusEnd, #omitRioEnd, #omitZoneEnd" ).selectmenu( "enable" );
  omitZonesHasStart = true;
  //
  /////////////////////////////////
  // Initialize Zones Status tab //
  /////////////////////////////////
  //
  $( "#statusZonesBusStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#statusZonesRioStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                              .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#statusZonesZoneStart" ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  //
  $( "#statusZonesButtonUpdateZone1"  ).click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateZone2"  ).click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateZone3"  ).click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateZone4"  ).click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateZone5"  ).click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateZone6"  ).click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateZone7"  ).click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateZone8"  ).click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  //
  $( "#statusZonesButtonUpdateReady"  ).button().click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateAlarm"  ).button().click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateOpen"   ).button().click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateTamper" ).button().click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateRstate" ).button().click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  $( "#statusZonesButtonUpdateOmit"   ).button().click( function(){ displayRioZoneStatesSendCommand( $(this) ); } );
  //
  $( "#anchorStatusZones" ).on( "click", function() { clearRioZoneStates(); });
  $( "#anchorZones" ).on( "click", function() { clearRioZoneStates(); });
  $( "#statusZonesBusStart, #statusZonesRioStart, #statusZonesZoneStart" ).on( "selectmenuchange", function() {
    clearRioZoneStates();
  });
  //
  /////////////////////////////////////
  // Initialize Zones Parameters tab //
  /////////////////////////////////////
  //
  // Create selectmenus and buttons for the parameters tab
  $( "#parametersBusStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#parametersRioStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                             .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#parametersZoneStart" ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#parametersByType"    ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                             .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#buttonSoakTestOn"    ).button().click( function(){ parametersZonesSendCommand( this ); } );
  $( "#buttonSoakTestOff"   ).button().click( function(){ parametersZonesSendCommand( this ); } );
  $( "#buttonPartSetOn"     ).button().click( function(){ parametersZonesSendCommand( this ); } );
  $( "#buttonPartSetOff"    ).button().click( function(){ parametersZonesSendCommand( this ); } );
  //
  // Set the callbacks for the selectmenu's on the parameters tab
  $( "#parametersBusStart"  ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); parametersZonesOnMenuSelect( this, ui ); } );
  $( "#parametersRioStart"  ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); parametersZonesOnMenuSelect( this, ui ); } );
  $( "#parametersZoneStart" ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); parametersZonesOnMenuSelect( this, ui ); } );
  $( "#parametersByType"    ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); parametersZonesOnMenuSelect( this, ui ); } );
  //
  // Display the initialy selected zone from the selectmenus
  $( "#parametersZonesSelectedStart" ).html( parseInt( $( "#parametersBusStart" ).val() ) + parseInt( $( "#parametersRioStart" ).val() ) + parseInt( $( "#parametersZoneStart" ).val() ) );
  parametersZonesHasStart = true;
  //
  //////////////////////////////////////
  // Initialize Zones Programming tab //
  //////////////////////////////////////
  //
  // Create selectmenus and buttons for the program tab
  $( "#programBusStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#programRioStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#programZoneStart" ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#programState"     ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflowProgramZoneState" );
  $( "#programArea"      ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#programType"      ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#programDesc"      ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#programButton"    ).button().click( function(){ programZonesSendCommand( this ); } );
  //
  ////////////////////////
  // Initialize Outputs //
  ////////////////////////
  //
  // Create selectmenus and buttons for the outputs set/unset tab
  $( "#outputBusStart"   ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#outputRioStart"   ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#outputOpStart"    ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#outputBusEnd"     ).selectmenu( { disabled: true, position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#outputRioEnd"     ).selectmenu( { disabled: true, position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#outputOpEnd"      ).selectmenu( { disabled: true, position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#outputByType"     ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#outputByTypeArea" ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                          .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#buttonOutputSet"    ).button().click( function(){ outputsSetSendCommand( true ); } );
  $( "#buttonOutputUnset"  ).button().click( function(){ outputsSetSendCommand( false ); } );
  //
  // Set the callbacks for the selectmenu's on the outputs set/unset tab
  $( "#outputBusStart"   ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); outputsSetOnMenuSelect( this, ui ); } );
  $( "#outputRioStart"   ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); outputsSetOnMenuSelect( this, ui ); } );
  $( "#outputOpStart"    ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); outputsSetOnMenuSelect( this, ui ); } );
  $( "#outputBusEnd"     ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); outputsSetOnMenuSelect( this, ui ); } );
  $( "#outputRioEnd"     ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); outputsSetOnMenuSelect( this, ui ); } );
  $( "#outputOpEnd"      ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); outputsSetOnMenuSelect( this, ui ); } );
  $( "#outputByType"     ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); outputsSetOnMenuSelect( this, ui ); } );
  $( "#outputByTypeArea" ).on( "selectmenuselect", function( event, ui ) { event.preventDefault(); outputsSetOnMenuSelect( this, ui ); } );
  //
  // Display the initialy selected zone from the selectmenus
  $( "#outputsSetSelectedStart" ).html( parseInt( $( "#outputBusStart" ).val() ) + parseInt( $( "#outputRioStart" ).val() ) + parseInt( $( "#outputOpStart" ).val() ) );
  $( "#outputBusEnd, #outputRioEnd, #outputOpEnd" ).selectmenu( "enable" );
  outputsSetHasStart = true;
  //
  ///////////////////////////////////
  // Initialize Outputs Status tab //
  ///////////////////////////////////
  //
  $( "#statusOutputsBusStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  $( "#statusOutputsRioStart"  ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } )
                                .selectmenu( "menuWidget" ).addClass( "menuselectOverflow" );
  $( "#statusOutputsOutputStart" ).selectmenu( { position: { my: "left top", at: "left bottom", collision: "flipfit" } } );
  //
  $( "#statusOutputsButtonUpdate" ).button().click( function(){ displayRioOutputStatesSendCommand( this ); } );
  //
  $( "#anchorStatusOutput" ).on( "click", function(){ clearRioOutputStates(); });
  $( "#anchorOutput" ).on( "click", function(){ clearRioOutputStates(); });
  $( "#statusOutputsBusStart, #statusOutputsRioStart, #statusOutputsOutputStart" ).on( "selectmenuchange", function(){
    clearRioOutputStates();
  });
  //
  ///////////////////////////////////////////////////////////////
  // initialize the dialog for displaying the websocket status //
  ///////////////////////////////////////////////////////////////
  $( "#SocketStatus" ).dialog(
    {
      title:		"openGalaxy",
      autoOpen:		true,
      resizable:	false,
      draggable:	true,
      modal:		false,
      width:		400,
      height:		150,
      position:		SocketStatus_default_position,
      open: 		function() {
			  // this Hides the close button 
			  $( this ).parent().children().children( ".ui-dialog-titlebar-close" ).hide();
			  // Initialize the help menu
			  $( "#SocketStatus-Menu" ).menu();
			  // Toggle the help menu when user clickes on the 'MenuToggle'
			  $( "#SocketStatus-MenuToggle" ).on( "click", function() { $( "#SocketStatus-Menu" ).toggleClass( "show" ); } );
			  // Set the handler for select events from the menu
			  $( "#SocketStatus-Menu" ).on( "menuselect", SocketStatus_MenuSelectEvent );
			},
    beforeClose:	function( event, ui ) { event.preventDefault(); return false; } // This cancels the closing of the dialog
    }
  );
  //
  $( "#defaultDialog" ).dialog(
    {
      autoOpen:		false,
      resizable:	true,
      draggable:	true,
      modal:		true,
      width:		500,
      height:		250,
      position:		{ my: "center", at: "center", of: "#Desktop" },
      buttons:		{
			  Close: function() {
			    $( this ).dialog( "close" );
          SocketStatus_SetCommandStatus( "Idle", "ui-state-active", "green", 0 );
			  }
			}
    }
  );
  //
  $( "#reloadDialog" ).dialog(
    {
      title:		"openGalaxy server restart",
      autoOpen:		false,
      resizable:	false,
      draggable:	true,
      modal:		true,
      width:		400,
      height:		200,
      position:		{ my: "center", at: "center", of: "#Desktop" },
      buttons:		{
			  Reload: function() {
			    $( this ).dialog( "close" );
          location.reload(true);
			  }
			}
    }
  );
  //
  $( "#openGalaxy-About" ).dialog(
    {
      title:		"About openGalaxy",
      autoOpen:		false,
      resizable:	true,
      draggable:	true,
      modal:		false,
      width:		550,
      height:		450,
      position:		{ my: "center", at: "center", of: "#Desktop" }
    }
  );
  //
  $( "#json-dialog" ).dialog(
    {
      title:		"JSON",
      autoOpen:		false,
      resizable:	true,
      draggable:	true,
      modal:		false,
      width:		500,
      height:		450,
      position:		{ my: "center", at: "center", of: "#Desktop" }
    }
  );
  //
  $( "#openGalaxy-cli" ).dialog(
    {
      title:		"Commander",
      autoOpen:		false,
      resizable:	false,
      draggable:	true,
      modal:		false,
      width:		600,
      height:		110,
      position:		{ my: "center", at: "center", of: "#Desktop" }
    }
  );
  //
  $( "#loginDialog" ).dialog(
    {
      title: "Please provide credentials to execute commands.",
      autoOpen: false,
      resizable: false,
      draggable: true,
      modal: false,
      width: 450,
      height: 230,
      position: { my: "center", at: "center", of: "#Desktop" },
      open: function () {
        // assign id/classes to the Enter button
        var buttonPane$ = $(this).siblings('.ui-dialog-buttonpane');
        var okButton = buttonPane$.find('button:contains("Enter")');
        okButton.addClass('ui-priority-primary');
        okButton.attr('id', 'loginDialogButton');
      },
      close: function () {
        // empty the inputs
        document.getElementById('loginDialog_username').value = "";
        document.getElementById('loginDialog_password').value = "";
      },
      buttons: {
        Enter: function() {
          // send the credentials
          socket_commander.send(
            session_id + "\n" +
            document.getElementById('loginDialog_username').value + "\n" +
            document.getElementById('loginDialog_password').value
          );
          $( this ).dialog( "close" );
        }
      }
    }
  );
  //
  //////////////////////////////////////////////////////////////
  // Handle the enter key for the commander and login dialogs //
  //////////////////////////////////////////////////////////////
  $(document).on("keypress", function (e) {
    var x = e || window.event;
    var key = (x.keyCode || x.which);
    // Catch the enter keypres
    if(key == 13 || key == 3){
      var c = "";
      // If it originated from the 'commander' its input is not empty
      var s = document.getElementById('commander_input').value;
      if( s.toString() != c.toString() ) {
        send( s ); // execute the command
        document.getElementById('commander_input').value = ""; // empty the input
      }
      // Test if it was the login dialog's username input
      s = document.getElementById('loginDialog_username').value;
      if( s.toString() != c.toString() ) {
        $("#loginDialogButton").click();
      }
      // Test if it was the login dialog's password input
      s = document.getElementById('loginDialog_password').value;
      if( s.toString() != c.toString() ) {
        $("#loginDialogButton").click();
      }
    }
  });
  //
  ///////////////////////////////
  // Initialize the websockets //
  ///////////////////////////////
  Websocket_Connect();
  //
  ////////////////////////////////////////
  // Scale the page after initial setup //
  ////////////////////////////////////////
  resize_me();
  //
});

