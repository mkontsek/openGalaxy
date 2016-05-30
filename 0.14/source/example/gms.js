// Global variables
var GMS_pending_alarms_last_id = -1;          // id of the last obj added to GMS-Pending-Alarms-Table
var GMS_pending_alarms_update_time_ms = 2000; // Try to update the GMS-Pending-Alarms-Table every X ms
var GMS_pending_alarms_update_mutex = 0;      // 1 during updating of GMS-Pending-Alarms-Table
var GMS_pending_alarms_empty_string = '';     // String used for empty table fields
var GMS_pending_alarms_x_filler = 0;          // width to make the GMS-Pending-Alarms-Dialog-??_x_filler classes (dynamicly initialised)

function AJAXerror( jqxhr )
///
/// Displays errors from AJAX transfers
///
{
  $('#GMS-Error-Dialog').parent().find( '.ui-dialog-titlebar' ).html( 'Error during AJAX data transfer' );
  $('#GMS-Error-Dialog-inner').html(
    '<p style="color:red;">' +
      jqxhr.responseText +
    '</p>'
  );
  $('#GMS-Error-Dialog').dialog( "open" );
}


function GMS_pending_alarm_onclick( _this )
///
/// Onlick event handler for items in the GMS-Pending-Alarms-Table html table
///
{
  // Inhoud van de ID cell in de tabel ( dit is de ID van de row in de SQL tabel: 'SIA-Messages' )
  var rowID = $(_this).find( '.rowID' ).html();
  alert("Dit is MySQL row id: " + rowID );
}


function GMS_pending_alarm_mouseover( _this )
///
/// Mouseover event handler for items in the GMS-Pending-Alarms-Table html table
///
{
 $(_this).removeClass('ui-state-default');
 $(_this).addClass('ui-state-hover');
}


function GMS_pending_alarm_mouseout( _this )
///
/// Mouseout event handler for items in the GMS-Pending-Alarms-Table html table
///
{
 $(_this).removeClass('ui-state-hover');
 $(_this).addClass('ui-state-default');
}


function GMS_insert_pending_alarm( obj )
///
/// Adds a single entry to the top of the 'GMS-Pending-Alarm-Table' html table.
///
{
  if(obj) {
    //
    // Remember what message ID was added last
    GMS_pending_alarms_last_id = parseInt( obj.id )
    // 
    // Replace empty table values with a default string
    if( ! obj.EventAddressNumber ) obj.EventAddressNumber = GMS_pending_alarms_empty_string;
    if( ! obj.SubscriberID ) obj.SubscriberID = GMS_pending_alarms_empty_string;
    if( ! obj.AreaID ) obj.AreaID = GMS_pending_alarms_empty_string;
    if( ! obj.PeripheralID ) obj.PeripheralID = GMS_pending_alarms_empty_string;
    //
    // Add the SIA message to the top of the html table
    $('#GMS-Pending-Alarms-Table > tbody:first').prepend(
      '<tr class="ui-state-default" '+
       'onmouseover="GMS_pending_alarm_mouseover(this)" '+
       'onmouseout="GMS_pending_alarm_mouseout(this)" '+
       'onclick="GMS_pending_alarm_onclick(this)"'+
      '>' +
      '<td class="rowID" style="display:none;">'    + obj.id                 + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td1">'  + obj.timeindex          + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td2">'  + obj.AccountID          + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td3">'  + obj.EventCode          + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td4">'  + obj.EventName          + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td5">'  + obj.ASCII              + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td6">'  + obj.EventDesc          + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td7">'  + obj.EventAddressType   + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td8">'  + obj.EventAddressNumber + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td9">'  + obj.SubscriberID       + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td10">' + obj.AreaID             + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td11">' + obj.PeripheralID       + '</td>' +
      '<td class="GMS-Pending-Alarms-Dialog-td_x_filler"></td>' +
      '</tr>'
    );
    //
    // Scale the width of the td x_filler class to the new value
    $( ".GMS-Pending-Alarms-Dialog-td_x_filler" ).css( "width", GMS_pending_alarms_x_filler );
  }
}


function GMS_get_pending_alarms( id )
///
/// Loads all messages (starting with ID 'id') from the
/// database and inserts them into a html table.
///
/// (The resulting object returned by the AJAX call is
/// empty when there are no messages to return)
///
{
  $.ajax({
    url: 'get-sia-messages.php?id=' + id,
    type: 'GET',
    dataType: 'json',
    error:  function( jqxhr ){
      GMS_pending_alarms_update_mutex = 0; // reset our mutex
      AJAXerror( jqxhr );
    },
    success: function( objs ){
      $( objs ).each( function(){
        GMS_insert_pending_alarm( this );
      });
      GMS_pending_alarms_update_mutex = 0; // reset our mutex
    }
  });
}


function GMS_update_pending_alarms()
///
/// Tries to update the html table with pending alarm messages every X ms
///
{
  
  if( GMS_pending_alarms_update_mutex == 0 ){ // Allready updating?
    GMS_pending_alarms_update_mutex = 1;      // No, set our mutex so we do'nt re-enter the update loop.
    // Try to get/add any messages with an id larger then the last one added to the html table.
    GMS_get_pending_alarms( GMS_pending_alarms_last_id + 1 );
  }
  // Try to update again in X miliseconds
  setTimeout( GMS_update_pending_alarms, GMS_pending_alarms_update_time_ms );
}


$(document).ready(function(){
  //
  // Used for positioning the dialogs
  var Xmax = $(window).width();
  var Ymax = $(window).height();
  //
  /////////////////////////////////////////////////////////
  // initialize the dialog for displaying error messages //
  /////////////////////////////////////////////////////////
  //
  $( "#GMS-Error-Dialog" ).dialog({
    autoOpen: false,
    resizable: true,
    width: 450,
    height: 200,
    modal: true,
    buttons: {
      "Ok": function() {
        $( this ).dialog( "close" );
      }
    },
    close: function() {
      location.reload();
    },
    open: function(){
      var titlebar = $( this ).parent().find( '.ui-dialog-titlebar' );
      //
      // Append an extra icon to the titlebar
      if( $( this ).parent().find( '#GMS-Error-Dialog-titlebar' ).length == 0 ){ // Only append if not appended before...
        titlebar.prepend(
          '<span id="GMS-Error-Dialog-titlebar" class="GMS-Error-Dialog-extra_icon ui-icon ui-icon-alert"></span>'
        );
      }
    }
  });
  //
  ///////////////////////////////////////////////////////
  // initialize the dialog for displaying the settings //
  ///////////////////////////////////////////////////////
  //
  $("#GMS-Settings-Dialog").dialog({
    autoOpen: true,
    resizable: false,
    draggable: true,
    modal: false,
    width: 250,
    height: 140,
    position: { my: "left top", at: "left top", of: $('#bodyGMS') },
    buttons: {
      "Apply": function() {
        $.ajax({
          url : 'settings.php?theme=' + $('#jqui_theme :selected').text(),
          type: 'POST',
          error: AJAXerror,
          success: function(){ // reload page on success
            location.reload();
          }
        });
      }
    },
    open: function(){
      $(this).parent().children().children(".ui-dialog-titlebar-close").hide(); // this Hides the close button 
    },
    beforeClose: function( event, ui ) { return false; /* This cancels the closing of the dialog */ }
  });
  //
  /////////////////////////////////////////////////////////////////
  // initialize the dialog for displaying pending alarm messages //
  /////////////////////////////////////////////////////////////////
  //
  $("#GMS-Pending-Alarms-Dialog").dialog({
    autoOpen: true,
    resizable: true,
    draggable: true,
    modal: false,
    width: Xmax - 10,//(Xmax - 10 >= 1790 + 30) ? 1790 + 30 : Xmax - 10,
    height: 600,
    position: { my: "center bottom", at: "center bottom", of: $('#bodyGMS') },
    open: function(){
      $(this).parent().children().children(".ui-dialog-titlebar-close").hide(); // this Hides the close button 
      //
      // With to add to the table to make it fit the width of the dialog
      GMS_pending_alarms_x_filler = parseInt($( ".GMS-Pending-Alarms-Dialog-outer_div " ).css( "width" )) -
                                    parseInt($( ".GMS-Pending-Alarms-Dialog-outer_table " ).css( "width" ));
      if( GMS_pending_alarms_x_filler < 0 ) GMS_pending_alarms_x_filler = 0;
      //
      // Set the new width of the table header
      $( ".GMS-Pending-Alarms-Dialog-th_x_filler" ).css( "width", GMS_pending_alarms_x_filler );
    },
    beforeClose: function( event, ui ) { return false; /* This cancels the closing of the dialog */ }
  });
  //
  // Kickstart updating the 'GMS-Pending-Alarm-Table' html table
  GMS_update_pending_alarms();
});

