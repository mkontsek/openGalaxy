/* This file is part of openGalaxy.
 *
 * opengalaxy - a SIA receiver for Galaxy security control panels.
 * Copyright (C) 2015 - 2016 Alexander Bruines <alexander.bruines@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * as published by the Free Software Foundation, or (at your option)
 * any later version.
 *
 * In addition, as a special exception, the author of this program
 * gives permission to link the code of its release with the OpenSSL
 * project's "OpenSSL" library (or with modified versions of it that
 * use the same license as the "OpenSSL" library), and distribute the
 * linked executables. You must obey the GNU General Public License
 * in all respects for all of the code used other than "OpenSSL".
 * If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so.
 * If you do not wish to do so, delete this exception statement
 * from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Advanced synoptic panel with area control
 */

#include "atomic.h"

#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib/gprintf.h>
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include "areas.h"
#include "opengalaxy-client.h"
#include "log.h"
#include "support.h"
#include "connect.h"
#include "commander.h"
#include "websocket.h"
#include "broadcast.h"
#include "client_area_images.h"

#define HAVE_VISIBLE_HOLDUP_ALARM 1
#define HAVE_VISIBLE_PANIC_ALARM 1

// Sets the state for an individual area on the areas notebook tab
static void Area_Grid_UiSetArmedStatus( int area, area_armed_status s );
static void Area_Grid_UiSetAlarmStatus( int area, area_status s );

// Area grid (initialized by Area_Init())
static area_grid areas[32];

GtkWidget *togglebuttonAllAreas; // (de)select all areas toggle button
GtkWidget *buttonForce; // Forced area(s) arm button
GtkWidget *buttonPartial; // Partset area(s) button
GtkWidget *buttonArm; // Arm area(s) button
GtkWidget *buttonDisarm; // Disarm area(s) button
GtkWidget *buttonReset; // Reset area(s) button
GtkWidget *buttonAbort; // Abort arming area(s) button

static bool doToggleAllAreas = true; // update areas selected state by cbArea_ButtonToggleAll() yes/no

static bool allAreasSelected = false; // used to determine if we should send 'area 0 xxx' commands to the panel

// Used by cbArea_Grid_TimeoutGetAlarmStatus()
static guint TimeoutGetAlarmStatus_Tag = 0;            // the id tag for the timeout
static int TimeoutGetAlarmStatus_AllreadyWaiting = 0;  // allready waiting for alarm status when nonzero


static int TimeoutGetArmedStatus_AllreadyWaiting = 0;  // allready waiting for armed status when nonzero


//
// Called in response to 'area 0 alarm' executed by:
//   cbArea_Grid_OnlineNotify()
//   cbArea_Grid_TimeoutGetAlarmStatus()
//
static void cbArea_Grid_JSON_ALL_AREA_ALARM_STATE( struct commander_reply_t *ev )
{
  // Update UI area alarm states
  for( int t = 0; t < 32; t++ ){
    areas[t].alarm = ev->areaStates[t];
    switch( ev->areaStates[t] ){
      case area_alarm_state_normal:
        areas[t].alarm = area_alarm_state_normal;
        Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_NORMAL );
        break;
      case area_alarm_state_alarm:
        areas[t].alarm = area_alarm_state_alarm;
        if( areas[t-1].trouble == 0){
          Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_ALARM );
        }
        else {
          Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_SABOTAGE );
        }
        break;
      case area_alarm_state_reset_required:
        areas[t].alarm = area_alarm_state_reset_required;
        Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_RESET_REQUIRED );
        break;
      default:
        areas[t].alarm = area_alarm_state_unknown;
        break;
    }
  }
  TimeoutGetAlarmStatus_AllreadyWaiting = 0; // Reset this for cbArea_Grid_TimeoutGetAlarmStatus()
}


//
// Called in response to 'area 0 state' executed by:
//  cbArea_Grid_OnlineNotify()
//  cbArea_ButtonArm()
//
static void cbArea_Grid_JSON_ALL_AREA_ARMED_STATE( struct commander_reply_t *ev )
{
  // Update UI area armed states
  for( int t = 0; t < 32; t++ ){
    areas[t].armed = ev->areaStates[t];
    switch( ev->areaStates[t] ){
      case area_armed_state_unset:
        areas[t].armed = area_armed_state_unset;
        Area_Grid_UiSetArmedStatus( t + 1, AREA_ARMED_NO );
        break;
      case area_armed_state_set:
        areas[t].armed = area_armed_state_set;
        Area_Grid_UiSetArmedStatus( t + 1, AREA_ARMED_YES );
        break;
      case area_armed_state_partial:
        areas[t].armed = area_armed_state_partial;
        Area_Grid_UiSetArmedStatus( t + 1, AREA_ARMED_PARTIAL );
        break;
      default:
        areas[t].armed = area_armed_state_unknown;
        break;
    }
  }
  TimeoutGetArmedStatus_AllreadyWaiting = 0;
}


//
// Registered as connect_callback for the 'online' event
// Called whenever a connection to an openGalaxy server is established/restored
//
static void cbArea_Grid_OnlineNotify( void )
{
  // Get the initial armed/alarm states from the panel
  Websocket_SendCommand( "AREA 0 STATE" ); // get armed state
  Websocket_SendCommand( "AREA 0 ALARM" ); // get ready or alarm state (depending on firmware version)

  // Start polling the areas 'ready' states
  Websocket_SendCommand( "POLL ADD AREAS" );
  Websocket_SendCommand( "POLL ON 20" );
}


//
// Registered as connect_callback for the 'offline' event
// Called whenever a connection to an openGalaxy server is lost
//
static void cbArea_Grid_OfflineNotify( void )
{
  // Set all areas status to UNKNOWN
  for( int t = 0; t < 32; t++ ){
    areas[t].armed = area_armed_state_unknown;
    areas[t].alarm = area_alarm_state_unknown;
    areas[t].ready = area_ready_state_unknown;
    Area_Grid_UiSetArmedStatus( t + 1, AREA_ARMED_UNKNOWN );
    Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_UNKNOWN );
  }
}


//
// Registered as commander_callback for JSON_POLL_REPLY
// Called whenever a JSON data block with typeId JSON_POLL_REPLY was received
//
static void cbArea_Grid_JSON_POLL_REPLY( struct commander_reply_t *ev )
{
  if( ev->haveAreaState ){
    for( int t = 0; t < 32; t++ ){
      areas[t].ready = ev->areaStates[t];
      switch( ev->areaStates[t] ){
        case area_ready_state_set:
          areas[t].ready = area_ready_state_set;                  // Set the new current ready state.
          if( areas[t].armed != area_armed_state_set ){           // Does it match with what we know about armed status?
            areas[t].armed = area_armed_state_set;                // If not update it.
            Area_Grid_UiSetArmedStatus( t + 1, AREA_ARMED_YES );  // And for the UI
          }
          if( areas[t].alarm == area_alarm_state_normal ){
            Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_NORMAL );
          }
          break;
        case area_ready_state_partial:
          areas[t].ready = area_ready_state_partial;                  // Set the new current ready state.
          if( areas[t].armed != area_armed_state_partial ){           // Does it match with what we know about armed status?
            areas[t].armed = area_armed_state_partial;                // If not update it.
            Area_Grid_UiSetArmedStatus( t + 1, AREA_ARMED_PARTIAL );  // And for the UI
          }
          if( areas[t].alarm == area_alarm_state_normal ){
            Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_NORMAL );
          }
          break;
        case area_ready_state_ready:
          areas[t].ready = area_ready_state_ready;
          if( areas[t].alarm == area_alarm_state_normal ){
            Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_READY );
          }
          break;
        case area_ready_state_locked:
          areas[t].ready = area_ready_state_locked;
          // fixme: Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_LOCKED );
          break;
        case area_ready_state_unset:
        default:
          areas[t].ready = ev->areaStates[t];
          if( areas[t].alarm == area_alarm_state_normal ){
            Area_Grid_UiSetAlarmStatus( t + 1, AREA_STATUS_NOT_READY );
          }
          break;
      }
    }    
  }
}


//
// Gets the area alarm status after a timeout
// called by:
//   cbArea_Grid_SIA_opening_report()
//   cbArea_Grid_SIA_partial_opening_report()
//   cbArea_Grid_SIA_alarm_opening_report()
//   cbArea_Grid_SIA_burglary_cancel_report()
//
gboolean G_MODULE_EXPORT cbArea_Grid_TimeoutGetAlarmStatus( gpointer user_data )
{
  if( TimeoutGetAlarmStatus_AllreadyWaiting == 0 ){
    TimeoutGetAlarmStatus_AllreadyWaiting = 1;
    // This will end up executing cbArea_Grid_JSON_ALL_AREA_ALARM_STATE()
    // which will also reset TimeoutGetAlarmStatus_AllreadyWaiting to 0
    Websocket_SendCommand( "AREA 0 ALARM" ); // get areas alarm state
  }
  TimeoutGetAlarmStatus_Tag = 0;
  return FALSE;
}


//
// called when an opening report is received (sia code OP)
//
static void cbArea_Grid_SIA_opening_report( struct sia_event_t *sia )
{
  int t = sia->AreaID;
  if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
  Area_Grid_UiSetArmedStatus( t, AREA_ARMED_NO );
  areas[t-1].armed = area_armed_state_unset;
  if( areas[t-1].alarm != area_alarm_state_normal ){
    Area_Grid_UiSetAlarmStatus( t, AREA_STATUS_RESET_REQUIRED );
  }

  // If no other report is received within 3 seconds then update the areas alarm status
  if( TimeoutGetAlarmStatus_Tag ) g_source_remove( TimeoutGetAlarmStatus_Tag ); // Cancel any pending timeout
  TimeoutGetAlarmStatus_Tag = g_timeout_add_seconds( 3, cbArea_Grid_TimeoutGetAlarmStatus, NULL );
}


//
// called when an opening report is received (sia code OG)
//
static void cbArea_Grid_SIA_partial_opening_report( struct sia_event_t *sia )
{
  int t = sia->AreaID;
  if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
  Area_Grid_UiSetArmedStatus( t, AREA_ARMED_NO );
  areas[t-1].armed = area_armed_state_unset;

  // If no other report is received within 3 seconds then update the areas alarm status
  if( TimeoutGetAlarmStatus_Tag ) g_source_remove( TimeoutGetAlarmStatus_Tag ); // Cancel any pending timeout
  TimeoutGetAlarmStatus_Tag = g_timeout_add_seconds( 3, cbArea_Grid_TimeoutGetAlarmStatus, NULL );
}


//
// called when an opening report is received from an area in the alarm state (sia code OR)
//
static void cbArea_Grid_SIA_alarm_opening_report( struct sia_event_t *sia )
{
  int t = sia->AreaID;
  if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
  Area_Grid_UiSetArmedStatus( t, AREA_ARMED_NO );
  areas[t-1].armed = area_armed_state_unset;

  // If no other report is received within 3 seconds then update the areas alarm status
  if( TimeoutGetAlarmStatus_Tag ) g_source_remove( TimeoutGetAlarmStatus_Tag ); // Cancel any pending timeout
  TimeoutGetAlarmStatus_Tag = g_timeout_add_seconds( 3, cbArea_Grid_TimeoutGetAlarmStatus, NULL );
}

//
// called when a burglary alarm has been cancelled (sia code BC)
//
static void cbArea_Grid_SIA_burglary_cancel_report( struct sia_event_t *sia )
{
  // If no other report is received within 3 seconds then update the areas alarm status
  int t = sia->AreaID;
  if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
  areas[t-1].trouble = 0;
  if( TimeoutGetAlarmStatus_Tag ) g_source_remove( TimeoutGetAlarmStatus_Tag ); // Cancel any pending timeout
  TimeoutGetAlarmStatus_Tag = g_timeout_add_seconds( 3, cbArea_Grid_TimeoutGetAlarmStatus, NULL );
}


//
// called when a closing report is received (sia code CL, CA and CP)
//
static void cbArea_Grid_SIA_closing_report( struct sia_event_t *sia )
{
  int t = sia->AreaID;
  if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
  Area_Grid_UiSetArmedStatus( t, AREA_ARMED_YES );
  areas[t-1].armed = area_armed_state_set;
}


//
// called when a partial closing report is received (sia code CG)
//
static void cbArea_Grid_SIA_partial_closing_report( struct sia_event_t *sia )
{
  int t = sia->AreaID;
  if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
  Area_Grid_UiSetArmedStatus( t, AREA_ARMED_PARTIAL );
  areas[t-1].armed = area_armed_state_partial;
}


//
// called when an alarm report is received
//
static void cbArea_Grid_SIA_alarm_report( struct sia_event_t *sia )
{
  if( sia != NULL ) {
    int t = 0;
    if( sia->have_AreaID != 0 ) t = sia->AreaID;
    if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
    Area_Grid_UiSetAlarmStatus( t, AREA_STATUS_ALARM );
    areas[t-1].alarm = area_alarm_state_alarm;
  }
}


//
// called when an tamper/trouble report is received
//
static void cbArea_Grid_SIA_trouble_report( struct sia_event_t *sia )
{
  if( sia != NULL ) {
    int t = 0;
    if( sia->have_AreaID != 0 ) t = sia->AreaID;
    if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
    Area_Grid_UiSetAlarmStatus( t, AREA_STATUS_SABOTAGE );
    areas[t-1].alarm = area_alarm_state_alarm;
    areas[t-1].trouble++;
  }
}


//
// called when an tamper/trouble restore report is received
//
static void cbArea_Grid_SIA_trouble_restore_report( struct sia_event_t *sia )
{
  if( sia != NULL ) {
    int t = 0;
    if( sia->have_AreaID != 0 ) t = sia->AreaID;
    if( t == 0 ) t++; // this is for when areas mode (blokkenmode) is not set in the Galaxy
    areas[t-1].alarm = area_alarm_state_normal;
    if( areas[t-1].trouble > 0) areas[t-1].trouble--;
    if( areas[t-1].trouble == 0) Area_Grid_UiSetAlarmStatus( t, AREA_STATUS_NORMAL );
  }
}


//
// Sets the ui armed status for an area
//
static void Area_Grid_UiSetArmedStatus( int area, area_armed_status s )
{
  area_grid *a = &areas[area-1];

  gtk_widget_set_opacity( a->overlay_area_unknown, 0.0 );
  gtk_widget_set_opacity( a->overlay_area_set, 0.0 );
  gtk_widget_set_opacity( a->overlay_area_unset, 0.0 );
  gtk_widget_set_opacity( a->overlay_area_partset, 0.0 );

  _gtk_widget_remove_class( a->container, "area_armed_unknown" );
  _gtk_widget_remove_class( a->container, "area_armed_yes" );
  _gtk_widget_remove_class( a->container, "area_armed_no" );
  _gtk_widget_remove_class( a->container, "area_armed_partial" );

  if( s == AREA_ARMED_UNKNOWN ){
    gtk_widget_set_opacity( a->overlay_area_unknown, 1.0 );
    _gtk_widget_add_class( a->container, "area_armed_unknown" );
  }
  else {
    if( s & AREA_ARMED_YES ){
      gtk_widget_set_opacity( a->overlay_area_set, 1.0 );
      _gtk_widget_add_class( a->container, "area_armed_yes" );
    }
    if( s & AREA_ARMED_NO ){
      gtk_widget_set_opacity( a->overlay_area_unset, 1.0 );
      _gtk_widget_add_class( a->container, "area_armed_no" );
    }
    if( s & AREA_ARMED_PARTIAL ){
      gtk_widget_set_opacity( a->overlay_area_partset, 1.0 );
      _gtk_widget_add_class( a->container, "area_armed_partial" );
    }
  }
}


//
// Sets the ui alarm status for an area
//
static void Area_Grid_UiSetAlarmStatus( int area, area_status s )
{
  area_grid *a = &areas[area-1];

  gtk_widget_set_opacity( a->overlay_status_alarm, 0.0 );
  gtk_widget_set_opacity( a->overlay_status_normal, 0.0 );
  gtk_widget_set_opacity( a->overlay_status_not_ready, 0.0 );
  gtk_widget_set_opacity( a->overlay_status_ready, 0.0 );
  gtk_widget_set_opacity( a->overlay_status_reset_required, 0.0 );
  gtk_widget_set_opacity( a->overlay_status_sabotage, 0.0 );

  _gtk_widget_remove_class( a->container2, "area_unknown" );
  _gtk_widget_remove_class( a->container2, "area_normal" );
  _gtk_widget_remove_class( a->container2, "area_alarm" );
  _gtk_widget_remove_class( a->container2, "area_not_ready" );
  _gtk_widget_remove_class( a->container2, "area_ready" );
  _gtk_widget_remove_class( a->container2, "area_reset_required" );
  _gtk_widget_remove_class( a->container2, "area_area_sabotage" );

  if( s == AREA_STATUS_UNKNOWN ){
    _gtk_widget_add_class( a->container2, "area_unknown" );
  }
  else {
    if( s & AREA_STATUS_NORMAL ){
      gtk_widget_set_opacity( a->overlay_status_normal, 1.0 );
      _gtk_widget_add_class( a->container2, "area_normal" );
    }
    if( s & AREA_STATUS_ALARM ){
      gtk_widget_set_opacity( a->overlay_status_alarm, 1.0 );
      _gtk_widget_add_class( a->container2, "area_alarm" );
    }
    if( s & AREA_STATUS_NOT_READY ){
      gtk_widget_set_opacity( a->overlay_status_not_ready, 1.0 );
      _gtk_widget_add_class( a->container2, "area_not_ready" );
    }
    if( s & AREA_STATUS_READY ){
      gtk_widget_set_opacity( a->overlay_status_ready, 1.0 );
      _gtk_widget_add_class( a->container2, "area_ready" );
    }
    if( s & AREA_STATUS_RESET_REQUIRED ){
      gtk_widget_set_opacity( a->overlay_status_reset_required, 1.0 );
      _gtk_widget_add_class( a->container2, "area_reset_required" );
    }
    if( s & AREA_STATUS_SABOTAGE ){
      gtk_widget_set_opacity( a->overlay_status_sabotage, 1.0 );
      _gtk_widget_add_class( a->container2, "area_sabotage" );
    }
  }
}


//
// Tests if all areas are selected and sets togglebuttonAllAreas in the appropriate displayed state
//
static void Area_Grid_ToggleAllHelper( void )
{
  gboolean state = TRUE;
  int t;
  for( t = 0; t < 32; t++ ){
    if( areas[t].selected == 0 ){
      state = FALSE;
      allAreasSelected = false;
      break;
    }
  }
  if( state != gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON( togglebuttonAllAreas ) ) ){
    doToggleAllAreas = false;
    gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( togglebuttonAllAreas ), state ); // this triggers a 'clicked' event
  }
}


//
// Callback function that is called when the user clicked on an area
//
gboolean G_MODULE_EXPORT cbArea_Grid_ButtonPressNotify( GtkWidget *widget, GdkEvent *event, gpointer user_data )
{
  gboolean event_handled = TRUE;

  area_grid *area = (area_grid*)user_data;
//  struct GdkEventButton *e = (void*)event;

  Log_printf( "area %d button_press_event -> ", area->number );

  switch( event->type ){
    case GDK_BUTTON_PRESS:
      Log_printf( "single click\n" );
      area->selected = (area->selected & 1) ^ 1;
      if( area->selected == 0 ){
        if( _gtk_widget_has_class( area->event, "area_selected" ) == TRUE ){
          _gtk_widget_remove_class( area->event, "area_selected" );
        }
        gtk_widget_set_opacity( area->overlay_selection_add, 1.0 );
        gtk_widget_set_opacity( area->overlay_selection_remove, 0.0 );
        gtk_widget_set_opacity( area->overlay_selection_selected, 0.0 );
      }
      else {
        if( _gtk_widget_has_class( area->event, "area_selected" ) == FALSE ){
          _gtk_widget_add_class( area->event, "area_selected" );
        }
        gtk_widget_set_opacity( area->overlay_selection_add, 0.0 );
        gtk_widget_set_opacity( area->overlay_selection_remove, 1.0 );
        gtk_widget_set_opacity( area->overlay_selection_selected, 1.0 );
      }
      Area_Grid_ToggleAllHelper();
      break;
    case GDK_2BUTTON_PRESS:
      Log_printf( "double click\n" );
      break;
    case GDK_3BUTTON_PRESS:
      Log_printf( "triple click\n" );
      break;
    default:
      Log_printf( "unexpected event type %d\n", event->type );
      event_handled = FALSE;
      break;
  }

  return event_handled;
}


//
// Callback functions that are called when the mouse pointer enters/leaves an area
//

gboolean G_MODULE_EXPORT cbArea_Grid_EnterNotify( GtkWidget *widget, GdkEvent *event, gpointer user_data )
{
  gboolean event_handled = TRUE;

  area_grid *area = (area_grid*)user_data;

  if( area->selected == 0 ){
    gtk_widget_set_opacity( area->overlay_selection_add, 1.0 );
  }
  else {
    gtk_widget_set_opacity( area->overlay_selection_remove, 1.0 );
  }

  _gtk_widget_add_class( area->event, "area_mouse_over" );
  _gtk_widget_remove_class( area->event, "area_event_default" );

  return event_handled;
}

gboolean G_MODULE_EXPORT cbArea_Grid_LeaveNotify( GtkWidget *widget, GdkEvent *event, gpointer user_data )
{
  gboolean event_handled = TRUE;

  area_grid *area = (area_grid*)user_data;

  gtk_widget_set_opacity( area->overlay_selection_add, 0.0 );
  gtk_widget_set_opacity( area->overlay_selection_remove, 0.0 );

  _gtk_widget_add_class( area->event, "area_event_default" );
  _gtk_widget_remove_class( area->event, "area_mouse_over" );

  if( area->selected == 0 ){
    if( _gtk_widget_has_class( area->event, "area_selected" ) == TRUE ){
      _gtk_widget_remove_class( area->event, "area_selected" );
    }
  }

  return event_handled;
}


//
// Fuction that is called 10 ms after the last GDK_RESOURCE event received
//  by cb_window_configure() and scales the items on the area notebook tab
//  according to the mainWindow size
//

struct TimeoutScaleAreas_UserData_t TimeoutScaleAreas_UserData;
guint TimeoutScaleAreas_Tag = 0;

gboolean G_MODULE_EXPORT cbArea_Grid_TimeoutScaleAreas( gpointer user_data )
{
  int t;
  struct TimeoutScaleAreas_UserData_t *scale = (struct TimeoutScaleAreas_UserData_t*)user_data;

  //
  // Calculate onscreen size and scale the area elements accordingly
  //
  GValue size = G_VALUE_INIT;
  g_value_init( &size, G_TYPE_INT );

  if( (scale->width >= 1250) && (scale->height >= 850) ){
    g_value_set_int( &size, GTK_ICON_SIZE_DIALOG ); // Set 'large' size 48x48
  }
  else {
   if( (scale->width >= 1000) && (scale->height >= 780) ){
     g_value_set_int( &size, GTK_ICON_SIZE_DND ); // Set 'medium' size 32x32
    }
    else {
      g_value_set_int( &size, GTK_ICON_SIZE_BUTTON ); // Set 'small' size 16x16
    }
  }

  for( t = 0; t < 32; t++ ){
    area_grid *area = &areas[t];

    gtk_widget_hide( GTK_WIDGET( area->overlay_area_unknown_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_area_set_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_area_unset_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_area_partset_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_status_alarm_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_status_normal_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_status_not_ready_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_status_ready_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_status_reset_required_img ) );
    gtk_widget_hide( GTK_WIDGET( area->overlay_status_sabotage_img ) );

    g_object_set_property( G_OBJECT( area->overlay_area_unknown_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_area_set_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_area_unset_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_area_partset_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_status_alarm_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_status_normal_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_status_not_ready_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_status_ready_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_status_reset_required_img ), "icon-size", &size );
    g_object_set_property( G_OBJECT( area->overlay_status_sabotage_img ), "icon-size", &size );

    gtk_widget_show( GTK_WIDGET( area->overlay_area_unknown_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_area_set_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_area_unset_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_area_partset_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_status_alarm_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_status_normal_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_status_not_ready_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_status_ready_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_status_reset_required_img ) );
    gtk_widget_show( GTK_WIDGET( area->overlay_status_sabotage_img ) );
  }
  TimeoutScaleAreas_Tag = 0;
  return FALSE;
}


//
// Callback for the 'select all areas' toggle button
//
void G_MODULE_EXPORT cbArea_ButtonToggleAll( GtkWidget *_this, gpointer user_data )
{
  if( doToggleAllAreas == true ){
    int t;
    gboolean selectAll = gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON( _this ) ); // TRUE when pressed
    Log_printf( "Toggle all areas -> %d\n", selectAll );
    for( t = 0; t < 32; t++ ){
      area_grid *area = &areas[t];
      if( selectAll == TRUE ){
        allAreasSelected = true;
        area->selected = 1;
        if( _gtk_widget_has_class( area->event, "area_selected" ) == FALSE ){
          _gtk_widget_add_class( area->event, "area_selected" );
        }
        gtk_widget_set_opacity( area->overlay_selection_selected, 1.0 );
      }
      else {
        allAreasSelected = false;
        area->selected = 0;
        if( _gtk_widget_has_class( area->event, "area_selected" ) == TRUE ){
          _gtk_widget_remove_class( area->event, "area_selected" );
        }
        gtk_widget_set_opacity( area->overlay_selection_selected, 0.0 );
      }
    }
  }
  doToggleAllAreas = true;
}


//
// unselects an area (0..31 !) (after pressing a command button)
//
static void Area_Grid_UnselectArea( int n )
{
  areas[n].selected = 0;
  if( _gtk_widget_has_class( areas[n].event, "area_selected" ) == TRUE ){
    _gtk_widget_remove_class( areas[n].event, "area_selected" );
  }
  gtk_widget_set_opacity( areas[n].overlay_selection_selected, 0.0 );
}


void G_MODULE_EXPORT cbArea_ButtonForce( GtkWidget *widget, gpointer data )
{
  int t;
  int selected = 0;
  if( Websocket_IsConnected() ){
    if( allAreasSelected ){
      // unselect after command
      for( t = 0; t < 32; t++ ){
        Area_Grid_UnselectArea( t );
      }
      Websocket_SendCommand( "AREA 0 FORCE" );
    }
    else {
      for( t = 0; t < 32; t++ ){
        if( areas[t].selected ) {
          Area_Grid_UnselectArea( t ); // unselect after command
          Websocket_SendCommand( "AREA %d FORCE", areas[t].number );
          selected = 1;
        }
      }
      if( selected == 0 ){
        InfoMessageBox( mainWindow, "Error", "Select at least 1 area before you do that!" );
      }
    }
    Area_Grid_ToggleAllHelper();
    // Get the armed state when we are done arming areas just in case we missed a SIA message
    if( TimeoutGetArmedStatus_AllreadyWaiting == 0 ){
      TimeoutGetArmedStatus_AllreadyWaiting = 1;
      Websocket_SendCommand( "AREA 0 STATE" );
    }
  }
  else {
    InfoMessageBox( mainWindow, "Error", "Cannot send commands while offline!" );
  }
}


void G_MODULE_EXPORT cbArea_ButtonPartial( GtkWidget *widget, gpointer data )
{
  int t;
  int selected = 0;

  if( Websocket_IsConnected() ){
    if( allAreasSelected ){
      // unselect after command
      for( t = 0; t < 32; t++ ){
        Area_Grid_UnselectArea( t );
      }
      Websocket_SendCommand( "AREA 0 PARTIAL" );
    }
    else {
      for( t = 0; t < 32; t++ ){
        if( areas[t].selected ) {
          Area_Grid_UnselectArea( t ); // unselect after command
          Websocket_SendCommand( "AREA %d PARTIAL", areas[t].number );
          selected = 1;
        }
      }
      if( selected == 0 ){
        InfoMessageBox( mainWindow, "Error", "Select at least 1 area before you do that!" );
      }
    }
    Area_Grid_ToggleAllHelper();
    // Get the armed state when we are done arming areas just in case we missed a SIA message
    if( TimeoutGetArmedStatus_AllreadyWaiting == 0 ){
      TimeoutGetArmedStatus_AllreadyWaiting = 1;
      Websocket_SendCommand( "AREA 0 STATE" );
    }
  }
  else {
    InfoMessageBox( mainWindow, "Error", "Cannot send commands while offline!" );
  }
}


void G_MODULE_EXPORT cbArea_ButtonArm( GtkWidget *widget, gpointer data )
{
  int t;
  int selected = 0;

  if( Websocket_IsConnected() ){
    if( allAreasSelected ){
      // unselect area after command
      for( t = 0; t < 32; t++ ){
        Area_Grid_UnselectArea( t );
      }
      Websocket_SendCommand( "AREA 0 SET" );
    }
    else {
      for( t = 0; t < 32; t++ ){
        if( areas[t].selected ) {
          Area_Grid_UnselectArea( t ); // unselect area after command
          Websocket_SendCommand( "AREA %d SET", areas[t].number );
          selected = 1;
        }
      }
      if( selected == 0 ){
        InfoMessageBox( mainWindow, "Error", "Select at least 1 area before you do that!" );
      }
    }

    // Update 'select all areas' button
    Area_Grid_ToggleAllHelper();

    // Get the armed state when we are done arming areas just in case we missed a SIA message
    if( TimeoutGetArmedStatus_AllreadyWaiting == 0 ){
      TimeoutGetArmedStatus_AllreadyWaiting = 1;
      Websocket_SendCommand( "AREA 0 STATE" );
    }

  }
  else {
    InfoMessageBox( mainWindow, "Error", "Cannot send commands while offline!" );
  }
}


void G_MODULE_EXPORT cbArea_ButtonDisarm( GtkWidget *widget, gpointer data )
{
  int t;
  int selected = 0;

  if( Websocket_IsConnected() ){
    if( allAreasSelected ){
      // unselect after command
      for( t = 0; t < 32; t++ ){
        Area_Grid_UnselectArea( t );
      }
      Websocket_SendCommand( "AREA 0 UNSET" );
    }
    else {
      for( t = 0; t < 32; t++ ){
        if( areas[t].selected ) {
          Area_Grid_UnselectArea( t ); // unselect after command
          Websocket_SendCommand( "AREA %d UNSET", areas[t].number );
          selected = 1;
        }
      }
      if( selected == 0 ){
        InfoMessageBox( mainWindow, "Error", "Select at least 1 area before you do that!" );
      }
    }
    Area_Grid_ToggleAllHelper();
    // Get the armed state when we are done arming areas just in case we missed a SIA message
    if( TimeoutGetArmedStatus_AllreadyWaiting == 0 ){
      TimeoutGetArmedStatus_AllreadyWaiting = 1;
      Websocket_SendCommand( "AREA 0 STATE" );
    }
  }
  else {
    InfoMessageBox( mainWindow, "Error", "Cannot send commands while offline!" );
  }
}


void G_MODULE_EXPORT cbArea_ButtonReset( GtkWidget *widget, gpointer data )
{
  int t;
  int selected = 0;

  if( Websocket_IsConnected() ){
    if( allAreasSelected ){
      // unselect after command
      for( t = 0; t < 32; t++ ){
        Area_Grid_UnselectArea( t );
      }
      Websocket_SendCommand( "AREA 0 RESET" );
    }
    else {
      for( t = 0; t < 32; t++ ){
        if( areas[t].selected ) {
          Area_Grid_UnselectArea( t ); // unselect after command
          Websocket_SendCommand( "AREA %d RESET", areas[t].number );
          selected = 1;
        }
      }
      if( selected == 0 ){
        InfoMessageBox( mainWindow, "Error", "Select at least 1 area before you do that!" );
      }
    }
    Area_Grid_ToggleAllHelper();
    // Get the armed state when we are done arming areas just in case we missed a SIA message
    if( TimeoutGetArmedStatus_AllreadyWaiting == 0 ){
      TimeoutGetArmedStatus_AllreadyWaiting = 1;
      Websocket_SendCommand( "AREA 0 STATE" );
    }
  }
  else {
    InfoMessageBox( mainWindow, "Error", "Cannot send commands while offline!" );
  }
}


void G_MODULE_EXPORT cbArea_ButtonAbort( GtkWidget *widget, gpointer data )
{
  int t;
  int selected = 0;

  if( Websocket_IsConnected() ){
    if( allAreasSelected ){
      // unselect after command
      for( t = 0; t < 32; t++ ){
        Area_Grid_UnselectArea( t );
      }
      Websocket_SendCommand( "AREA 0 ABORT" );
    }
    else {
      for( t = 0; t < 32; t++ ){
        if( areas[t].selected ) {
          Area_Grid_UnselectArea( t ); // unselect after command
          Websocket_SendCommand( "AREA %d ABORT", areas[t].number );
          selected = 1;
        }
      }
      if( selected == 0 ){
        InfoMessageBox( mainWindow, "Error", "Select at least 1 area before you do that!" );
      }
    }
    Area_Grid_ToggleAllHelper();
    // Get the armed state when we are done arming areas just in case we missed a SIA message
    if( TimeoutGetArmedStatus_AllreadyWaiting == 0 ){
      TimeoutGetArmedStatus_AllreadyWaiting = 1;
      Websocket_SendCommand( "AREA 0 STATE" );
    }
  }
  else {
    InfoMessageBox( mainWindow, "Error", "Cannot send commands while offline!" );
  }
}


//
// Initialize the Areas notebook tab
//
int Area_Init( GtkBuilder *builder )
{
  int t;

  // get button widgets
  togglebuttonAllAreas = GTK_WIDGET( gtk_builder_get_object( builder, "togglebuttonAllAreas" ) );
  buttonForce          = GTK_WIDGET( gtk_builder_get_object( builder, "buttonAreasForce" ) );
  buttonArm            = GTK_WIDGET( gtk_builder_get_object( builder, "buttonAreasArm" ) );
  buttonDisarm         = GTK_WIDGET( gtk_builder_get_object( builder, "buttonAreasDisarm" ) );
  buttonReset          = GTK_WIDGET( gtk_builder_get_object( builder, "buttonAreasReset" ) );
  buttonAbort          = GTK_WIDGET( gtk_builder_get_object( builder, "buttonAreasAbort" ) );
  buttonPartial        = GTK_WIDGET( gtk_builder_get_object( builder, "buttonAreasPartial" ) );

  // Loop through the areas area_grid and initialize each array member
  for( t = 0; t < 32; t++ ){
    area_grid *area = &areas[t];
    char buf[32];
    static const char *fmt_event_area = "eventbox-area%02d";
    static const char *fmt_container = "box-area%02d";
    static const char *fmt_overlay = "overlay%d";
    static const char *fmt_container2 = "box-overlay%02d";

    memset( area, 0, sizeof( area_grid) );

    // - the widget that receives the mouse/button signals
    snprintf( buf, 32, fmt_event_area, t + 1);
    area->event = GTK_WIDGET( gtk_builder_get_object( builder, buf ) );

    // - the widget that contains the (main) background color for this area
    snprintf( buf, 32, fmt_container, t + 1 );
    area->container = GTK_WIDGET( gtk_builder_get_object( builder, buf ) );

    // - the overlay to display status information
    snprintf( buf, 32, fmt_overlay, t + 1);
    area->overlay = GTK_OVERLAY( gtk_builder_get_object( builder, buf ) );

    // - the widget that contains the visual elements (area name and description)
    snprintf( buf, 32, fmt_container2, t + 1 );
    area->container2 = GTK_WIDGET( gtk_builder_get_object( builder, buf ) );

    // Create a fresh GtkBuilder object to load the overlay images for _each_ area
    GtkBuilder *image_builder = gtk_builder_new();
    if( 0 == gtk_builder_add_from_string( image_builder, (const gchar*)client_area_images_glade, client_area_images_glade_len, NULL ) ){
      Log_printf( "ERROR: main( 'Gtkuilder could not load area images.' );\n" );
      return(0);
    }
    // Get the individual eventboxes and images for each area,
    // the eventbox is used to catch enter/leave notifications for the mousepointer)
    area->overlay_selection_add             = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-selection-add" ) );
    area->overlay_selection_remove          = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-selection-remove" ) );
    area->overlay_selection_selected        = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-selection-selected" ) );
    area->overlay_area_unknown              = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-area-unknown" ) );
    area->overlay_area_unknown_img          = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-area-unknown-img" ) );
    area->overlay_area_set                  = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-area-set" ) );
    area->overlay_area_set_img              = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-area-set-img" ) );
    area->overlay_area_unset                = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-area-unset" ) );
    area->overlay_area_unset_img            = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-area-unset-img" ) );
    area->overlay_area_partset              = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-area-partset" ) );
    area->overlay_area_partset_img          = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-area-partset-img" ) );
    area->overlay_status_alarm              = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-alarm" ) );
    area->overlay_status_alarm_img          = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-alarm-img" ) );
    area->overlay_status_normal             = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-normal" ) );
    area->overlay_status_normal_img         = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-normal-img" ) );
    area->overlay_status_not_ready          = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-not-ready" ) );
    area->overlay_status_not_ready_img      = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-not-ready-img" ) );
    area->overlay_status_ready              = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-ready" ) );
    area->overlay_status_ready_img          = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-ready-img" ) );
    area->overlay_status_reset_required     = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-reset-required" ) );
    area->overlay_status_reset_required_img = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-reset-required-img" ) );
    area->overlay_status_sabotage           = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-sabotage" ) );
    area->overlay_status_sabotage_img       = GTK_WIDGET( gtk_builder_get_object( image_builder, "image-status-sabotage-img" ) );

    // Add the images to each area as an overlay
    // (please note that the order matters here)
    gtk_overlay_add_overlay( area->overlay, area->overlay_area_unknown );
    gtk_overlay_add_overlay( area->overlay, area->overlay_area_set );
    gtk_overlay_add_overlay( area->overlay, area->overlay_area_unset );
    gtk_overlay_add_overlay( area->overlay, area->overlay_area_partset );
    gtk_overlay_add_overlay( area->overlay, area->overlay_status_alarm );
    gtk_overlay_add_overlay( area->overlay, area->overlay_status_normal );
    gtk_overlay_add_overlay( area->overlay, area->overlay_status_not_ready );
    gtk_overlay_add_overlay( area->overlay, area->overlay_status_ready );
    gtk_overlay_add_overlay( area->overlay, area->overlay_status_reset_required );
    gtk_overlay_add_overlay( area->overlay, area->overlay_status_sabotage );
    gtk_overlay_add_overlay( area->overlay, area->overlay_selection_selected );
    gtk_overlay_add_overlay( area->overlay, area->overlay_selection_add );
    gtk_overlay_add_overlay( area->overlay, area->overlay_selection_remove );

    // Set the location each overlay image:
    // - selection overlays go in the upper right corner
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_selection_add ), GTK_ALIGN_END );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_selection_add ), GTK_ALIGN_START );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_selection_remove ), GTK_ALIGN_END );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_selection_remove ), GTK_ALIGN_START );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_selection_selected ), GTK_ALIGN_END );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_selection_selected ), GTK_ALIGN_START );
    gtk_widget_set_margin_top( GTK_WIDGET( area->overlay_selection_selected ), 8 );
    gtk_widget_set_margin_end( GTK_WIDGET( area->overlay_selection_selected ), 8 );
    // - area 'set' information in the upper left corner
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_area_unknown ), GTK_ALIGN_START );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_area_unknown ), GTK_ALIGN_START );
    gtk_widget_set_margin_top( GTK_WIDGET( area->overlay_area_unknown ), 4 );
    gtk_widget_set_margin_start( GTK_WIDGET( area->overlay_area_unknown ), 4 );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_area_set ), GTK_ALIGN_START );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_area_set ), GTK_ALIGN_START );
    gtk_widget_set_margin_top( GTK_WIDGET( area->overlay_area_set ), 4 );
    gtk_widget_set_margin_start( GTK_WIDGET( area->overlay_area_set ), 4 );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_area_unset ), GTK_ALIGN_START );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_area_unset ), GTK_ALIGN_START );
    gtk_widget_set_margin_top( GTK_WIDGET( area->overlay_area_unset ), 4 );
    gtk_widget_set_margin_start( GTK_WIDGET( area->overlay_area_unset ), 4 );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_area_partset ), GTK_ALIGN_START );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_area_partset ), GTK_ALIGN_START );
    gtk_widget_set_margin_top( GTK_WIDGET( area->overlay_area_partset ), 4 );
    gtk_widget_set_margin_start( GTK_WIDGET( area->overlay_area_partset ), 4 );
    // - area 'status' information is displayed in the center
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_status_alarm ), GTK_ALIGN_CENTER );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_status_alarm ), GTK_ALIGN_END );
    gtk_widget_set_margin_bottom( GTK_WIDGET( area->overlay_status_alarm ), 4 );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_status_normal ), GTK_ALIGN_CENTER );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_status_normal ), GTK_ALIGN_END );
    gtk_widget_set_margin_bottom( GTK_WIDGET( area->overlay_status_normal ), 4 );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_status_not_ready ), GTK_ALIGN_CENTER );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_status_not_ready ), GTK_ALIGN_END );
    gtk_widget_set_margin_bottom( GTK_WIDGET( area->overlay_status_not_ready ), 4 );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_status_ready ), GTK_ALIGN_CENTER );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_status_ready ), GTK_ALIGN_END );
    gtk_widget_set_margin_bottom( GTK_WIDGET( area->overlay_status_ready ), 4 );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_status_reset_required ), GTK_ALIGN_CENTER );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_status_reset_required ), GTK_ALIGN_END );
    gtk_widget_set_margin_bottom( GTK_WIDGET( area->overlay_status_reset_required ), 4 );
    gtk_widget_set_halign( GTK_WIDGET( area->overlay_status_sabotage ), GTK_ALIGN_CENTER );
    gtk_widget_set_valign( GTK_WIDGET( area->overlay_status_sabotage ), GTK_ALIGN_END );
    gtk_widget_set_margin_bottom( GTK_WIDGET( area->overlay_status_sabotage ), 4 );

    // Set initial opacity for the area overlay images (completely transparent)
    gtk_widget_set_opacity( area->overlay_selection_add, 0.0 );
    gtk_widget_set_opacity( area->overlay_selection_remove, 0.0 );
    gtk_widget_set_opacity( area->overlay_selection_selected, 0.0 );

    // Throw this image_builder away
    g_object_unref( G_OBJECT( image_builder ) );

    // Set (initial) values for:
    area->number = t + 1;                    // - area number
    area->selected = 0;                      // - area is not selected
    area->armed = area_armed_state_unknown;  // - area armed state is unknown
    area->alarm = area_alarm_state_unknown;  // - area alarm state is unknown
    area->ready = area_ready_state_unknown;  // - area ready state is unknown

  }

  //
  // Setup the signal/event handlers
  //

  for( t = 0; t < 32; t++ ){
    area_grid *area = &areas[t];
    gtk_widget_set_events(
      GTK_WIDGET( area->event ),
      GDK_BUTTON_PRESS_MASK |
      GDK_ENTER_NOTIFY_MASK |
      GDK_LEAVE_NOTIFY_MASK
    );
    g_signal_connect( area->event, "button-press-event", G_CALLBACK( cbArea_Grid_ButtonPressNotify ), area );
    g_signal_connect( area->event, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->event, "leave-notify-event", G_CALLBACK( cbArea_Grid_LeaveNotify ), area );

    // Also set the enter-notify-event on the overlay images to counteract the leave-notify-event
    //  when the mousepointer is moved over an overlay icon (but is still inside the current area)
    g_signal_connect( area->overlay_selection_add, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_selection_remove, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_selection_selected, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_area_set, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_area_unset, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_area_partset, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_status_alarm, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_status_normal, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_status_not_ready, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_status_ready, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_status_reset_required, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_status_sabotage, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
    g_signal_connect( area->overlay_area_unknown, "enter-notify-event", G_CALLBACK( cbArea_Grid_EnterNotify ), area );
  }

  // set callbacks for the UI buttons
  g_signal_connect( togglebuttonAllAreas, "clicked", G_CALLBACK( cbArea_ButtonToggleAll ), NULL );
  g_signal_connect( buttonForce, "clicked", G_CALLBACK( cbArea_ButtonForce ), NULL );
  g_signal_connect( buttonPartial, "clicked", G_CALLBACK( cbArea_ButtonPartial ), NULL );
  g_signal_connect( buttonArm, "clicked", G_CALLBACK( cbArea_ButtonArm ), NULL );
  g_signal_connect( buttonDisarm, "clicked", G_CALLBACK( cbArea_ButtonDisarm ), NULL );
  g_signal_connect( buttonReset, "clicked", G_CALLBACK( cbArea_ButtonReset ), NULL );
  g_signal_connect( buttonAbort, "clicked", G_CALLBACK( cbArea_ButtonAbort ), NULL );

  // set callbacks for online/offline events
  Connect_RegisterCallback( connect_event_id_online, cbArea_Grid_OnlineNotify );
  Connect_RegisterCallback( connect_event_id_offline, cbArea_Grid_OfflineNotify );
  Connect_RegisterCallback( connect_event_id_connecting, cbArea_Grid_OfflineNotify );

  // set callbacks for commander events
  Commander_RegisterCallback( JSON_POLL_REPLY, cbArea_Grid_JSON_POLL_REPLY );
  Commander_RegisterCallback( JSON_ALL_AREA_ARMED_STATE, cbArea_Grid_JSON_ALL_AREA_ARMED_STATE );
  Commander_RegisterCallback( JSON_ALL_AREA_ALARM_STATE, cbArea_Grid_JSON_ALL_AREA_ALARM_STATE );

  // set callbacks for SIA events...
  // ...opening
  SIA_RegisterCallback( "OG", cbArea_Grid_SIA_partial_opening_report );
  SIA_RegisterCallback( "OK", cbArea_Grid_SIA_opening_report );
  SIA_RegisterCallback( "OP", cbArea_Grid_SIA_opening_report );
  // ...disarm alarm
  SIA_RegisterCallback( "OR", cbArea_Grid_SIA_alarm_opening_report );
  // ...cancel (reset) alarm
  SIA_RegisterCallback( "BC", cbArea_Grid_SIA_burglary_cancel_report );
  // ...closing
  SIA_RegisterCallback( "CA", cbArea_Grid_SIA_closing_report );
  SIA_RegisterCallback( "CL", cbArea_Grid_SIA_closing_report );
  SIA_RegisterCallback( "CP", cbArea_Grid_SIA_closing_report );
  SIA_RegisterCallback( "CG", cbArea_Grid_SIA_partial_closing_report );
  // ...alarms
  SIA_RegisterCallback( "BA", cbArea_Grid_SIA_alarm_report );
  SIA_RegisterCallback( "DF", cbArea_Grid_SIA_alarm_report );
  SIA_RegisterCallback( "DT", cbArea_Grid_SIA_alarm_report );
  SIA_RegisterCallback( "FA", cbArea_Grid_SIA_alarm_report );
#ifdef HAVE_VISIBLE_HOLDUP_ALARM
  SIA_RegisterCallback( "HA", cbArea_Grid_SIA_alarm_report );
#endif
  SIA_RegisterCallback( "MA", cbArea_Grid_SIA_alarm_report );
#ifdef HAVE_VISIBLE_PANIC_ALARM
  SIA_RegisterCallback( "PA", cbArea_Grid_SIA_alarm_report );
#endif
  SIA_RegisterCallback( "JA", cbArea_Grid_SIA_alarm_report );
  SIA_RegisterCallback( "XQ", cbArea_Grid_SIA_alarm_report );
  // ...tamper/trouble
  SIA_RegisterCallback( "AT", cbArea_Grid_SIA_trouble_report );
  SIA_RegisterCallback( "BT", cbArea_Grid_SIA_trouble_report );
  SIA_RegisterCallback( "FT", cbArea_Grid_SIA_trouble_report );
#ifdef HAVE_VISIBLE_HOLDUP_ALARM
  SIA_RegisterCallback( "HT", cbArea_Grid_SIA_trouble_report );
#endif
  SIA_RegisterCallback( "LT", cbArea_Grid_SIA_trouble_report );
#ifdef HAVE_VISIBLE_PANIC_ALARM
  SIA_RegisterCallback( "PT", cbArea_Grid_SIA_trouble_report );
#endif
  SIA_RegisterCallback( "TA", cbArea_Grid_SIA_trouble_report );
  SIA_RegisterCallback( "XT", cbArea_Grid_SIA_trouble_report );
  SIA_RegisterCallback( "YT", cbArea_Grid_SIA_trouble_report );
  // ...reset alarm
  SIA_RegisterCallback( "AR", cbArea_Grid_SIA_trouble_restore_report );
  SIA_RegisterCallback( "BJ", cbArea_Grid_SIA_trouble_restore_report );
  SIA_RegisterCallback( "FJ", cbArea_Grid_SIA_trouble_restore_report );
#ifdef HAVE_VISIBLE_HOLDUP_ALARM
  SIA_RegisterCallback( "HJ", cbArea_Grid_SIA_trouble_restore_report );
#endif
  SIA_RegisterCallback( "LR", cbArea_Grid_SIA_trouble_restore_report );
#ifdef HAVE_VISIBLE_PANIC_ALARM
  SIA_RegisterCallback( "PJ", cbArea_Grid_SIA_trouble_restore_report );
#endif
  SIA_RegisterCallback( "XR", cbArea_Grid_SIA_trouble_restore_report );
  SIA_RegisterCallback( "YR", cbArea_Grid_SIA_trouble_restore_report );

  return 1;
}

