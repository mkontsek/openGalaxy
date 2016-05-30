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

#ifndef __OPENGALAXY_CLIENT_AREAS_H__
#define __OPENGALAXY_CLIENT_AREAS_H__

#include <gtk/gtk.h>

//
// Possible area states as returned in the JSON data
//
typedef enum {
  area_ready_state_unset = 0, // AREA x READY
  area_ready_state_set,
  area_ready_state_partial,
  area_ready_state_ready,
  area_ready_state_locked,
  area_ready_state_unknown = -1,
  area_armed_state_unset = 0, // AREA x STATE
  area_armed_state_set,
  area_armed_state_partial,
  area_armed_state_unknown = -1
} json_area_ready_state, json_area_armed_state; 

typedef enum {
  area_alarm_state_normal = 0, // AREA x ALARM
  area_alarm_state_alarm,
  area_alarm_state_reset_required,
  area_alarm_state_unknown = -1
} json_area_alarm_state;


typedef struct area_grid_t {
  int                    number;       // the area number 1 .. 32
  int                    selected;     // nonzero if the area is selected
  json_area_armed_state  armed;        // current armed state
  json_area_alarm_state  alarm;        // current alarm state
  json_area_ready_state  ready;        // current ready state
  int                    trouble;      // current trouble/tamper state
  // UI widgets for this area
  GtkWidget              *event;       // (parent of the container widget) -> events and css for mouse enter/leave + events for mouseclicks and css for selected status
  GtkWidget              *container;   // (parent of the overlay widget) -> css for armed status
  GtkOverlay             *overlay;     // (1st child of container widget)
  GtkWidget              *container2;  // (1st child of the overlay widget) -> css for alarm status
  // overlayed widgets
  GtkWidget              *overlay_selection_add;
  GtkWidget              *overlay_selection_remove;
  GtkWidget              *overlay_selection_selected;
  GtkWidget              *overlay_area_unknown;
  GtkWidget              *overlay_area_unknown_img;
  GtkWidget              *overlay_area_set;
  GtkWidget              *overlay_area_set_img;
  GtkWidget              *overlay_area_unset;
  GtkWidget              *overlay_area_unset_img;
  GtkWidget              *overlay_area_partset;
  GtkWidget              *overlay_area_partset_img;
  GtkWidget              *overlay_status_alarm;
  GtkWidget              *overlay_status_alarm_img;
  GtkWidget              *overlay_status_normal;
  GtkWidget              *overlay_status_normal_img;
  GtkWidget              *overlay_status_not_ready;
  GtkWidget              *overlay_status_not_ready_img;
  GtkWidget              *overlay_status_ready;
  GtkWidget              *overlay_status_ready_img;
  GtkWidget              *overlay_status_reset_required;
  GtkWidget              *overlay_status_reset_required_img;
  GtkWidget              *overlay_status_sabotage;
  GtkWidget              *overlay_status_sabotage_img;
} area_grid;

//
// Area states as used by the set_area_ui_xxx() functions
//
typedef enum {
  AREA_STATUS_UNKNOWN        = 0,
  AREA_STATUS_NORMAL         = 1 << 0,
  AREA_STATUS_ALARM          = 1 << 1,
  AREA_STATUS_NOT_READY      = 1 << 2,
  AREA_STATUS_READY          = 1 << 3,
  AREA_STATUS_RESET_REQUIRED = 1 << 4,
  AREA_STATUS_SABOTAGE       = 1 << 5
} area_status;

typedef enum {
  AREA_ARMED_UNKNOWN = 0,
  AREA_ARMED_YES     = 1 << 0,
  AREA_ARMED_NO      = 1 << 1,
  AREA_ARMED_PARTIAL = 1 << 2
} area_armed_status;


// user data passed to the cbArea_Grid_TimeoutScaleAreas() function
extern struct TimeoutScaleAreas_UserData_t {
  int width;
  int height;
} TimeoutScaleAreas_UserData;


// 'tag' the GTK timer for cbArea_Grid_TimeoutScaleAreas() is connected to
extern guint TimeoutScaleAreas_Tag;


// callback for when the mainWindow receives a GDK_CONFIGURE (window resize) event
gboolean G_MODULE_EXPORT cbArea_Grid_TimeoutScaleAreas( gpointer user_data );


// Loads glade xml data for the areas notebook tab and
//  sets up signal/event callbacks used on the areas notebook tab
int Area_Init( GtkBuilder *builder );

#endif

