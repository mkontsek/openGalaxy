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
 * Everything for dealing with the 'commander' websocket
 */

#ifndef __OPENGALAXY_CLIENT_COMMANDER_H__
#define __OPENGALAXY_CLIENT_COMMANDER_H__

#include <stdbool.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

extern GMutex commander_mutex;

//
// All possible typeId values received (in the JSON data)
//
typedef enum {
  JSON_STANDARD_REPLY = 1,
  JSON_HELP_REPLY,
  JSON_AREA_ARMED_STATE,
  JSON_ALL_AREA_ARMED_STATE,
  JSON_AREA_ALARM_STATE,
  JSON_ALL_AREA_ALARM_STATE,
  JSON_AREA_READY_STATE,
  JSON_ALL_AREA_READY_STATE,
  JSON_ZONE_OMIT_STATE,
  JSON_ZONE_STATE,
  JSON_ALL_ZONE_READY_STATE,
  JSON_ALL_ZONE_ALARM_STATE,
  JSON_ALL_ZONE_OPEN_STATE,
  JSON_ALL_ZONE_TAMPER_STATE,
  JSON_ALL_ZONE_R_STATE,
  JSON_ALL_ZONE_OMIT_STATE,
  JSON_ALL_OUTPUT_STATE,
  JSON_POLL_REPLY,
  JSON_AUTHORIZATION_REQUIRED,
  JSON_AUTHENTICATION_ACCEPTED,
  JSON_FMT_COUNT
} JSON_typeId;


//
// All possible values in JSON objects received by the commander protocol
// (ie. not every field is filled for a given received JSON object,
// it all depends on the value of typeId )
//
typedef struct commander_reply_t {
  int           typeId;
  char          *typeDesc;
  int           success;
  char          *command;
  char          *text;
  int           areaState;
  unsigned char areaStates[32];
  int           zoneNumber;
  int           omitState;
  int           zoneState;
  unsigned char zoneStates[65];
  unsigned char outputStates[32];
  int           panelIsOnline;
  int           haveAreaState;
  int           haveZoneState;
  int           haveOutputState;
  char          *raw; // points back to commander_reply_list->msg ( set by Commander_AddJSON(), not json_parse_opengalaxy_commander() )
} commander_reply;


// This is what the (internal) list of received JSON data looks like
typedef struct commander_reply_list_t {
   char *msg;                           // the raw JSON data received
   struct commander_reply_t *decoded;   // the decoded data
   struct commander_reply_list_t *next; // next item in the list
} commander_reply_list;


// This is what a callback for the diffrent typeId's in the received JSON data should look like
typedef void (*commander_callback)(struct commander_reply_t *);


int Commander_Init( void );
void Commander_Exit( void );

// Add a JSON object to be processed (called from websocket.c)
void Commander_AddMessage( const char *fmt, ... );
void Websocket_AddMessage( const char *fmt, ... );

// Free a struct commander_reply_t
void Commander_FreeReply( struct commander_reply_t *r );

// (un)registeres callbacks to be called upon arrival of a specific typeId
bool Commander_RegisterCallback( JSON_typeId typeId, commander_callback callback );
bool Commander_UnRegisterCallback( JSON_typeId typeId, commander_callback callback );

#endif

