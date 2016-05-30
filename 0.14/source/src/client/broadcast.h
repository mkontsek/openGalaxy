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
 * Deal with incomming messages on the 'broadcast' websocket
 */

#ifndef __OPENGALAXY_CLIENT_BROADCAST_H__
#define __OPENGALAXY_CLIENT_BROADCAST_H__

#include <stdbool.h>

//
// Received JSON data by BroadcastConsole_printf()
//
typedef struct pending_sia_message_t {
  char *msg; // Message received by the broadcast protocol (JSON)
  struct pending_sia_message_t *next;
} pending_sia_message;

//
// Decoded SIA message as returned by json_parse_opengalaxy_broadcast()
//
typedef struct sia_event_t {
  unsigned int AccountID;
  char *EventCode;
  char *EventName;
  char *EventDesc;
  char *EventAddressType;
  char *Date;
  char *Time;
  char *Raw;
  unsigned int EventAddressNumber;
  int have_EventAddressNumber;
  char *ASCII;
  int have_ASCII;
  unsigned int SubscriberID;
  int have_SubscriberID;
  unsigned int AreaID;
  int have_AreaID;
  unsigned int PeripheralID;
  int have_PeripheralID;
  unsigned int AutomatedID;
  int have_AutomatedID;
  unsigned int TelephoneID;
  int have_TelephoneID;
  unsigned int Level;
  int have_Level;
  unsigned int Value;
  int have_Value;
  unsigned int Path;
  int have_Path;
  unsigned int RouteGroup;
  int have_RouteGroup;
  unsigned int SubSubscriber;
  int have_SubSubscriber;
  struct sia_event_t *next;
} sia_event;

typedef struct sia_message_list_t {
  struct sia_event_t *msg;
  struct sia_message_list_t *next;
} sia_message_list;


typedef void (*sia_callback)(struct sia_event_t *);

int SIA_Init( void );
void SIA_Exit( void );

void SIA_AddMessage( const char *fmt, ... );
void xSIA_AddMessage( struct sia_event_t *s );
void SIA_FreeEvent( struct sia_event_t *e );

bool SIA_RegisterCallback( const char *lettercode, const sia_callback callback );
bool SIA_UnRegisterCallback( const sia_callback callback );

#endif

