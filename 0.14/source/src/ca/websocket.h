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
 * Functions to connect to an openGalaxy server as client and upload
 * a new set of certificates and keys
 */

#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

#include "atomic.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

enum {
  JSON_SIA_MESSAGE = 0,
  JSON_STANDARD_REPLY,
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
  JSON_AUTHENTICATION_ACCEPTED
};

// function to call for a given websocket status
// these function must not block too long
// members can be NULL
typedef struct WebsocketCallbacks_t {
  void(*connecting)(void* user);
  void(*offline)(void* user);
  void(*online)(void* user);
  void(*receive)(const char* data, void* user);
  void(*connect_error)(const char* address, void* user);
  void* user;
} WebsocketCallbacks;

extern GThread *WebsocketThreadId; // ID for this thread

GThread *Websocket_InitThread(void);
void Websocket_ExitThread(void);

// disconnected: 0
// connected using http: 1
// connected using https: 2
// using client certificate: 3
int Websocket_IsConnected(void);

int Websocket_AsyncConnect(WebsocketCallbacks* cb);
void Websocket_AsyncDisconnect(void);

//
// Sets connection parameters, call before connecting
//
// addr     = URL or IP address or NULL to use the default
// prt      = port number to use or 0 to use the default
// ssl      = nonzero to use SSL
// cert     = the client cert or null
// cert_key = the client cert key or null
// ca       = the ca cert to use
//
void Websocket_SetConnectParameters( char *addr, int prt, int ssl, char* cert, char* cert_key, char *ca );

int Websocket_SendCommand(const char *cmd, ...);
int Websocket_SendCredentials( const char *sid, const char *username, const char *password );

#endif

