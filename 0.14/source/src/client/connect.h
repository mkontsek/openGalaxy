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
 * Everything for the connection with the server 
 */

#ifndef __OPENGALAXY_CLIENT_CONNECT_H__
#define __OPENGALAXY_CLIENT_CONNECT_H__

#include <stdbool.h>
#include <glib.h>
#include <gtk/gtk.h>

typedef enum {
  connect_event_id_online = 0,
  connect_event_id_offline,
  connect_event_id_connecting,
  connect_event_id_error
} connect_event_id;

// Callback for when the user selects the 'connect' item from the menu
void G_MODULE_EXPORT cbMenu_websocketConnect( GtkMenuItem *_this, gpointer user_data );

// Callback for when the user selects the 'disconnect' item from the menu.
void G_MODULE_EXPORT cbMenu_websocketDisconnect( GtkMenuItem *_this, gpointer user_data );

// Used by websocket.c to notify a connection status change
void Connect_setStatusOnline( void );
void Connect_setStatusOffline( void );
void Connect_setStatusConnecting( void );
void Connect_setStatusError( void );

// This is what a callback for the diffrent connection states looks like
typedef void (*connect_callback)(void);

// (un)register a callback for a connect_event_id.
bool Connect_RegisterCallback( connect_event_id ev, connect_callback cb );
bool Connect_UnRegisterCallback( connect_event_id ev, connect_callback cb );

// Show the username/password dialog
void Connect_ShowPasswordDialog( const char *session_id );

#endif

