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

#include "atomic.h"

#include <stdbool.h>
#include <stdlib.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib.h>
#include <glib/gprintf.h>
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include <string.h>
#include "support.h"
#include "websocket.h"
#include "log.h"
#include "json-decode.h"
#include "commander.h"
#include "connect.h"
#include "opengalaxy-client.h"

static commander_reply_list *commander_messages = NULL;
static int commander_quit = 1;
GMutex commander_mutex;

//
// Lists of callback functions for all possible typeId's.
//
// Each callback in the list of callbacks for a given typeId
//  is called every time a JSON data block with that typeId is received
//

#define DECLARE_TYPEID_CALLBACKS_LIST(typeId)\
  struct typeId##_callbacks_t {\
    commander_callback callback;\
    struct typeId##_callbacks_t *next;\
  } * typeId##_callbacks;

#define INIT_TYPEID_CALLBACKS_LIST(typeId)\
  NULL,

static struct commander_callbacks_list_t {
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_STANDARD_REPLY )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_HELP_REPLY )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_AREA_ARMED_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_AREA_ARMED_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_AREA_ALARM_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_AREA_ALARM_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_AREA_READY_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_AREA_READY_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ZONE_OMIT_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ZONE_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_READY_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_ALARM_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_OPEN_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_TAMPER_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_R_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_OMIT_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_ALL_OUTPUT_STATE )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_POLL_REPLY )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_AUTHORIZATION_REQUIRED )
  DECLARE_TYPEID_CALLBACKS_LIST( JSON_AUTHENTICATION_ACCEPTED )
} lists_of_callbacks = {
  INIT_TYPEID_CALLBACKS_LIST( JSON_STANDARD_REPLY )
  INIT_TYPEID_CALLBACKS_LIST( JSON_HELP_REPLY )
  INIT_TYPEID_CALLBACKS_LIST( JSON_AREA_ARMED_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_AREA_ARMED_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_AREA_ALARM_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_AREA_ALARM_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_AREA_READY_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_AREA_READY_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ZONE_OMIT_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ZONE_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_READY_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_ALARM_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_OPEN_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_TAMPER_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_R_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_ZONE_OMIT_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_ALL_OUTPUT_STATE )
  INIT_TYPEID_CALLBACKS_LIST( JSON_POLL_REPLY )
  INIT_TYPEID_CALLBACKS_LIST( JSON_AUTHORIZATION_REQUIRED )
  INIT_TYPEID_CALLBACKS_LIST( JSON_AUTHENTICATION_ACCEPTED )
};


//
// Free a struct commander_reply_t
//
void Commander_FreeReply( struct commander_reply_t *r )
{
  if( r->typeDesc ) free( r->typeDesc );
  if( r->command ) free( r->command );
  if( r->text ) free( r->text );
  free( r );
}


//
// Sends an UI user command to the server
//
void G_MODULE_EXPORT cbCommander_SendUserCommand(GtkEntry *_this, gpointer user_data)
{
  // Check that we are connected to a server
  if( !Websocket_IsConnected() ){
    InfoMessageBox( GTK_WIDGET( _this ), "Information", "You need to connect to an openGalaxy server before you can do that!" );
    return;
  }

  // clear the (previous) output
  GtkTextIter start, end;
  GtkTextBuffer *buffer = gtk_text_view_get_buffer( commander_output );
  gtk_text_buffer_get_start_iter( buffer, &start );
  gtk_text_buffer_get_end_iter( buffer, &end );
  gtk_text_buffer_delete( buffer, &start, &end );

  // send the command
  Websocket_SendCommand( gtk_entry_get_text( _this ) );

  // clear the text entry
  gtk_entry_set_text( _this, "" );
}


//
// These functions (un)register a callback function that is called
//  everytime a JSON data block is received with the given typeId
//

bool Commander_RegisterCallback( JSON_typeId typeId, commander_callback callback )
{
  bool retv = false;
  g_mutex_lock( &commander_mutex );
  switch( typeId ){

#define REGISTER_TYPEID_CALLBACK(typeId)\
  case typeId : {\
    struct typeId##_callbacks_t *new = malloc( sizeof( struct typeId##_callbacks_t ) );\
    if( new == NULL ) break;\
    new->callback = callback;\
    new->next = lists_of_callbacks.typeId##_callbacks;\
    lists_of_callbacks.typeId##_callbacks = new;\
    retv = true;\
    break;\
  }

    REGISTER_TYPEID_CALLBACK( JSON_STANDARD_REPLY )
    REGISTER_TYPEID_CALLBACK( JSON_HELP_REPLY )
    REGISTER_TYPEID_CALLBACK( JSON_AREA_ARMED_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_AREA_ARMED_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_AREA_ALARM_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_AREA_ALARM_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_AREA_READY_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_AREA_READY_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ZONE_OMIT_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ZONE_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_READY_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_ALARM_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_OPEN_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_TAMPER_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_R_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_OMIT_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_ALL_OUTPUT_STATE )
    REGISTER_TYPEID_CALLBACK( JSON_POLL_REPLY )
    REGISTER_TYPEID_CALLBACK( JSON_AUTHORIZATION_REQUIRED )
    REGISTER_TYPEID_CALLBACK( JSON_AUTHENTICATION_ACCEPTED )
    default: {
      break;
    }
  }
  g_mutex_unlock( &commander_mutex );
  return retv;
}

bool Commander_UnRegisterCallback( JSON_typeId typeId, commander_callback callback )
{
  bool retv = false;
  g_mutex_lock( &commander_mutex );
  switch( typeId ){

#define UNREGISTER_TYPEID_CALLBACK(typeId)\
  case typeId : {\
    struct typeId##_callbacks_t *next, *prev = NULL, *current = lists_of_callbacks.typeId##_callbacks;\
    while( current != NULL ){\
      if( current->callback == callback ){\
        next = current->next;\
        free( current );\
        if( prev ){\
          prev->next = next;\
        }\
        else {\
          lists_of_callbacks.typeId##_callbacks = next;\
        }\
        break;\
      }\
      prev = current;\
      current = current->next;\
    }\
    break;\
  }

    UNREGISTER_TYPEID_CALLBACK( JSON_STANDARD_REPLY )
    UNREGISTER_TYPEID_CALLBACK( JSON_HELP_REPLY )
    UNREGISTER_TYPEID_CALLBACK( JSON_AREA_ARMED_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_AREA_ARMED_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_AREA_ALARM_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_AREA_ALARM_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_AREA_READY_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_AREA_READY_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ZONE_OMIT_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ZONE_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_READY_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_ALARM_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_OPEN_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_TAMPER_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_R_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_ZONE_OMIT_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_ALL_OUTPUT_STATE )
    UNREGISTER_TYPEID_CALLBACK( JSON_POLL_REPLY )
    UNREGISTER_TYPEID_CALLBACK( JSON_AUTHORIZATION_REQUIRED )
    UNREGISTER_TYPEID_CALLBACK( JSON_AUTHENTICATION_ACCEPTED )
    default: {
      break;
    }
  }
  g_mutex_unlock( &commander_mutex );
  return retv;
}


//
// Define the functions that call the callbacks for a given typeId
//

#define DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION(typeId)\
static void exec_##typeId##_callbacks( struct commander_reply_t *reply )\
{\
  struct typeId##_callbacks_t *current = lists_of_callbacks.typeId##_callbacks;\
  while( current != NULL ){\
    current->callback( reply );\
    current = current->next;\
  }\
}

DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_STANDARD_REPLY );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_HELP_REPLY );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_AREA_ARMED_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_AREA_ARMED_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_AREA_ALARM_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_AREA_ALARM_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_AREA_READY_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_AREA_READY_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ZONE_OMIT_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ZONE_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_ZONE_READY_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_ZONE_ALARM_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_ZONE_OPEN_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_ZONE_TAMPER_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_ZONE_R_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_ZONE_OMIT_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_ALL_OUTPUT_STATE );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_POLL_REPLY );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_AUTHORIZATION_REQUIRED );
DEFINE_EXEC_TYPEID_CALLBACKS_FUNCTION( JSON_AUTHENTICATION_ACCEPTED );


//
// These function are registered on program initialisation by default
//

static void default_JSON_STANDARD_REPLY_callback( struct commander_reply_t * decoded )
{
  GtkTextIter iter;
  char text[8192];
  GtkTextBuffer *buffer = gtk_text_view_get_buffer( commander_output );

  snprintf( text, sizeof( text ), "Command: %s\nStatus: %s\n",
    decoded->command,
    decoded->success ? "Ok." : "Error!" 
  );
  gtk_text_buffer_get_end_iter( buffer, &iter );
  gtk_text_buffer_insert( buffer, &iter, text, strlen( text ) );
  if( decoded->success == FALSE ){
    snprintf( text, sizeof( text ), "Reason: %s\n", decoded->text );
    gtk_text_buffer_get_end_iter( buffer, &iter );
    gtk_text_buffer_insert( buffer, &iter, text, strlen( text ) );
  }
}

static void default_JSON_HELP_REPLY_callback( struct commander_reply_t * decoded )
{
  GtkTextIter iter;
  char text[8192];
  GtkTextBuffer *buffer = gtk_text_view_get_buffer( commander_output );

  snprintf( text, sizeof( text ), "Command: %s\n\n", decoded->command );
  gtk_text_buffer_get_end_iter( buffer, &iter );
  gtk_text_buffer_insert( buffer, &iter, text, strlen( text ) );
  gtk_text_buffer_get_end_iter( buffer, &iter );
  gtk_text_buffer_insert( buffer, &iter, decoded->text, strlen( decoded->text ) );
}

static void default_JSON_AUTHORIZATION_REQUIRED_callback( struct commander_reply_t * decoded )
{
  Connect_ShowPasswordDialog( decoded->typeDesc );
}

static void default_JSON_AUTHENTICATION_ACCEPTED_callback( struct commander_reply_t * decoded )
{
  Connect_setStatusOnline();
}

// These default callbacks print the raw JSON object to the commander window

#define DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION(typeId)\
static void default_##typeId##_callback( struct commander_reply_t * decoded )\
{\
  Log_printf( "Default callback: %s", decoded->raw );\
}

DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_AREA_ARMED_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_AREA_ARMED_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_AREA_ALARM_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_AREA_ALARM_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_AREA_READY_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_AREA_READY_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ZONE_OMIT_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ZONE_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_ZONE_READY_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_ZONE_ALARM_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_ZONE_OPEN_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_ZONE_TAMPER_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_ZONE_R_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_ZONE_OMIT_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_ALL_OUTPUT_STATE );
DEFINE_TYPEID_DEFAULT_CALLBACK_FUNCTION( JSON_POLL_REPLY );

//
// Called every second to process pending received messages
//
static gboolean Commander_MessageLoop( gpointer user_data )
{
  g_mutex_lock( &commander_mutex );
  gboolean retv = TRUE;
  commander_reply_list *list = commander_messages, *prev = NULL;
  while( list != NULL ){

    switch( list->decoded->typeId ){

#define DEFINE_PARSER_CASE_TYPEID(typeId)\
  case typeId : {\
    exec_##typeId##_callbacks( list->decoded );\
    break;\
  }

      DEFINE_PARSER_CASE_TYPEID( JSON_STANDARD_REPLY )
      DEFINE_PARSER_CASE_TYPEID( JSON_HELP_REPLY )
      DEFINE_PARSER_CASE_TYPEID( JSON_AREA_ARMED_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_AREA_ARMED_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_AREA_ALARM_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_AREA_ALARM_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_AREA_READY_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_AREA_READY_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ZONE_OMIT_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ZONE_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_ZONE_READY_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_ZONE_ALARM_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_ZONE_OPEN_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_ZONE_TAMPER_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_ZONE_R_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_ZONE_OMIT_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_ALL_OUTPUT_STATE )
      DEFINE_PARSER_CASE_TYPEID( JSON_POLL_REPLY )
      DEFINE_PARSER_CASE_TYPEID( JSON_AUTHORIZATION_REQUIRED )
      DEFINE_PARSER_CASE_TYPEID( JSON_AUTHENTICATION_ACCEPTED )

      default: {
        GtkTextIter iter;
        GtkTextBuffer *buffer = gtk_text_view_get_buffer( commander_output );
        gtk_text_buffer_get_end_iter( buffer, &iter );
        gtk_text_buffer_insert( buffer, &iter, list->msg, strlen( list->msg ) );
        break;
      }
    }

    // Free data and process next message
    prev = list;
    list = list->next;
    if( prev ){
      if( prev->decoded ) Commander_FreeReply( prev->decoded );
      if( prev->msg ) free( prev->msg );
      free( prev );
    }
  }
  commander_messages = NULL;
  if( commander_quit ) retv = FALSE ;
  g_mutex_unlock( &commander_mutex );
  return retv; // continue with the next call or quit this main loop
}


//
// These functions will free the memory for the callbacks list for a given typeId
//
#define DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION(typeId)\
  static void unregister_##typeId##_callbacks_at_exit( void )\
  {\
    g_mutex_lock( &commander_mutex );\
    struct typeId##_callbacks_t *next, *current = lists_of_callbacks.typeId##_callbacks;\
    while( current != NULL ){\
      next = current->next;\
      free( current );\
      current = next;\
    }\
    g_mutex_unlock( &commander_mutex );\
  }
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_STANDARD_REPLY );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_HELP_REPLY );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_AREA_ARMED_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_AREA_ARMED_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_AREA_ALARM_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_AREA_ALARM_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_AREA_READY_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_AREA_READY_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ZONE_OMIT_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ZONE_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_ZONE_READY_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_ZONE_ALARM_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_ZONE_OPEN_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_ZONE_TAMPER_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_ZONE_R_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_ZONE_OMIT_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_ALL_OUTPUT_STATE );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_POLL_REPLY );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_AUTHORIZATION_REQUIRED );
DEFINE_TYPEID_CALLBACKS_AT_EXIT_FUNCTION( JSON_AUTHENTICATION_ACCEPTED );

//
// Initializes the console window for the openGalaxy command protocol
//
int Commander_Init( void )
{

#define REGISTER_DEFAULT_TYPEID_CALLBACK(typeId)\
  Commander_RegisterCallback( typeId , default_##typeId##_callback );

#define UNREGISTER_TYPEID_CALLBACKS_AT_EXIT(typeId)\
  atexit( unregister_##typeId##_callbacks_at_exit );

  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_STANDARD_REPLY )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_HELP_REPLY )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_AREA_ARMED_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_AREA_ARMED_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_AREA_ALARM_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_AREA_ALARM_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_AREA_READY_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_AREA_READY_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ZONE_OMIT_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ZONE_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_ZONE_READY_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_ZONE_ALARM_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_ZONE_OPEN_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_ZONE_TAMPER_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_ZONE_R_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_ZONE_OMIT_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_ALL_OUTPUT_STATE )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_POLL_REPLY )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_AUTHORIZATION_REQUIRED )
  REGISTER_DEFAULT_TYPEID_CALLBACK( JSON_AUTHENTICATION_ACCEPTED )

  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_STANDARD_REPLY )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_HELP_REPLY )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_AREA_ARMED_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_AREA_ARMED_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_AREA_ALARM_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_AREA_ALARM_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_AREA_READY_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_AREA_READY_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ZONE_OMIT_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ZONE_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_ZONE_READY_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_ZONE_ALARM_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_ZONE_OPEN_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_ZONE_TAMPER_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_ZONE_R_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_ZONE_OMIT_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_ALL_OUTPUT_STATE )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_POLL_REPLY )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_AUTHORIZATION_REQUIRED )
  UNREGISTER_TYPEID_CALLBACKS_AT_EXIT( JSON_AUTHENTICATION_ACCEPTED )

  g_mutex_lock( &commander_mutex );
  g_signal_connect( commander_user_cmd, "activate", G_CALLBACK( cbCommander_SendUserCommand ), NULL );
  commander_quit = 0;
  g_mutex_unlock( &commander_mutex );

  // Kickstart message processing
//  g_timeout_add_seconds( 1, Commander_MessageLoop, NULL );
  g_timeout_add( 100, Commander_MessageLoop, NULL );

  return 0;
}


void Commander_Exit( void )
{
  g_mutex_lock( &commander_mutex );
  commander_quit = 1;
  g_mutex_unlock( &commander_mutex );
}

//
// The result of fmt and va_args is assumed to be a JSON object
// received by the commander protocol. It is decoded and the data is 
// added to the commander_messages
//
void Commander_AddMessage( const char *fmt, ... )
{
  if( commander_quit ) return;
  char buf[8192];
  va_list args;
  commander_reply_list *new = malloc( sizeof( commander_reply_list ) );
  va_start( args, fmt );
  g_vsnprintf( buf, 8192, fmt, args );
  va_end( args );
  char *dup = g_strdup( buf );
  if( !new || !dup ){
    if( new ) free( new );
    if( dup ) free( dup );
    return;
  }
  new->msg = dup;
  new->next = NULL;

  new->decoded = JSON_ParseOpenGalaxyCommanderObject( buf );
  if( !new->decoded ){
    if( new ) free( new );
    if( dup ) free( dup );
    return;
  }

  new->decoded->raw = new->msg; // point back to the raw msg

  g_mutex_lock( &commander_mutex );
  if( commander_messages == NULL ){
    commander_messages = new;
  }
  else {
    commander_reply_list *list = commander_messages;
    while( list->next ) list = list->next;
    list->next = new;
  }
  g_mutex_unlock( &commander_mutex );
}

void Websocket_AddMessage( const char *fmt, ... )
{
  if( commander_quit ) return;
  struct sia_event_t *s = NULL;
  char buf[8192];
  va_list args;

  commander_reply_list *cl = malloc( sizeof( commander_reply_list ) );
  va_start( args, fmt );
  g_vsnprintf( buf, 8192, fmt, args );
  va_end( args );
  char *dup = g_strdup( buf );
  if( !cl || !dup ){
    if( cl ) free( cl );
    if( dup ) free( dup );
    return;
  }
  cl->msg = dup;
  cl->next = NULL;

  //cl->decoded = JSON_ParseOpenGalaxyCommanderObject( buf );
  if( JSON_ParseOpenGalaxyWebsocketObject( &s, &cl->decoded, buf ) < 0 ){
    if( s ) xSIA_AddMessage( s );
    if( cl ) free( cl );
    if( dup ) free( dup );
    return;
  }

  if( s ) xSIA_AddMessage( s );

  if( !cl->decoded ){
    if( cl ) free( cl );
    if( dup ) free( dup );
    return;
  }

  cl->decoded->raw = cl->msg; // point back to the raw msg

  g_mutex_lock( &commander_mutex );
  if( commander_messages == NULL ){
    commander_messages = cl;
  }
  else {
    commander_reply_list *clist = commander_messages;
    while( clist->next ) clist = clist->next;
    clist->next = cl;
  }
  g_mutex_unlock( &commander_mutex );

}

