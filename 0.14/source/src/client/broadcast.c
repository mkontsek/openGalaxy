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

#include "atomic.h"

#include <string.h>
#include <stdlib.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib.h>
#include <glib/gprintf.h>
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include "support.h"
#include "websocket.h"
#include "broadcast.h"
#include "log.h"
#include "json-decode.h"
#include "opengalaxy-client.h"


//oud
static pending_sia_message *pending_sia_messages = NULL; // List of yet to be decoded SIA messages

// new
static sia_message_list *slist = NULL;

static GMutex sia_mutex;
static int sia_quit = 1;


static struct sia_callbacks_list_entry_t {
  char *lettercode;
  sia_callback callback;
  struct sia_callbacks_list_entry_t *next;
} *sia_callbacks_list = NULL;


//
// Free a struct sia_events_list_t
//
void SIA_FreeEvent( struct sia_event_t *e )
{
  if( e->EventCode ) free( e->EventCode );
  if( e->EventName ) free( e->EventName );
  if( e->EventDesc ) free( e->EventDesc );
  if( e->EventAddressType ) free( e->EventAddressType );
  if( e->Date ) free( e->Date );
  if( e->Time ) free( e->Time );
  if( e->ASCII ) free( e->ASCII );
  if( e->Raw ) free( e->Raw );
  free( e );
}


//
// Register a function to be called when a specific SIA message is received
//
// In:  lettercode = The 2 digit lettercode or null for any
//      callback   = the function to be called
//
// Out: True = success, false = error.
//
bool SIA_RegisterCallback( const char *lettercode, const sia_callback callback )
{
  g_mutex_lock( &sia_mutex );
  bool retv = false;

  struct sia_callbacks_list_entry_t *new = g_try_malloc( sizeof( struct sia_callbacks_list_entry_t ) );
  if( new == NULL ) goto exit;
  new->lettercode = (char*)lettercode;
  new->callback = callback;
  new->next = sia_callbacks_list;
  sia_callbacks_list = new;
  retv = true;

exit:
  g_mutex_unlock( &sia_mutex );
  return retv;
}


//
// Unregister a callback set with SIA_RegisterCallback()
//
// In: callback = the function to unregister
//
// Out: True = success, false = error.
//
bool SIA_UnRegisterCallback( const sia_callback callback )
{
  g_mutex_lock( &sia_mutex );
  bool retv = false;

  struct sia_callbacks_list_entry_t *next, *prev = NULL, *current = sia_callbacks_list;
  while( current != NULL ){
    if( current->callback == callback ){
      next = current->next;
      g_free( current );
      if( prev ){
        prev->next = next;
      }
      else {
        sia_callbacks_list = next;
      }
      retv = true;
      break;
    }
    prev = current;
    current = current->next;
  }

  g_mutex_unlock( &sia_mutex );
  return retv;
}


//
// Called every second to parse pending SIA messages:
// Decodes and adds them to the SIA messsage list of the main window
//
static gboolean SIA_MessageLoop( gpointer user_data )
{
  gboolean retv = TRUE;
  g_mutex_lock( &sia_mutex );
  //pending_sia_message *list = pending_sia_messages, *prev = NULL;
  sia_message_list *list = slist, *prev = NULL;
  while( list ){

    //struct sia_event_t *e =  JSON_ParseOpenGalaxyBroadcastObject( list->msg );
    if( list->msg ){
      GtkTreeIter iter;
      gtk_list_store_prepend( liststoreSIA, &iter );
      gtk_list_store_set( liststoreSIA, &iter,
        0, ( gchararray )list->msg->Time,
        1, ( gchararray )list->msg->EventCode,
        2, ( gchararray )list->msg->EventName,
        3, ( gchararray )list->msg->ASCII,
        4, ( gchararray )list->msg->EventDesc,
        5, ( gchararray )list->msg->EventAddressType,
        -1
      );
      if( list->msg->have_EventAddressNumber ) gtk_list_store_set( liststoreSIA, &iter, 6, ( gint )list->msg->EventAddressNumber, -1 );
      if( list->msg->have_SubscriberID ) gtk_list_store_set( liststoreSIA, &iter, 7, ( gint )list->msg->SubscriberID, -1 );
      if( list->msg->have_AreaID ) gtk_list_store_set( liststoreSIA, &iter, 8, ( gint )list->msg->AreaID, -1 );
      if( list->msg->have_PeripheralID ) gtk_list_store_set( liststoreSIA, &iter, 9, ( gint )list->msg->PeripheralID, -1 );

      // execute callbacks
      struct sia_callbacks_list_entry_t *current = sia_callbacks_list;
      while( current != NULL ){
        if( current->lettercode == NULL ){
          current->callback( list->msg );
        }
        else if( strcmp( current->lettercode, list->msg->EventCode ) == 0 ){
          current->callback( list->msg );
        }
        current = current->next;
      }

      SIA_FreeEvent( list->msg );
    }

    // Free data and process next message
    prev = list;
    list = list->next;
    //if( prev->msg ) g_free( prev->msg );
    if( prev ) g_free( prev );
  }
//  pending_sia_messages = NULL;
  slist = NULL;
  if( sia_quit ) retv = FALSE ;
  g_mutex_unlock( &sia_mutex );
  return retv; // continue with the next call or quit this main loop
}


//
// Start processing received SIA messages
//
int SIA_Init( void )
{
  g_mutex_lock( &sia_mutex );
  gtk_list_store_clear( liststoreSIA );
  g_signal_connect( treeviewSIA, "size-allocate", G_CALLBACK( cbTreeViewScrollToStart ), NULL );
  sia_quit = 0;
  g_mutex_unlock( &sia_mutex );
//  g_timeout_add_seconds( 1, SIA_MessageLoop, NULL );
  g_timeout_add( 250, SIA_MessageLoop, NULL );
  return 0;
}


void SIA_Exit( void )
{
//printf("%d:%s\n",__LINE__,__FILE__);
  g_mutex_lock( &sia_mutex );
  sia_quit = 1;
  g_mutex_unlock( &sia_mutex );
}


//
// Adds a new (JSON formatted) SIA message to pending_sia_messages.
// Called from the broadcast_callback in the websocket thread.
//
void SIA_AddMessage( const char *fmt, ... )
{
  if( sia_quit ) return;
  char buf[8192];
  va_list args;
  pending_sia_message *new = g_malloc( sizeof( pending_sia_message ) );
  va_start( args, fmt );
  g_vsnprintf( buf, 8192, fmt, args );
  va_end( args );
  char *dup = g_strdup( buf );
  if( !new || !dup ){
    if( new ) g_free( new );
    if( dup ) g_free( dup );
    return;
  }
  new->msg = dup;
  new->next = NULL;
  g_mutex_lock( &sia_mutex );
  if( pending_sia_messages == NULL ){
    pending_sia_messages = new;
  }
  else {
    pending_sia_message *list = pending_sia_messages;
    while( list->next ) list = list->next;
    list->next = new;
  }
  g_mutex_unlock( &sia_mutex );
}

void xSIA_AddMessage( struct sia_event_t *s )
{
  if( sia_quit ) return;
  sia_message_list *new = g_malloc( sizeof( sia_message_list ) );
  new->msg = s;
  new->next = NULL;
  g_mutex_lock( &sia_mutex );
  if( slist == NULL ){
    slist = new;
  }
  else {
    sia_message_list *list = slist;
    while( list->next ) list = list->next;
    list->next = new;
  }
  g_mutex_unlock( &sia_mutex );
}


