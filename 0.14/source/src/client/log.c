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

#include "atomic.h"

#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib.h>
#include <glib/gprintf.h>
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include "support.h"
#include "log.h"
#include "opengalaxy-client.h"

typedef struct log_messages_to_process_t {
  char *msg;
  struct log_messages_to_process_t *next;
} log_messages_to_process;


static log_messages_to_process *log_messages = NULL;
static GMutex log_mutex;
static int log_quit = 0;

 
//
// Called every second to process pending log messages
// and prints them to the log console window
//
static gboolean Log_MessageLoop( gpointer user_data )
{
  gboolean retv = TRUE;
  GtkTextIter iter;
  g_mutex_lock( &log_mutex );
  GtkTextBuffer *buffer = gtk_text_view_get_buffer( log_output );
  log_messages_to_process *list = log_messages, *prev = NULL;
  while( list ){
    // Add message to consoleWindowLogOutput
    gtk_text_buffer_get_end_iter( buffer, &iter );
    gtk_text_buffer_insert( buffer, &iter, list->msg, strlen( list->msg ) );
    // Free data and process next message
    prev = list;
    list = list->next;
    if( prev->msg ) g_free( prev->msg );
    if( prev ) g_free( prev );
  }
  log_messages = NULL;
  if( log_quit ) retv = FALSE ;
  g_mutex_unlock( &log_mutex );
  return retv; // continue with the next call or quit this main loop
}


//
// Initializes/shows the logging console window
//
int Log_Init( void )
{
  g_mutex_lock( &log_mutex );
  log_quit = 0;
  g_signal_connect( log_output, "size-allocate", G_CALLBACK( cbTextbufferScrollToEof ), NULL );
  g_mutex_unlock( &log_mutex );
//  g_timeout_add_seconds( 1, Log_MessageLoop, NULL );
  g_timeout_add( 50, Log_MessageLoop, NULL );
  return 0;
}


void Log_Exit( void )
{
  g_mutex_lock( &log_mutex );
  log_quit = 1;
  g_mutex_unlock( &log_mutex );
}


void Log_printf( const char *fmt, ... )
{
  if( log_quit ) return;
  char buf[8192];
  va_list args;
  log_messages_to_process *new = g_malloc( sizeof( log_messages_to_process ) );
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
  g_mutex_lock( &log_mutex );
  if( log_messages == NULL ){
    log_messages = new;
  }
  else {
    log_messages_to_process *list = log_messages;
    while( list->next ) list = list->next;
    list->next = new;
  }
  g_mutex_unlock( &log_mutex );
}


