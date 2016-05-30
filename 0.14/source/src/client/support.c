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

// Various support functions

#include "atomic.h"
#include <dirent.h>
#include <stdarg.h>
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib.h>
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include "opengalaxy-client.h"
#include "support.h"
#include "log.h"
#include "info_dialog.h"

// The names of the variables stored in the Windows registry
const char     *str_registry_install_dir      = "openGalaxyDirectory";    // directory of openGalaxy.exe
const char     *str_registry_data_dir         = "DataDirectory";          // directory of the ssl certs (and on Windows, the config files)
const char     *str_registry_config_dir       = "ConfigDirectory";        // directory of the configuration files (and on Windows, the ssl certs)
const char     *str_registry_opengalaxyca_dir = "openGalaxyCaDirectory";  // directory of openGalaxyCA.exe
const char     *str_registry_www_dir          = "WebDirectory";           // root www directory

//
// Retrieves directory paths from the Registry keys written by the NSIS installer
// Or on Linux, get the values from the hardcoded values.
//
#if ! __linux__
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
const char* openGalaxyGetRegistry( const char *key )
{
  DWORD dwType = REG_SZ;
  HKEY hKey = 0;
  char value[1024], *out;
  DWORD value_length = sizeof( value );
  const char* subkey = "Software\\openGalaxy";
  value[0] = '\0';
  RegOpenKey( HKEY_CURRENT_USER, subkey, &hKey );
  if( RegQueryValueEx( hKey, key, NULL, &dwType, ( LPBYTE )&value, &value_length ) != ERROR_SUCCESS ){
    return NULL;
  }
  if( strlen(value) > 2 ){
    for( int t=0; t<strlen(value); t++ ) if( value[t] == '\\' ) value[t] = '/';
    if( *value == '\"' ){ // remove the quotes
      int t = strlen( value ) - 1;
      if( t > 0 && t < value_length ) value[ t ] = '\0';
      out = strdup( &value[1] );
    }
    else out = strdup( value );
  }
  else out = NULL;

  return out;
}
#else
#ifndef _INSTALL_DIR_
#error _INSTALL_DIR_ has not been set!
#endif
#ifndef _CERT_DIR_
#error _CERT_DIR_ has not been set!
#endif
#ifndef _CONFIG_DIR_
#error _CONFIG_DIR_ has not been set!
#endif
#ifndef _SHARE_DIR_
#error _SHARE_DIR_ has not been set!
#endif
#ifndef _WWW_DIR_
#error _WWW_DIR_ has not been set!
#endif
const char* openGalaxyGetRegistry( const char *key )
{
  static const char *install = _INSTALL_DIR_;
  static const char *data = _SHARE_DIR_;
  static const char *config = _CONFIG_DIR_;
  static const char *www = _WWW_DIR_;
  if( strcmp( key, str_registry_install_dir ) == 0 ) return install;
  if( strcmp( key, str_registry_data_dir ) == 0 ) return data;
  if( strcmp( key, str_registry_config_dir ) == 0 ) return config;
  if( strcmp( key, str_registry_opengalaxyca_dir ) == 0 ) return install;
  if( strcmp( key, str_registry_www_dir ) == 0 ) return www;
  return NULL;
}
#endif


//
// Callback for when the contents of a GtkTextBuffer has changed.
// Scrolls the view to the start of the text.
//
void G_MODULE_EXPORT cbTextbufferScrollToStart( GtkTextView *_this, gpointer user_data )
{
  GtkTextIter iter;
  gtk_text_buffer_get_start_iter( gtk_text_view_get_buffer( _this ), &iter );
  gtk_text_view_scroll_to_iter( _this, &iter, 0.0, FALSE, 0.0, 0.0 );
}


//
// Callback for when the contents of a GtkTreeView has changed.
// Scrolls the view to the start of the text.
//
void G_MODULE_EXPORT cbTreeViewScrollToStart( GtkTreeView *_this, gpointer user_data )
{
  // Check if row 0 exists
  GtkTreeIter iter;
  GtkTreePath *path = gtk_tree_path_new_from_string( "0" );
  GtkTreeModel *list_store = gtk_tree_view_get_model( _this );
  int rv = gtk_tree_model_get_iter( list_store, &iter, path );

  // If it exist, scroll to it
  if( rv == TRUE ) gtk_tree_view_scroll_to_cell( _this, path, NULL, FALSE, 0.0, 0.0 );
}


//
// Callback for when the contents of a GtkTextBuffer has changed.
// Scrolls the view to the end of the text.
//
void G_MODULE_EXPORT cbTextbufferScrollToEof( GtkTextView *_this, gpointer user_data )
{
  GtkTextIter iter;
  GtkTextBuffer *textbuffer = gtk_text_view_get_buffer( _this );
  GtkTextMark *insert_mark = gtk_text_buffer_get_mark( textbuffer, "insert" );
  gtk_text_buffer_get_iter_at_mark( textbuffer, &iter, insert_mark );
  gtk_text_view_scroll_to_iter( _this, &iter, 0.0, FALSE, 0.0, 0.0 );
}


//
// General purpose informational dialog
//
void InfoMessageBox( GtkWidget *parent, char *title, char *fmt, ... )
{
  char buf[8192];
  va_list args;
  va_start( args, fmt );
  g_vsnprintf( buf, 8192, fmt, args );
  va_end( args );

  GtkWindow *window;
  GtkButton *button;
  GtkLabel *label;
  GtkBuilder *builder = gtk_builder_new();
  if( 0 == gtk_builder_add_from_string( builder, (const gchar*)info_dialog_glade, info_dialog_glade_len, NULL ) ){
    Log_printf( "ERROR: GtkBuilder could not load XML data.\n" );
    return;
  }
  window = GTK_WINDOW( gtk_builder_get_object( builder, "info-dialog" ) );
  label = GTK_LABEL( gtk_builder_get_object( builder, "info-dialog-label" ) );
  button = GTK_BUTTON( gtk_builder_get_object( builder, "info-dialog-button" ) );
  g_object_unref( G_OBJECT( builder ) );
  gtk_window_set_attached_to( window, parent );
  gtk_window_set_transient_for( window, GTK_WINDOW( parent ) );
  if( title ) gtk_window_set_title( window, title );
  gtk_label_set_text( label, buf );
  g_signal_connect_swapped( button, "clicked", G_CALLBACK( gtk_window_close ), window );
  if( isFullscreen ) gtk_window_set_decorated( GTK_WINDOW( window ), FALSE );
  gtk_widget_show( GTK_WIDGET( window ) );
}


//
// functions to test/add/remove a CSS class for/to/from a GTK widget 
//

gboolean _gtk_widget_has_class( GtkWidget *widget, const gchar *class_name )
{
  GtkStyleContext *ctx = gtk_widget_get_style_context( widget );
  return gtk_style_context_has_class( ctx, class_name );
}

void _gtk_widget_add_class( GtkWidget *widget, const gchar *class_name )
{
  GtkStyleContext *ctx = gtk_widget_get_style_context( widget );
  gtk_style_context_add_class( ctx, class_name );
}

void _gtk_widget_remove_class( GtkWidget *widget, const gchar *class_name )
{
  GtkStyleContext *ctx = gtk_widget_get_style_context( widget );
  gtk_style_context_remove_class( ctx, class_name );
}


//
// Functions to aid working with a list of (needed filenames of) client certificates
//

// Adds a single client cert to a list of client certs
static int certsList_add( struct certs_list_t **list, char* ca_pem, char *fn_p12, char *fn_pem, char *fn_key, char *display )
{
  struct certs_list_t *new = g_malloc( sizeof( struct certs_list_t ) );
  if( new ){
    new->ca_pem = g_strdup( ca_pem );
    new->fn_p12 = g_strdup( fn_p12 );
    new->fn_pem = g_strdup( fn_pem );
    new->fn_key = g_strdup( fn_key );
    new->display = g_strdup( display );
    if( new->fn_p12 && new->fn_pem && new->fn_key && display ){
      new->next = *list;
      *list = new;
      return 0;
    }
  }
  if( new->ca_pem ) g_free( ca_pem );
  if( new->fn_p12 ) g_free( new->fn_p12 );
  if( new->fn_pem ) g_free( new->fn_pem );
  if( new->fn_key ) g_free( new->fn_key );
  if( new->display ) g_free( new->display );
  if( new ) g_free( new );
  return -1;
}

// Free's the list of client certs
void certsList_free( struct certs_list_t **list )
{
  struct certs_list_t *c; 
  while( *list ){
    c = *list;
    if( c->ca_pem ) g_free( c->ca_pem );
    if( c->fn_p12 ) g_free( c->fn_p12 );
    if( c->fn_pem ) g_free( c->fn_pem );
    if( c->fn_key ) g_free( c->fn_key );
    if( c->display ) g_free( c->display );
    *list = c->next;
    g_free( c );
  }
}

// Locates and adds all client certs to a list of certs
int certsList_get( struct certs_list_t **list )
{
  struct dirent *ep;
  char dirname[4096];
  const char *path = GET_DATA_DIR;
  // Open the client certs directory
  snprintf( dirname, sizeof( dirname ), "%s/ssl/certs/users", GET_DATA_DIR );
  DIR *dp = opendir( dirname );
  if( dp != NULL ){
    // List all files in the directory
    while( ( ep = readdir (dp) ) != NULL ){
      //is it a .pem file?
      if( strstr( ep->d_name, ".pem" ) ){
        // Add it to the stack of certs
        int len = strlen( ep->d_name ) + strlen( path ) + 32;
        char basename[len];
        char fn_p12[len];
        char fn_pem[len];
        char fn_key[len];
        strcpy( basename, ep->d_name );
        *(strstr( basename, ".pem" )) = '\0';
        snprintf( fn_p12, len, "%s/ssl/certs/users/%s.p12", path, basename );          
        snprintf( fn_pem, len, "%s/ssl/certs/users/%s.pem", path, basename );          
        snprintf( fn_key, len, "%s/ssl/private/users/%s-KEY.pem", path, basename );
        len = strlen( path ) + 32;          
        char ca_pem[len];
        snprintf( ca_pem, len, "%s/ssl/certs/%sCA.pem", path, "openGalaxy" );          
        if( certsList_add( list, ca_pem, fn_p12, fn_pem, fn_key, basename ) ){
          Log_printf( "certsList_get: could not add client cert: %s\n", ep->d_name );
        }
      }
    }
  }
  return 0;
}

// Copies a list of client certs to the liststore in a combobox
void certsList_fillComboStore( struct certs_list_t **list, GtkComboBox *combo, GtkListStore *store )
{
  GtkTreeIter iter;
  struct certs_list_t *cert = *list;
  if( cert ) gtk_list_store_clear( store );
  while( cert ){
    // Add each client cert to the combobox's liststore
    gtk_list_store_append( store, &iter );
    gtk_list_store_set( store, &iter,
      0, (gpointer)cert,
      1, (gchararray)cert->display,
      -1
    );
    // This also triggers the 'changed' signal ...
    gtk_combo_box_set_active_iter( combo, &iter );
    cert = cert->next;
  }
}



