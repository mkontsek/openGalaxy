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
 * Everything for connecting to an openGalaxy server 
 */

#include "atomic.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib.h>
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include "support.h"
#include "opengalaxy-client.h"
#include "websocket.h"
#include "log.h"
#include "connect.h"
#include "commander.h"
#include "client_password_dialog.h"
#include "client_connect_dialog.h"

//
// Data for the connect-to-server dialog
//

static GtkEntry            *server;
static GtkEntry            *port;
static GtkCheckButton      *use_ssl;
static GtkCheckButton      *use_client_cert;
static GtkFrame            *client_certs_frame;
static GtkComboBox         *client_certs_combo;
static GtkListStore        *client_certs_store;
static struct certs_list_t *client_certs_list = NULL;
static GtkEntry            *username;
static GtkEntry            *password;

static char session_id[64];

//
// Lists of callback functions for connection state changes.
//
// Each callback in the list of callbacks for a given connection event
//  is called once every time that connection state occurs
//

#define DECLARE_CONNECT_CALLBACKS_LIST(event)\
  struct connect_callbacks_##event##_t {\
    connect_callback cb;\
    struct connect_callbacks_##event##_t *next;\
  } * event##_callbacks;

#define INIT_CONNECT_CALLBACKS_LIST(event)\
  NULL,

static struct connect_callbacks_t {
  DECLARE_CONNECT_CALLBACKS_LIST(online)
  DECLARE_CONNECT_CALLBACKS_LIST(offline)
  DECLARE_CONNECT_CALLBACKS_LIST(connecting)
  DECLARE_CONNECT_CALLBACKS_LIST(error)
} connect_callbacks_lists = {
  INIT_CONNECT_CALLBACKS_LIST(online)
  INIT_CONNECT_CALLBACKS_LIST(offline)
  INIT_CONNECT_CALLBACKS_LIST(connecting)
  INIT_CONNECT_CALLBACKS_LIST(error)
};


//
// Registered as commander_callback for JSON_POLL_REPLY by cbConnectDialog_onConnect()
// Unregistered  by cbMenu_websocketDisconnect(()
// Called whenever a JSON data block with typeId JSON_POLL_REPLY was received
//
static void cbConnect_PollEvent( struct commander_reply_t * e )
{
  if( e->panelIsOnline == 0 ){
    // panel is offline
    Connect_setStatusError();
  }
  else {
    // panel is online
    Connect_setStatusOnline();
  }
}


//
// Connect dialog callback.
// Called when the 'connect' button on the 'connect to server' dialog is clicked.
//
void G_MODULE_EXPORT cbConnectDialog_onConnect( GtkWindow *_this, gpointer user_data )
{
  GtkTreeIter iter;
  GtkTreeModel *model;
  struct certs_list_t *client = NULL;
  char *cert = NULL;
  char *cert_key = NULL;
  int ssl = 0, prt = 0;
  char *ca = NULL;

#if ! HAVE_NO_SSL
//  char buf_cert[8192];
//  char buf_cert_key[8192];
  const char *path = GET_DATA_DIR;
  size_t len = strlen( path ) + 32;          
  char ca_pem[len];

  if( TRUE == gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON( use_client_cert ) ) ){

    // Get the client_cert_stack_t from the currently selected item of the combo box.
    // If nothing is selected, do nothing.
    if( gtk_combo_box_get_active_iter( client_certs_combo, &iter ) ){
      // Get data model from the combo box.
      model = gtk_combo_box_get_model( client_certs_combo );
      // Get pointer to client_t from the model.
      gtk_tree_model_get( model, &iter, 0, (gpointer)&client, -1 );
    }
    else {
      InfoMessageBox( GTK_WIDGET( _this ), "Information", "You need to select a client certificate before you can do that." );
      return;
    }
    ca = client->ca_pem;
    cert = client->fn_pem;
    cert_key = client->fn_key;
  }
  else {
    snprintf( ca_pem, len, "%s/ssl/certs/%sCA.pem", path, "openGalaxy" );          
    ca = ca_pem;
  }
#endif

  if( TRUE == gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON( use_ssl ) ) ) ssl = 1;

  prt = strtol( gtk_entry_get_text( port ), NULL, 10 );

  if( Websocket_IsConnected() ){
    Websocket_AsyncDisconnect(); // first disconnect
    while( Websocket_IsConnected() ) g_thread_yield ();
  }
  Websocket_SetConnectParameters(
    (char*)gtk_entry_get_text( server ),
    prt,
    ssl,
    cert,
    cert_key,
    ca
  );

  Commander_RegisterCallback( JSON_POLL_REPLY, cbConnect_PollEvent );

  Websocket_AsyncConnect();

  gtk_widget_destroy( GTK_WIDGET( _this ) );
}


//
// Connect dialog callback.
// Called when the 'cancel' button on the 'connect to server' dialog is clicked.
//
void G_MODULE_EXPORT cbConnectDialog_onDestroy( GtkWidget *_this, gpointer user_data )
{
  certsList_free( &client_certs_list );
}


//
// Connect dialog callback.
// Called when the 'use SSL' togglebutton on the 'connect to server' dialog is clicked.
//
void G_MODULE_EXPORT cbConnectDialog_sslToggled( GtkToggleButton *_this, gpointer user_data )
{
  if( !gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON( _this ) ) ){
    gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( use_client_cert ), FALSE );
    gtk_widget_set_sensitive( GTK_WIDGET( use_client_cert ), FALSE );
    gtk_widget_set_sensitive( GTK_WIDGET( client_certs_frame ), FALSE );
  }
  else {
    gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( use_client_cert ), TRUE );
    gtk_widget_set_sensitive( GTK_WIDGET( use_client_cert ), TRUE );
    gtk_widget_set_sensitive( GTK_WIDGET( client_certs_frame ), TRUE );
  }
}


//
// Connect dialog callback.
// Called when the 'use client cert' togglebutton on the 'connect to server' dialog is clicked.
//
void G_MODULE_EXPORT cbConnectDialog_certToggled( GtkToggleButton *_this, gpointer user_data )
{
  if( !gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON( _this ) ) ){
    gtk_widget_set_sensitive( GTK_WIDGET( client_certs_frame ), FALSE );
  }
  else {
    gtk_widget_set_sensitive( GTK_WIDGET( client_certs_frame ), TRUE );
  }
}


//
// Menu callback.
// Callback for when the user selects the 'connect' item from the menu.
// Displays the 'connect to server' dialog.
//
void G_MODULE_EXPORT cbMenu_websocketConnect( GtkMenuItem *_this, gpointer user_data )
{
//  isPasswordDialog = 0;

  GtkBuilder *builder = gtk_builder_new();
  if( 0 == gtk_builder_add_from_string( builder, (const gchar*)client_connect_dialog_glade, client_connect_dialog_glade_len, NULL ) ){
    Log_printf( "ERROR: cbMenuWebsocketConnect( 'GtkBuilder could not load the connect dialog.' );\n" );
    return;
  }
  GtkDialog *dialog  = GTK_DIALOG(       gtk_builder_get_object( builder, "dialogConnect" ) );
  GtkButton *cancel  = GTK_BUTTON(       gtk_builder_get_object( builder, "buttonConnectDoCancel" ) );
  GtkButton *connect = GTK_BUTTON(       gtk_builder_get_object( builder, "buttonConnectDoConnect" ) );
  server             = GTK_ENTRY(        gtk_builder_get_object( builder, "entryServer" ) );
  port               = GTK_ENTRY(        gtk_builder_get_object( builder, "entryPort" ) );
  use_ssl            = GTK_CHECK_BUTTON( gtk_builder_get_object( builder, "checkbuttonSSL" ) );
  use_client_cert    = GTK_CHECK_BUTTON( gtk_builder_get_object( builder, "checkbuttonClientCert" ) );
  client_certs_combo = GTK_COMBO_BOX(    gtk_builder_get_object( builder, "comboboxClientCerts" ) );
  client_certs_frame = GTK_FRAME(        gtk_builder_get_object( builder, "frameClientCerts" ) );
  client_certs_store = GTK_LIST_STORE(   gtk_builder_get_object( builder, "liststoreClientCerts" ) );
  g_object_unref( G_OBJECT( builder ) );

  gtk_window_set_attached_to( GTK_WINDOW( dialog ), mainWindow );
  gtk_window_set_transient_for( GTK_WINDOW( dialog ), GTK_WINDOW( mainWindow ) );
  gtk_window_set_title( GTK_WINDOW( dialog ), "Connect to server..." );
  if( isFullscreen ) gtk_window_set_decorated( GTK_WINDOW( dialog ), FALSE );

  g_signal_connect( G_OBJECT( dialog ),          "destroy", G_CALLBACK( cbConnectDialog_onDestroy ), NULL );
  g_signal_connect( G_OBJECT( use_ssl ),         "toggled", G_CALLBACK( cbConnectDialog_sslToggled ), NULL );
  g_signal_connect( G_OBJECT( use_client_cert ), "toggled", G_CALLBACK( cbConnectDialog_certToggled ), NULL );
  g_signal_connect_swapped( connect,             "clicked", G_CALLBACK( cbConnectDialog_onConnect ), dialog );
  g_signal_connect_swapped( cancel,              "clicked", G_CALLBACK( gtk_widget_destroy ), dialog );

#if HAVE_NO_SSL

  // Disable the SSL option if we don't have SSL compiled in
  gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( use_ssl ), FALSE );
  gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( use_client_cert ), FALSE );
  gtk_widget_set_sensitive( GTK_WIDGET( use_ssl ), FALSE );
  gtk_widget_set_sensitive( GTK_WIDGET( use_client_cert ), FALSE );
  gtk_widget_set_sensitive( GTK_WIDGET( client_certs_frame ), FALSE );

#if __linux__
  gtk_entry_set_text( port, "1500" );
#else
  gtk_entry_set_text( port, "80" );
#endif

#else
  // Use SSL by default
  gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( use_ssl ), TRUE );
  gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( use_client_cert ), TRUE );

#if __linux__
  gtk_entry_set_text( port, "1500" );
#else
  gtk_entry_set_text( port, "443" );
#endif

  certsList_get( &client_certs_list );
  certsList_fillComboStore( &client_certs_list, client_certs_combo, client_certs_store );
#endif

  gtk_widget_show_all( GTK_WIDGET( dialog ) );
}


//
// Menu callback.
// Callback for when the user selects the 'disconnect' item from the menu.
//
void G_MODULE_EXPORT cbMenu_websocketDisconnect( GtkMenuItem *_this, gpointer user_data )
{
  Commander_UnRegisterCallback( JSON_POLL_REPLY, cbConnect_PollEvent );
  Websocket_AsyncDisconnect();
}


//
// These functions (un)registers a callback function that will be called
//  everytime every time a given connection state (event) occurs
//

bool Connect_RegisterCallback( connect_event_id ev, connect_callback cb )
{
  bool retv = false;
  switch( ev ){

#define REGISTER_CONNECT_CALLBACK(event)\
  case connect_event_id_##event : {\
    struct connect_callbacks_##event##_t *new = g_try_malloc( sizeof( struct connect_callbacks_##event##_t ) );\
    if( new == NULL ) break;\
    new->cb = cb;\
    new->next = connect_callbacks_lists.event##_callbacks;\
    connect_callbacks_lists.event##_callbacks = new;\
    retv = true;\
    break;\
  }

    REGISTER_CONNECT_CALLBACK(online)
    REGISTER_CONNECT_CALLBACK(offline)
    REGISTER_CONNECT_CALLBACK(connecting)
    REGISTER_CONNECT_CALLBACK(error)
    default: {
      break;
    }
  }
  return retv;
}


bool Connect_UnRegisterCallback( connect_event_id ev, connect_callback cb )
{
  bool retv = false;
  switch( ev ){

#define UNREGISTER_CONNECT_CALLBACK(event)\
  case connect_event_id_##event : {\
    struct connect_callbacks_##event##_t *next, *prev = NULL, *current = connect_callbacks_lists.event##_callbacks;\
    while( current != NULL ){\
      if( current->cb == cb ){\
        next = current->next;\
        g_free( current );\
        if( prev ){\
          prev->next = next;\
        }\
        else {\
          connect_callbacks_lists.event##_callbacks = next;\
        }\
        break;\
      }\
      prev = current;\
      current = current->next;\
    }\
    break;\
  }

    UNREGISTER_CONNECT_CALLBACK(online)
    UNREGISTER_CONNECT_CALLBACK(offline)
    UNREGISTER_CONNECT_CALLBACK(connecting)
    UNREGISTER_CONNECT_CALLBACK(error)
    default: {
      break;
    }
  }
  return retv;
}


//
// Define the functions that call the callbacks for a given connection event
//

#define CONNECT_EXEC_EVENT_CALLBACKS_FUNCTION(event)\
static void connect_exec_##event##_callbacks( void )\
{\
  struct connect_callbacks_##event##_t *c = connect_callbacks_lists.event##_callbacks;\
  while( c != NULL ){\
    c->cb();\
    c = c->next;\
  }\
}

CONNECT_EXEC_EVENT_CALLBACKS_FUNCTION(online);
CONNECT_EXEC_EVENT_CALLBACKS_FUNCTION(offline);
CONNECT_EXEC_EVENT_CALLBACKS_FUNCTION(connecting);
CONNECT_EXEC_EVENT_CALLBACKS_FUNCTION(error);


//
// These are called once per connection state change
//  by the Connect_setStatusXXX() functions below.
//

static void cbConnect_onOnline( void )
{
  // Start polling the online status of the Galaxy every 30 seconds
  Websocket_SendCommand( "POLL REMOVE ALL" );
  Websocket_SendCommand( "POLL ADD AREAS" );
  Websocket_SendCommand( "POLL ON 30" );

  // exec the list of callbacks for this event
  connect_exec_online_callbacks();
}

static void cbConnect_onOffline( void )
{
  // exec the list of callbacks for this event
  connect_exec_offline_callbacks();
}

static void cbConnect_onConnecting( void )
{
  // exec the list of callbacks for this event
  connect_exec_connecting_callbacks();
}

static void cbConnect_onError( void )
{
  // exec the list of callbacks for this event
  connect_exec_error_callbacks();
}

static void cbConnect_onErrorRestore( void )
{
  cbConnect_onOnline();
}

//
// These functions are called when the connection status changes,
//  they set the correct UI status overlay's opacity to 100% and the rest to 0%.
// Also the above cbConnect_onXXXX() functions are called once per changed status.
//
// ( called from the websocket protocol callbacks and main() )
//

static int statusOnline = 1; // set because Connect_setStatusOffline() is called on init by main()
static int statusConnecting = 0;
static int statusError = 0;

void Connect_setStatusOnline( void )
{
  // Change the opacity of the possible connection statusses to the correct values
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOnline ), 1.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOffline ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusConnecting ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusError ), 0.0 );
  // generate event?
  if( statusOnline == 0 || statusError == 1 || statusConnecting == 1 ){
    if( !statusConnecting ){
      if( statusError ){
       cbConnect_onErrorRestore();
      }
    }
    else {
      cbConnect_onOnline();
    }
    statusOnline = 1;
    statusConnecting = 0;
    statusError = 0;
  }
}

void Connect_setStatusOffline( void )
{
  // Change the opacity of the possible connection statusses to the correct values
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOnline ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOffline ), 1.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusConnecting ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusError ), 0.0 );
  // generate event?
  if( statusOnline == 1 || statusConnecting == 1 ){
    statusOnline = 0;
    cbConnect_onOffline();
  }
  statusConnecting = 0;
  statusError = 0;
}


void Connect_setStatusConnecting( void )
{
  // Change the opacity of the possible connection statusses to the correct values
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOnline ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOffline ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusConnecting ), 1.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusError ), 0.0 );
  // generate event?
  if( statusError ){
    cbConnect_onErrorRestore();
  }
  if( statusConnecting == 0 ){
    statusConnecting = 1;
    cbConnect_onConnecting();
  }
  statusOnline = 0;
  statusError = 0;
}


void Connect_setStatusError( void )
{
  // Change the opacity of the possible connection statusses to the correct values
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOnline ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOffline ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusConnecting ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusError ), 1.0 );
  // generate event?
  if( statusError == 0 ){
    statusError = 1;
    cbConnect_onError();
  }
  statusConnecting = 0;
}


static int isPasswordDialog = 0; // !0 when the password dialog is open

void G_MODULE_EXPORT cbPasswordDialog_onConfirm( GtkWindow *_this, gpointer user_data )
{
  // Send the username/password to the server
  if(
    !Websocket_SendCredentials(
      session_id,
      gtk_entry_get_text( username ),
      gtk_entry_get_text( password )
    )
  ){
    gtk_widget_destroy( GTK_WIDGET( _this ) );
    isPasswordDialog = 0;
  }
}

void G_MODULE_EXPORT cbPasswordDialog_onDestroy( GtkWindow *_this, gpointer user_data )
{
  if( isPasswordDialog == 0) Connect_setStatusOnline();
  isPasswordDialog = 0;
}


// Called by default_JSON_AUTHORIZATION_REQUIRED_callback()
void Connect_ShowPasswordDialog( const char *sid )
{
  // only show the dialog once
  if( isPasswordDialog ) return;

  if( strlen( sid ) >= sizeof( session_id ) ){
    Log_printf( "ERROR: Connect_ShowPasswordDialog: Session ID is too long.\n" );
    return;
  }
  strcpy( session_id, sid );

  GtkBuilder *builder = gtk_builder_new();
  if( 0 == gtk_builder_add_from_string( builder, (const gchar*)client_password_dialog_glade, client_password_dialog_glade_len, NULL ) ){
    Log_printf( "ERROR: Connect_ShowPasswordDialog: GtkBuilder could not load the password dialog.\n" );
    return;
  }
  GtkWindow *dialog  = GTK_WINDOW( gtk_builder_get_object( builder, "dialogPassword" ) );
  GtkButton *cancel  = GTK_BUTTON( gtk_builder_get_object( builder, "buttonBack" ) );
  GtkButton *confirm = GTK_BUTTON( gtk_builder_get_object( builder, "buttonConfirm" ) );
  username           = GTK_ENTRY(  gtk_builder_get_object( builder, "entryUsername" ) );
  password           = GTK_ENTRY(  gtk_builder_get_object( builder, "entryPassword" ) );
  g_object_unref( G_OBJECT( builder ) );

  gtk_window_set_attached_to( GTK_WINDOW( dialog ), mainWindow );
  gtk_window_set_transient_for( GTK_WINDOW( dialog ), GTK_WINDOW( mainWindow ) );
  gtk_window_set_title( GTK_WINDOW( dialog ), "Authentication required..." );
  if( isFullscreen ) gtk_window_set_decorated( GTK_WINDOW( dialog ), FALSE );

  g_signal_connect_swapped( confirm, "clicked", G_CALLBACK( cbPasswordDialog_onConfirm ), dialog );
  g_signal_connect_swapped( cancel,  "clicked", G_CALLBACK( gtk_widget_destroy ), dialog );
  g_signal_connect_swapped( username, "activate", G_CALLBACK( cbPasswordDialog_onConfirm ), dialog );
  g_signal_connect_swapped( password, "activate", G_CALLBACK( cbPasswordDialog_onConfirm ), dialog );
  g_signal_connect( G_OBJECT( dialog ), "destroy",  G_CALLBACK( cbPasswordDialog_onDestroy ), NULL );

  Connect_setStatusError();
  isPasswordDialog = 1;
  gtk_widget_show_all( GTK_WIDGET( dialog ) );
}


