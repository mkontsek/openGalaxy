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

#include "atomic.h"
#include <sys/types.h>
#include <dirent.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#endif
#include "libwebsockets.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib.h>
#include <glib/gprintf.h>
#pragma GCC diagnostic pop

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

#include "credentials.h"
#include "websocket.h"
#include "support.h"
#include "json.h"

// Include the C header files generated from the CSS files used with the glade XML files
// defines:
// const gchar ca_connect_dialog_glade[]
// const guint ca_connect_dialog_glade_len
#include "ca_connect_dialog.h"

// Include the C header files generated from the CSS files used with the glade XML files
// defines:
// const gchar ca_upload_info_glade[]
// const guint ca_upload_info_glade_len
#include "ca_upload_info.h"

// These are declared in opengalaxy-ca.c
extern char* FN_CAPEM;
extern char* CERTFILES;
extern char* FN_CAPUBKEY;
extern char* FN_SERVERPEM;
extern char* FN_SERVERKEY;
extern char* FN_CRL;
extern char* FN_CRED_KEY;
extern char* FN_CAKEY;
extern char* FN_CRED_PUBKEY;
extern int pass_cb(char *buf, int size, int rwflag, void *u);
extern const gchar ca_password_dialog_glade[];
extern const guint ca_password_dialog_glade_len;
extern GtkWidget *window;
extern GtkWidget *button_upload;

// Declared in ssl_evp/certs_pkg.c
extern char* encrypt_certs_to_JSON(
  const char* fn_ca_cert,
  const char* fn_server_cert,
  const char* fn_server_key,
  const char* fn_crl_cert,
  const char* fn_verify_key,
  const char* fn_decrypt_key,
  const char** error,
  int encrypt,
  EVP_PKEY *sign_key,
  EVP_PKEY *encrypt_key
);

static GtkEntry            *server;
static GtkEntry            *port;
static GtkCheckButton      *use_ssl;
static GtkCheckButton      *use_client_cert;
static GtkFrame            *client_certs_frame;
static GtkEntry            *username;
static GtkEntry            *password;


static void callback_connecting(void* user);
static void callback_offline(void* user);
static void callback_online(void* user);
static void callback_receive(const char* in, void* user);
static void callback_connect_error(const char* address, void* user);

static WebsocketCallbacks ws_callbacks = {
  callback_connecting,
  callback_offline,
  callback_online,
  callback_receive,
  callback_connect_error,
  NULL // user data
};

static char session_id[32];
static int isPasswordDialog = 0; // !0 when the password dialog is open

static GMutex callback_mutex;

int waiting_for_websocket = 0;
int waiting_for_credentials = 0;
int waiting_for_success = 1;
int is_success = 0;
guint waiting_for_websocket_tag = 0;

// set by cbConnectDialog_onConnect
int do_use_ssl = 0;

//
// Some helper functions to create the list of client certificates for the
// 'connect to server' dialog
//

typedef struct certs_list_t {
  char *ca_pem;
  char *fn_p12;
  char *fn_pem;
  char *fn_key;
  char *display;
  struct certs_list_t *next;
} certs_list;


static GtkComboBox         *client_certs_combo;
static GtkListStore        *client_certs_store;
static struct certs_list_t *client_certs_list = NULL;

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
  const char *path = CERTFILES;
  // Open the client certs directory
  snprintf( dirname, sizeof( dirname ), "%s/certs/users", path );
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
        snprintf( fn_p12, len, "%s/certs/users/%s.p12", path, basename );
        snprintf( fn_pem, len, "%s/certs/users/%s.pem", path, basename );
        snprintf( fn_key, len, "%s/private/users/%s-KEY.pem", path, basename );
        if( certsList_add( list, FN_CAPEM, fn_p12, fn_pem, fn_key, basename ) ){
          _gtk_display_error_dialog( GTK_WIDGET(window), "Error", "certsList_get: could not add client cert: %s\n", ep->d_name);
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

//
// Functions/dialog for the username/password dialog
//

void G_MODULE_EXPORT cbPasswordDialog_onConfirm( GtkWindow *_this, gpointer user_data )
{
  g_mutex_lock(&callback_mutex);
  waiting_for_credentials = 0;
  g_mutex_unlock(&callback_mutex);
  Websocket_SendCredentials(
    session_id,
    gtk_entry_get_text( username ),
    gtk_entry_get_text( password )
  );
  gtk_widget_destroy( GTK_WIDGET( _this ) );
}

void G_MODULE_EXPORT cbPasswordDialog_onCancel( GtkWindow *_this, gpointer user_data )
{
  Websocket_AsyncDisconnect();
  g_mutex_lock(&callback_mutex);
  waiting_for_websocket = 0;
  g_mutex_unlock(&callback_mutex);
  gtk_widget_set_sensitive( button_upload, TRUE );
  gtk_widget_destroy( GTK_WIDGET( _this ) );
}

void G_MODULE_EXPORT cbPasswordDialog_onDestroy( GtkWindow *_this, gpointer user_data )
{
  isPasswordDialog = 0;
}

void Connect_ShowPasswordDialog( void )
{
  // only show the dialog once
  if( isPasswordDialog ) return;
  isPasswordDialog = 1;

  GtkBuilder *builder = gtk_builder_new();
  if( 0 == gtk_builder_add_from_string( builder, ca_password_dialog_glade, ca_password_dialog_glade_len, NULL ) ){
    isPasswordDialog = 0;
    return;
  }
  GtkWindow *dialog      = GTK_WINDOW( gtk_builder_get_object( builder, "dialogPassword" ) );
  GtkButton *_cancel     = GTK_BUTTON( gtk_builder_get_object( builder, "buttonBack" ) );
  GtkButton *confirm     = GTK_BUTTON( gtk_builder_get_object( builder, "buttonConfirm" ) );
  GtkWidget *boxUsername = GTK_WIDGET( gtk_builder_get_object( builder, "boxUsername" ) );
  username               = GTK_ENTRY(  gtk_builder_get_object( builder, "entryUsername" ) );
  password               = GTK_ENTRY(  gtk_builder_get_object( builder, "entryPassword" ) );
  g_object_unref( G_OBJECT( builder ) );

  gtk_widget_set_sensitive( GTK_WIDGET( boxUsername ), TRUE );
  gtk_widget_grab_focus( GTK_WIDGET( username ));
  gtk_window_set_attached_to( GTK_WINDOW( dialog ), window );
  gtk_window_set_transient_for( GTK_WINDOW( dialog ), GTK_WINDOW( window ) );
  gtk_window_set_title( GTK_WINDOW( dialog ), "Authentication required..." );

  g_signal_connect_swapped( confirm, "clicked", G_CALLBACK( cbPasswordDialog_onConfirm ), dialog );
  g_signal_connect_swapped( _cancel,  "clicked", G_CALLBACK( cbPasswordDialog_onCancel ), dialog );
  g_signal_connect_swapped( username, "activate", G_CALLBACK( cbPasswordDialog_onConfirm ), dialog );
  g_signal_connect_swapped( password, "activate", G_CALLBACK( cbPasswordDialog_onConfirm ), dialog );
  g_signal_connect( G_OBJECT( dialog ), "destroy",  G_CALLBACK( cbPasswordDialog_onDestroy ), NULL );

  gtk_widget_show_all( GTK_WIDGET( dialog ) );
}

//
// Functions/dialog to connect to an openGalaxy server
//

// Called when the 'connect' button on the 'connect to server' dialog is clicked.
void G_MODULE_EXPORT cbConnectDialog_onConnect( GtkWindow *_this, gpointer user_data )
{
  GtkTreeIter iter;
  GtkTreeModel *model;
  struct certs_list_t *client = NULL;
  char *cert = NULL;
  char *cert_key = NULL;
  int prt = 0;

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
      _gtk_display_error_dialog( GTK_WIDGET(_this), "Error", "You need to select a client certificate before you can do that.");
      return;
    }
    cert = client->fn_pem;
    cert_key = client->fn_key;
  }

  if( TRUE == gtk_toggle_button_get_active( GTK_TOGGLE_BUTTON( use_ssl ) ) ) do_use_ssl = 1;

  prt = strtol( gtk_entry_get_text( port ), NULL, 10 );

  if( Websocket_IsConnected() ){
    Websocket_AsyncDisconnect(); // first disconnect
    while( Websocket_IsConnected() ) g_thread_yield ();
  }

  Websocket_SetConnectParameters(
    (char*)gtk_entry_get_text( server ),
    prt,
    do_use_ssl,
    cert,
    cert_key,
    FN_CAPEM
  );

  ws_callbacks.user = (void*)window;
  Websocket_AsyncConnect(&ws_callbacks);

  gtk_widget_destroy( GTK_WIDGET( _this ) );
}

void G_MODULE_EXPORT cbConnectDialog_onCancel( GtkWindow *_this, gpointer user_data )
{
  g_mutex_lock(&callback_mutex);
  waiting_for_websocket = 0;
  g_mutex_unlock(&callback_mutex);
  gtk_widget_set_sensitive( button_upload, TRUE );
  gtk_widget_destroy( GTK_WIDGET( _this ) );
}

void G_MODULE_EXPORT cbConnectDialog_onDestroy( GtkWidget *_this, gpointer user_data )
{
  certsList_free( &client_certs_list );
}

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
// Displays the 'connect to server' dialog.
//
void websocketConnect(GtkWidget *mainWindow)
{
  GtkBuilder *builder = gtk_builder_new();
  if( 0 == gtk_builder_add_from_string( builder, (const gchar *)ca_connect_dialog_glade, ca_connect_dialog_glade_len, NULL ) ){
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

  g_signal_connect( G_OBJECT( dialog ),          "destroy", G_CALLBACK( cbConnectDialog_onDestroy ), NULL );
  g_signal_connect( G_OBJECT( use_ssl ),         "toggled", G_CALLBACK( cbConnectDialog_sslToggled ), NULL );
  g_signal_connect( G_OBJECT( use_client_cert ), "toggled", G_CALLBACK( cbConnectDialog_certToggled ), NULL );
  g_signal_connect_swapped( connect,             "clicked", G_CALLBACK( cbConnectDialog_onConnect ), dialog );
  g_signal_connect_swapped( cancel,              "clicked", G_CALLBACK( cbConnectDialog_onCancel ), dialog );

  // Use SSL by default
  gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( use_ssl ), TRUE );
  gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( use_client_cert ), TRUE );

gtk_entry_set_text( server, "localhost" );

#if __linux__
  gtk_entry_set_text( port, "1500" );
#else
  gtk_entry_set_text( port, "443" );
#endif

  certsList_get( &client_certs_list );
  certsList_fillComboStore( &client_certs_list, client_certs_combo, client_certs_store );

  gtk_widget_set_sensitive( button_upload, FALSE );
  gtk_widget_show_all( GTK_WIDGET( dialog ) );
}

//
// The info dialog shown when send_certs() is done
//

void G_MODULE_EXPORT cb_upload_info_dialog_onClose( GtkWindow *_this, gpointer user_data )
{
puts("cb_upload_info_dialog_onClose");
  gtk_widget_destroy( GTK_WIDGET( _this ) );
}

void G_MODULE_EXPORT cb_upload_info_dialog_onDestroy( GtkWindow *_this, gpointer user_data )
{
puts("cb_upload_info_dialog_onDestroy");
  gtk_widget_set_sensitive( button_upload, TRUE );
}

void show_upload_info_dialog(int success)
{
puts("show_upload_info_dialog");
  waiting_for_websocket = 0;
  GtkBuilder *builder = gtk_builder_new();
  if( 0 == gtk_builder_add_from_string( builder, (const gchar *)ca_upload_info_glade, ca_upload_info_glade_len, NULL ) ){
    return;
  }
  GtkWindow *dialog = GTK_WINDOW( gtk_builder_get_object( builder, "upload-info-dialog" ) );
  GtkButton *close = GTK_BUTTON( gtk_builder_get_object( builder, "upload-info-button" ) );
  g_object_unref( G_OBJECT( builder ) );

  gtk_window_set_attached_to( GTK_WINDOW( dialog ), window );
  gtk_window_set_transient_for( GTK_WINDOW( dialog ), GTK_WINDOW( window ) );
  gtk_window_set_title( GTK_WINDOW( dialog ), "Uploading certificates..." );

  g_signal_connect_swapped( close, "clicked", G_CALLBACK( cb_upload_info_dialog_onClose ), dialog );
  g_signal_connect( G_OBJECT( dialog ), "destroy",  G_CALLBACK( cb_upload_info_dialog_onDestroy ), NULL );

  gtk_widget_show_all( GTK_WIDGET( dialog ) );
puts("show_upload_info_dialog done");
}

// This function is a our communication between the gtk and the websocket threads
// This way do not have to call gtk functions from the websocket thread...
gboolean G_MODULE_EXPORT waitForWebsocket(gpointer user_data)
{
puts("waitForWebsocket");
  g_mutex_lock(&callback_mutex);

  if(!waiting_for_websocket){
    waiting_for_websocket_tag = 0;
    g_mutex_unlock(&callback_mutex);
puts("waitForWebsocket done");
    return FALSE;
  }

  if(waiting_for_credentials){
    waiting_for_credentials = 0;
    g_mutex_unlock(&callback_mutex);
    Connect_ShowPasswordDialog();
    g_mutex_lock(&callback_mutex);
  }

  if(!waiting_for_success) {
    waiting_for_success = 1;
    show_upload_info_dialog(is_success);
  }

  g_mutex_unlock(&callback_mutex);
  g_thread_yield();

puts("waitForWebsocket wait");
  return TRUE; // keep waiting
}

//
// Functions to upload all server side cerificates to an openGalaxy server
//
// Callback function for the 'clicked' signal of:
// 'button_upload' GtkButton on the 'Upload' notebook tab
// of the opengalaxy-ca main window
//

void G_MODULE_EXPORT button_UploadCerts( GtkWidget *widget, gpointer data )
{

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *parent = gtk_widget_get_toplevel( widget );

  if(waiting_for_websocket_tag) g_source_remove(waiting_for_websocket_tag);

  websocketConnect(parent);
  waiting_for_websocket = 1;
  waiting_for_credentials = 0;
  waiting_for_success = 1;

  // wait for the websocket
  waiting_for_websocket_tag =  g_timeout_add_seconds(1, waitForWebsocket, (gpointer)parent);

}

//
// The function that loads and sends the cerificates to the server
//

void send_certs(void)
{
printf("%s\n",__func__);

  EVP_PKEY *sign_key = NULL, *encrypt_key = NULL;
  char *json;
  const char *err;

  // get the RSA keys and encrypt the credentials
  // - use the CA key to sign
  // - use the 'cred' public key to encrypt
  if(!ssl_evp_rsa_load_private_key(FN_CAKEY, &sign_key, pass_cb, (char*)window)){
    _gtk_display_error_dialog( window, "Error", "Could not load RSA private key!");
  gtk_widget_set_sensitive( button_upload, TRUE );
    return;
  }
  if(!ssl_evp_rsa_load_public_key(FN_CRED_PUBKEY, &encrypt_key)){
    _gtk_display_error_dialog( window, "Error", "Could not load RSA public key!");
  gtk_widget_set_sensitive( button_upload, TRUE );
    return;
  }

  // package the certs
  json = encrypt_certs_to_JSON(FN_CAPEM, FN_SERVERPEM, FN_SERVERKEY, FN_CRL, FN_CAPUBKEY, FN_CRED_KEY, &err, do_use_ssl, sign_key, encrypt_key);
  if(!json){
    _gtk_display_error_dialog( window, "Failed to encrypt", err, 0 );
  gtk_widget_set_sensitive( button_upload, TRUE );
    goto exit;
  }

  // Send the certificates in a format the server recognizes and is able to process
  Websocket_SendCommand("CERTS%s", json);

exit:
  ssl_pkey_free(sign_key);
  ssl_pkey_free(encrypt_key);
  ssl_free(json);
}

//
// The callback functions for the websocket connection
//

// this is called by the websocket thread:
// while trying to (re)connect
static void callback_connecting(void* user)
{
  puts("Connecting...");
  gtk_widget_set_sensitive( button_upload, FALSE );
}

// this is called by the websocket thread:
// when the connection is established
static void callback_online(void* user)
{
  puts("Online...");
  int s = 0;
  g_mutex_lock(&callback_mutex);

  s = Websocket_IsConnected();
  if(s == 1 /* no ssl */) send_certs();

  g_mutex_unlock(&callback_mutex);

  if(s == 3){
    // TODO
    // execute a delayed function in a couple of seconds
    // in case we do not receive a JSON_AUTHORIZATION_REQUIRED
    // when we connect (this happens when the user allready has a client
    // connection to this server from the same IP address)
  }
}

// this is called by the websocket thread:
// when we disconnected from the server
static void callback_offline(void* user)
{
  puts("Offline...");
}

// this is called by the websocket thread:
// when we receive data
static void callback_receive(const char* in, void* user)
{
  puts("Receive...");
  g_mutex_lock(&callback_mutex);

  json_item *i;
  json_object *o;
  char* typeDesc = NULL;
  char* replyText = NULL;
  int typeId = -1;
  int success = -1;

  // - decode the JSON object to a new rsa_aes_encrypted_data object.
  o = json_parse_objects(in);
  if(!o){
    g_mutex_unlock(&callback_mutex);
    return;
  }
  //json_print_objects(o);

  i = o->items;
  while( i != NULL ){
    if( i->data != NULL ){
      switch( i->data->type ){
        case json_string_value:
          if( strcmp( i->name->value, "typeDesc" ) == 0 ){
            typeDesc = g_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "replyText" ) == 0 ){
            replyText = g_strdup( i->data->content.string->value );
          }
          break;
        case json_number_value:
          if( strcmp( i->name->value, "typeId" ) == 0 ){
            typeId = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "success" ) == 0 ){
            success = i->data->content.number->value;
          }
          break;

        default:
          break;
      }
      i = i->next;
    }
  }
  json_free_objects(o);

  switch(typeId){
    case JSON_STANDARD_REPLY:
      Websocket_AsyncDisconnect();
      waiting_for_success = 0;
      is_success = success;
      break;
    case JSON_AUTHORIZATION_REQUIRED:
      strncpy(session_id, typeDesc, sizeof(session_id));
      waiting_for_credentials = 1;
      break;
    case JSON_AUTHENTICATION_ACCEPTED:
      send_certs();
      break;
    case -1:
      break;
    default:
printf("Message reason = %d\n", typeId);
      break;
  }

  g_free(typeDesc);
  g_free(replyText);
  g_mutex_unlock(&callback_mutex);
puts("Receive done...");
}

static void callback_connect_error(const char* address, void* user)
{
  puts("Connect Error...");
  Websocket_AsyncDisconnect();
  _gtk_display_error_dialog( GTK_WIDGET(user), "Error", "Could not connect to the openGalaxy server at '%s'", address);
  gtk_widget_set_sensitive( button_upload, TRUE );
}


