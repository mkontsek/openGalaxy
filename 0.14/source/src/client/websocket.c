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
 * This sourcefile is based on "libwebsockets test client"
 * (C) Copyright 2010-2015 Andy Green <andy@warmcat.com> 
 *
 */

//////////////////////////////////////////////////////////////////////////////
// WebSocket client interface ////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//
// Tested with libwebsockets version: 1.4 2a5774e
//

#include "atomic.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#endif

#include <stdbool.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib.h>
#include <glib/gprintf.h>
#pragma GCC diagnostic pop

#if ! HAVE_NO_SSL
#if HAVE_WOLFSSL
#include <wolfssl/openssl/ssl.h>
#else
#if HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#endif
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#define random rand
#else
#include <unistd.h>
#endif

#include "opengalaxy-client.h"
#include "connect.h"
#include "support.h"
#include "libwebsockets.h"
#include "websocket.h"
#include "broadcast.h"
#include "commander.h"
#include "log.h"

// Buffer sizes for in- and outgoing data
#define INPUT_BUFFER_SIZE 8192
#define OUTPUT_BUFFER_SIZE 8192


// connection parameters used
static int port = 0;
static int use_ssl = 0;
static int use_ssl_client = 0;
static char address[8192];

static const char cipher_list[] =
  "-ALL:-COMPLEMENTOFALL:"
  "ECDHE-ECDSA-AES256-GCM-SHA384:"
  "ECDHE-RSA-AES256-GCM-SHA384:"
  "ECDHE-ECDSA-AES128-GCM-SHA256:"         // ssllabs nr1 in chrome/firefox
  "ECDHE-RSA-AES128-GCM-SHA256:"           // ssllabs nr2 in chrome/firefox
  "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256:"  // ssllabs nr3/5 in chrome
  "ECDHE-RSA-CHACHA20-POLY1305-SHA256";    // ssllabs nr4/6 in chrome

static char ca_cert[8192];
static char client_cert[8192];
static char client_cert_key[8192];

// default values for the connection parameters
static char* default_address = "localhost";
#if __linux__
static int   default_port = 1500;
#else
static int   default_port = 443;
#endif
static int   default_use_ssl = 2; // allow self signed certs
static int   default_use_ssl_client = 1; // only makes sense when use_ssl is set


// libwebsockets variables
static struct lws_context_creation_info info;
static struct lws_context *context;
static struct lws *wsi_http;
static struct lws *wsi_commander;

static const struct lws_extension exts[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate"
	},
	{
		"deflate-frame",
		lws_extension_callback_pm_deflate,
		"deflate_frame"
	},
	{ NULL, NULL, NULL }
};

// connection state variables used by the main() in this thread
static volatile int libIsInitialized = 0; // nonzero when the websockets library is initialized
static volatile int mustQuit = 0;         // Set to non-zero to exit this thread
static volatile int isInitialized = 0;    // non-zero when this thread has been initialized
static volatile int isConnected = 0;      // non-zero when we are connected to a server
static volatile int doConnect = 0;        // Set to non-zero to connect using the connection parameters
static volatile int doDisconnect = 0;     // Set to non-zero to disconnect
static volatile int was_closed = 0;       // Set to non-zero (by the protocol cb) when the connection was closed
static volatile int forceDisconnect = 0;  // Set to non-zero to force a disconnect (even when still trying to connect)


static int deny_deflate; // Set to non-zero to disallow compressing the stream/data with deflate
static int deny_mux;     // Set to non-zero to disallow sticky mux opcode usage if ever used in channel

// Non-zero indicates there is data to be send for that protocol (see websocket callback function)
static volatile int websocket_commander_do_send = 0;
//static volatile int websocket_http_do_send = 0;

static volatile int do_send_authorization = 0;

GThread *WebsocketThreadId = NULL; // ID for this thread
static GMutex WebsocketMutex;      // Mutex to safeguard thread data


// Count of all protocols supported by our websocket
enum websocket_protocols {
  PROTOCOL_HTTP = 0,
  PROTOCOL_OPENGALAXY,
  PROTOCOL_COUNT
};


// Per session data for the http-protocol
struct websocket_per_session_data_http_protocol {
  ;// no data
};

// Per session data for the openGalaxy-websocket-protocol
struct websocket_per_session_data_opengalaxy_protocol {
  ;// no data
};

// list of supported protocols and callbacks
static int callback_http( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len );
static int callback_commander( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len );
static struct lws_protocols protocols[] = {
  {
    "openGalaxy-http-protocol",
    callback_http,
    sizeof( struct websocket_per_session_data_http_protocol ),
    INPUT_BUFFER_SIZE,
  },
  {
    "openGalaxy-websocket-protocol",
    callback_commander,
    sizeof( struct websocket_per_session_data_opengalaxy_protocol ),
    OUTPUT_BUFFER_SIZE,
  },
  { NULL, NULL, 0, 0 } // end of list
};


// output buffer for sending commands (openGalaxy-command-protocol)
//static unsigned char ws_output_buffer_internal[LWS_SEND_BUFFER_PRE_PADDING + OUTPUT_BUFFER_SIZE + LWS_SEND_BUFFER_POST_PADDING];
//static unsigned char *ws_output_buffer = &ws_output_buffer_internal[LWS_SEND_BUFFER_PRE_PADDING];


// for counting the commands send
static guint delayed_remove_overlay_tag = 0;
static int cmd_count = 0;


static char Websocket_username[8192];
static char Websocket_password[8192];
static char Websocket_session_id[64];

/*
static const char *reason2txt(int reason)
{
  switch(reason){
    case LWS_CALLBACK_ESTABLISHED: return "LWS_CALLBACK_ESTABLISHED";
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: return "LWS_CALLBACK_CLIENT_CONNECTION_ERROR";
    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH: return "LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH";
    case LWS_CALLBACK_CLIENT_ESTABLISHED: return "LWS_CALLBACK_CLIENT_ESTABLISHED";
    case LWS_CALLBACK_CLOSED: return "LWS_CALLBACK_CLOSED";
    case LWS_CALLBACK_CLOSED_HTTP: return "LWS_CALLBACK_CLOSED_HTTP";
    case LWS_CALLBACK_RECEIVE: return "LWS_CALLBACK_RECEIVE";
    case LWS_CALLBACK_RECEIVE_PONG: return "LWS_CALLBACK_RECEIVE_PONG";
    case LWS_CALLBACK_CLIENT_RECEIVE: return "LWS_CALLBACK_CLIENT_RECEIVE";
    case LWS_CALLBACK_CLIENT_RECEIVE_PONG: return "LWS_CALLBACK_CLIENT_RECEIVE_PONG";
    case LWS_CALLBACK_CLIENT_WRITEABLE: return "LWS_CALLBACK_CLIENT_WRITEABLE";
    case LWS_CALLBACK_SERVER_WRITEABLE: return "LWS_CALLBACK_SERVER_WRITEABLE";
    case LWS_CALLBACK_HTTP: return "LWS_CALLBACK_HTTP";
    case LWS_CALLBACK_HTTP_BODY: return "LWS_CALLBACK_HTTP_BODY";
    case LWS_CALLBACK_HTTP_BODY_COMPLETION: return "LWS_CALLBACK_HTTP_BODY_COMPLETION";
    case LWS_CALLBACK_HTTP_FILE_COMPLETION: return "LWS_CALLBACK_HTTP_FILE_COMPLETION";
    case LWS_CALLBACK_HTTP_WRITEABLE: return "LWS_CALLBACK_HTTP_WRITEABLE";
    case LWS_CALLBACK_FILTER_NETWORK_CONNECTION: return "LWS_CALLBACK_FILTER_NETWORK_CONNECTION";
    case LWS_CALLBACK_FILTER_HTTP_CONNECTION: return "LWS_CALLBACK_FILTER_HTTP_CONNECTION";
    case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED: return "LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED";
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: return "LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION";
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS: return "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS";
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS: return "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS";
    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION: return "LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION";
    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: return "LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER";
    case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY: return "LWS_CALLBACK_CONFIRM_EXTENSION_OKAY";
    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED: return "LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED";
    case LWS_CALLBACK_PROTOCOL_INIT: return "LWS_CALLBACK_PROTOCOL_INIT";
    case LWS_CALLBACK_PROTOCOL_DESTROY: return "LWS_CALLBACK_PROTOCOL_DESTROY";
    case LWS_CALLBACK_WSI_CREATE: return "LWS_CALLBACK_WSI_CREATE";
    case LWS_CALLBACK_WSI_DESTROY: return "LWS_CALLBACK_WSI_DESTROY";
    case LWS_CALLBACK_GET_THREAD_ID: return "LWS_CALLBACK_GET_THREAD_ID";
    case LWS_CALLBACK_ADD_POLL_FD: return "LWS_CALLBACK_ADD_POLL_FD";
    case LWS_CALLBACK_DEL_POLL_FD: return "LWS_CALLBACK_DEL_POLL_FD";
    case LWS_CALLBACK_CHANGE_MODE_POLL_FD: return "LWS_CALLBACK_CHANGE_MODE_POLL_FD";
    case LWS_CALLBACK_LOCK_POLL: return "LWS_CALLBACK_LOCK_POLL";
    case LWS_CALLBACK_UNLOCK_POLL: return "LWS_CALLBACK_UNLOCK_POLL";
    case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY: return "LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY";
    case LWS_CALLBACK_USER: return "LWS_CALLBACK_USER";
  }
  return "unknown";
}
*/

//
// Logging function for libwebsockets
//
static void emit_log( int level,  const char *msg )
{
#if ! __linux__
  Log_printf( "websocket: %s", msg );
#else
  Log_printf( "websocket: %s\n", msg );
#endif
}


// Define a type that can be used as linked list of commands to send
typedef struct ws_command_fifo_t {
  char *cmd;
  struct ws_command_fifo_t *next;
} ws_command_fifo_entry;

// Stack of commands to send
static struct ws_command_fifo_t *commands_to_send = NULL;


// Push a command to the stack of commands to send
static int ws_command_fifo_push( const char *cmd )
{
  ws_command_fifo_entry *new = g_malloc( sizeof( ws_command_fifo_entry ) );
  if( new ){
    new->cmd = g_strdup( cmd );
    new->next = NULL;
    if( !new->cmd ) goto err;
    if( commands_to_send ){
      ws_command_fifo_entry *l = commands_to_send;
      while( l->next ) l = l->next;
      l->next = new;
    }
    else {
      commands_to_send = new;
    }
  }
  return 0;
err:
  Log_printf( "websocket: ws_command_fifo_push( Failed to add a command! )\n" );
  if( new ) g_free( new );
  return -1;
}


// Pop a command from the stack of commands
// The returned string should not be modified or free'd
static const char* ws_command_fifo_pop( void )
{
  static char buffer[8192];
  char *retv = NULL;

  ws_command_fifo_entry *e = commands_to_send;
  if( e ){
    commands_to_send = e->next;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security" // do not complain about e->cmd not being a literal string
    g_snprintf( buffer, sizeof( buffer ), e->cmd );
#pragma GCC diagnostic pop
    retv = buffer;
    g_free( e->cmd );
    g_free( e );
  }

  return retv;
}


//
//  Callback for the http protocol
//
static int callback_http(
  struct lws *wsi,
  enum lws_callback_reasons reason,
  void *user,
  void *in,
  size_t len
)
{
  switch (reason) {
    case LWS_CALLBACK_CLIENT_RECEIVE:
      return 1;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
      return 1;

    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
      if ((strcmp(in, "deflate-stream") == 0) && deny_deflate) {
        Log_printf( "websocket: denied deflate-stream extension\n");
        return 1;
      }
      if ((strcmp(in, "deflate-frame") == 0) && deny_deflate) {
        Log_printf( "websocket: denied deflate-frame extension\n");
        return 1;
      }
      if ((strcmp(in, "x-google-mux") == 0) && deny_mux) {
        Log_printf( "websocket: denied x-google-mux extension\n");
        return 1;
      }
      break;

    default:
      break;
  }
  return 0;
}

//
//  Callback for the commander protocol
//
static int callback_commander(
  struct lws *wsi,
  enum lws_callback_reasons reason,
  void *user,
  void *in,
  size_t len
)
{
  //struct lws_context *context = lws_get_context(wsi);
  unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + OUTPUT_BUFFER_SIZE + LWS_SEND_BUFFER_POST_PADDING];
  int l, n;

  switch (reason) {

    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      g_mutex_unlock( &WebsocketMutex );
      Connect_setStatusOnline();
      g_mutex_lock( &WebsocketMutex );
      // start the ball rolling,
      // LWS_CALLBACK_CLIENT_WRITEABLE will come next service
      lws_callback_on_writable( wsi );
      break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
      if( forceDisconnect ){
        g_mutex_unlock( &WebsocketMutex );
        Connect_setStatusOffline();
        g_mutex_lock( &WebsocketMutex );
      }
      else {
        g_mutex_unlock( &WebsocketMutex );
        Connect_setStatusConnecting();
        g_mutex_lock( &WebsocketMutex );
      }
      was_closed = 1;
      doDisconnect = 1;
      if( !forceDisconnect ){
        doConnect = 1;
      }
      break;

    case LWS_CALLBACK_CLOSED:
      if( forceDisconnect ){
        g_mutex_unlock( &WebsocketMutex );
        Connect_setStatusOffline();
        g_mutex_lock( &WebsocketMutex );
      }
      else {
        g_mutex_unlock( &WebsocketMutex );
        Connect_setStatusConnecting();
        g_mutex_lock( &WebsocketMutex );
      }
      was_closed = 1;
      doDisconnect = 1;
      // Try to reconnect if the connection was not closed by us
      if( !forceDisconnect ){
        doConnect = 1;
      }
      break;

    case LWS_CALLBACK_PROTOCOL_DESTROY:
      if( forceDisconnect ){
        g_mutex_unlock( &WebsocketMutex );
        Connect_setStatusOffline();
        g_mutex_lock( &WebsocketMutex );
      }
      else {
        g_mutex_unlock( &WebsocketMutex );
        Connect_setStatusConnecting();
        g_mutex_lock( &WebsocketMutex );
      }
      break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
      ((char *)in)[len] = '\0';
      Websocket_AddMessage( "%s\n", (char *)in );
      break;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
      // Output a single command from the fifo list.
      // Schedule another write if the list is not yet empty.
      //
      // Message(s) to send?
      if( do_send_authorization ){
        Log_printf( "websocket: Sending user credentials to server\n");

        char *p = (char*)&buf[LWS_SEND_BUFFER_PRE_PADDING];
        snprintf( p, 8192, "%s\n%s\n%s",
          Websocket_session_id, Websocket_username, Websocket_password
        );
        lws_write(
          wsi,
          &buf[LWS_SEND_BUFFER_PRE_PADDING],
          strlen( p ),
          LWS_WRITE_TEXT
        );
        do_send_authorization = 0;
      }
      if( websocket_commander_do_send ){
        // yes, pop the first message and send it
        const char *cmd = ws_command_fifo_pop();
        if( cmd ){
          l = strlen( cmd );
          if( l > OUTPUT_BUFFER_SIZE ) l = OUTPUT_BUFFER_SIZE;
          memcpy( &buf[LWS_SEND_BUFFER_PRE_PADDING], cmd, l );
          n = lws_write( wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], l, LWS_WRITE_TEXT );
          if( n < 0 ){ // (sanity check, test for write error)
            Log_printf( "websocket:commander: ERROR %d writing to socket\n", n );
            return -1; // (fatal, close connection)
          }
        }
        if( !commands_to_send ){
          websocket_commander_do_send = 0;
        }
      }
      lws_callback_on_writable( wsi );
      break;

    default:
      break;
  }
  return 0;
}


//
// Initialzes the websockets library
//
static int websocket_lib_init(void)
{
  if( libIsInitialized ) return 0;

  memset(&info, 0, sizeof( info ) );

  info.port = CONTEXT_PORT_NO_LISTEN;
  info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
  info.extensions = exts;
#endif
  info.gid = -1;
  info.uid = -1;

#if ! HAVE_NO_SSL
  // The CA and client cert to connect with
  if( use_ssl != 0 ){
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    if( strlen( ca_cert ) ) info.ssl_ca_filepath = ca_cert;
    if( strlen(client_cert) ) info.ssl_cert_filepath = client_cert;
    if( strlen(client_cert_key) ) info.ssl_private_key_filepath = client_cert_key;
    info.ssl_cipher_list = cipher_list;
  }
#endif

  lws_set_log_level( LLL_ERR | LLL_WARN /*| LLL_NOTICE | LLL_INFO | LLL_DEBUG | LLL_HEADER | LLL_EXT | LLL_CLIENT | LLL_LATENCY | LLL_PARSER*/, emit_log );

  context = lws_create_context( &info );
  if( context == NULL ){
    Log_printf( "ERROR: websocket_lib_init( 'Creating libwebsocket context failed' );\n" );
    return 1;
  }

  libIsInitialized = 1;

  return 0;
}


//
// Destroys the current websockets library instance
//
static void websocket_lib_exit(void)
{
  lws_context_destroy( context );
  libIsInitialized = 0;
}


//
// The main() function for this thread
//
static gpointer Websocket_ThreadMain( gpointer data )
{
  int forceQuit = 0;

  struct lws_client_connect_info info_http, info_ws;
  memset(&info_http, 0, sizeof(info_http));
  memset(&info_ws, 0, sizeof(info_ws));

  while( !forceQuit ){
    g_mutex_lock( &WebsocketMutex );

    // Disconnect & destroy library instance?
    if( isConnected && doDisconnect ){
      websocket_lib_exit();
      doDisconnect = 0;
      isConnected = 0;
      g_mutex_unlock( &WebsocketMutex );
      g_thread_yield ();
      continue;
    }

    // (re)initialize library and connect?
    if( !isConnected && doConnect && !mustQuit && !forceDisconnect ){

      g_mutex_unlock( &WebsocketMutex );
      Connect_setStatusConnecting();
      g_mutex_lock( &WebsocketMutex );

      if( websocket_lib_init() == 0 ){
        was_closed = 0;
        doConnect = 0;
        isConnected = 1;

        info_http.port = port;
        info_http.address = address;
        info_http.port = port;
        info_http.path = "/";
        info_http.context = context;
        info_http.ssl_connection = use_ssl;
        info_http.host = address;
        info_http.origin = address;
        info_http.ietf_version_or_minus_one = -1;
        info_http.client_exts = exts;
        info_http.protocol = protocols[PROTOCOL_HTTP].name;

        info_ws.port = port;
        info_ws.address = address;
        info_ws.port = port;
        info_ws.path = "/";
        info_ws.context = context;
        info_ws.ssl_connection = use_ssl;
        info_ws.host = address;
        info_ws.origin = address;
        info_ws.ietf_version_or_minus_one = -1;
        info_ws.client_exts = exts;
        info_ws.protocol = protocols[PROTOCOL_OPENGALAXY].name;

        // connect first protocol (http)
        // (Not actually http, the connection is upgraded to a websocket...)
        wsi_http = lws_client_connect_via_info( &info_http );
//        wsi_http = lws_client_connect(context, address, port, use_ssl, "/", address, address, protocols[PROTOCOL_HTTP].name, -1);
        if(wsi_http == NULL ){
          // Error
          Log_printf( "ERROR: WebsocketThreadMain( 'HTTP protocol failed to connect.' );\n" );
          doDisconnect = 1; // un-init the websocket library on failure (on the next loop iteration)
          doConnect = 1; // Try again (on the loop iteration after that)
        }
        else {
          // connect second protocol (websocket)
          //info_http.parent_wsi = wsi_http;
          wsi_commander = lws_client_connect_via_info( &info_ws );
//          wsi_commander = lws_client_connect(context, address, port, use_ssl, "/", address, address, protocols[PROTOCOL_OPENGALAXY].name, -1);
          if(wsi_commander == NULL ){
            // Error
            Log_printf( "ERROR: WebsocketThreadMain( 'websocket protocol failed to connect.' );\n" );
            doDisconnect = 1; // un-init the websocket library on failure (on the next loop iteration)
            doConnect = 1; // Try again (on the loop iteration after that)
          }
        }

      }
      else {
        doDisconnect = 0;
        doConnect = 0;
      }
      g_mutex_unlock( &WebsocketMutex );
      g_thread_yield ();
      continue;
    }

    // Service the websockets
    if( libIsInitialized && !was_closed ){
      // Service the websockets
      lws_service( context, 0 );
    }

    // The signal to quit was given?
    if( mustQuit ){
      // gracefully disconnect first
      if( isConnected ){
        doDisconnect = 1;
        continue;
      }
      // break out of the infinite loop
      forceQuit = 1;
    }

    // reset state variables after forced disconnect
    if( forceDisconnect && !isConnected ){
      forceDisconnect = 0;
      doDisconnect = 0;
      doConnect = 0;
    }

    g_mutex_unlock( &WebsocketMutex );
    g_thread_yield ();
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 50000000; // 50ms
    nanosleep( &ts, NULL );

  }
  g_thread_exit( 0 );
  return NULL;
}


//
// Removes any command status overlay from the toolbar after a timeout period
//
static gboolean delayed_remove_overlay( gpointer user_data )
{
  gtk_widget_set_opacity( GTK_WIDGET( commandStatusSending ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( commandStatusReady ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( commandStatusError ), 0.0 );
  gtk_widget_set_opacity( GTK_WIDGET( commandStatusIdle ), 1.0 );
  delayed_remove_overlay_tag = 0;
  return FALSE;
}


//
// Callback for JSON_STANDARD_REPLY,
//  displays the success/error command status on the toolbar.
//
void cbWebsocket_Commander_StandardReply( struct commander_reply_t * c )
{
  if( cmd_count > 0 ){
    cmd_count--;
  }
  if( c->success == 1 ){
    if( delayed_remove_overlay_tag != 0) g_source_remove( delayed_remove_overlay_tag ); // Cancel any pending timeout
    gtk_widget_set_opacity( GTK_WIDGET( commandStatusSending ), 0.0 );
    gtk_widget_set_opacity( GTK_WIDGET( commandStatusReady ), 1.0 );
    gtk_widget_set_opacity( GTK_WIDGET( commandStatusError ), 0.0 );
    gtk_widget_set_opacity( GTK_WIDGET( commandStatusIdle ), 0.0 );
    delayed_remove_overlay_tag = g_timeout_add_seconds( 5, delayed_remove_overlay, NULL );
  }
  else {
    if( delayed_remove_overlay_tag != 0) g_source_remove( delayed_remove_overlay_tag ); // Cancel any pending timeout
    gtk_widget_set_opacity( GTK_WIDGET( commandStatusSending ), 0.0 );
    gtk_widget_set_opacity( GTK_WIDGET( commandStatusReady ), 0.0 );
    gtk_widget_set_opacity( GTK_WIDGET( commandStatusError ), 1.0 );
    gtk_widget_set_opacity( GTK_WIDGET( commandStatusIdle ), 0.0 );
    delayed_remove_overlay_tag = g_timeout_add_seconds( 5, delayed_remove_overlay, NULL );
  }
}


//
// call these from the main thread
//

//
// Initialize thread and set the default connection parameters
// Returns the GThread or NULL on error
//
GThread *Websocket_InitThread( void )
{
  g_mutex_lock( &WebsocketMutex );
  if( !isInitialized ){
    isInitialized = 1;
    g_mutex_unlock( &WebsocketMutex );
    WebsocketThreadId = g_thread_try_new( "", Websocket_ThreadMain, NULL, NULL );
    if( ! WebsocketThreadId ){
      g_mutex_lock( &WebsocketMutex );
      isInitialized = 0;
      g_mutex_unlock( &WebsocketMutex );
    }
  }
  else g_mutex_unlock( &WebsocketMutex );
  if( WebsocketThreadId ){
    Websocket_SetConnectParameters( default_address, default_port, default_use_ssl, NULL, NULL, NULL );
    Commander_RegisterCallback( JSON_STANDARD_REPLY, cbWebsocket_Commander_StandardReply );
  }
  return WebsocketThreadId;
}


gpointer Websocket_ExitThread( void )
{
  g_mutex_lock( &WebsocketMutex );
  doDisconnect = 1;
  forceDisconnect = 1;
  mustQuit = 1;
  g_mutex_unlock( &WebsocketMutex );

  gpointer retv = g_thread_join( WebsocketThreadId );

  g_mutex_lock( &WebsocketMutex );
  if( isInitialized ){
    isInitialized = 0;
  }
  g_mutex_unlock( &WebsocketMutex );

  return retv;
}


int Websocket_IsConnected( void )
{
  g_mutex_lock( &WebsocketMutex );
  int retv = isConnected && !doConnect;
  g_mutex_unlock( &WebsocketMutex );
  return retv;
}


void Websocket_AsyncConnect( void )
{
  g_mutex_lock( &WebsocketMutex );
  doConnect = 1;
  g_mutex_unlock( &WebsocketMutex );
}


void Websocket_AsyncDisconnect( void )
{
  g_mutex_lock( &WebsocketMutex );
  doDisconnect = 1;
  forceDisconnect = 1;
  g_mutex_unlock( &WebsocketMutex );
}


//
// Sets connection parameters
//
// addr     = URL or IP address or NULL to use the default
// prt      = port number to use or 0 to use the default
// ssl      = nonzero to use SSL
// auth     = the client cert or null
// auth_key = the client cert key or null
// ca       = the ca cert to use
//
void Websocket_SetConnectParameters( char *addr, int prt, int ssl, char* auth, char* auth_key, char *ca )
{
//printf("%d:%s\n",__LINE__,__FILE__);
  g_mutex_lock( &WebsocketMutex );

  if( addr ){
    snprintf( address, sizeof( address ), "%s", addr );
  }
  else {
    snprintf( address, sizeof( address ), "%s", default_address );
  }

  if( prt ) port = prt;
  else port = default_port;

  if( ssl ) use_ssl = 2; // allow selfsigned certs
  else use_ssl = 0;

  if( auth ){
    use_ssl_client = default_use_ssl_client;
    snprintf( client_cert, sizeof( client_cert ), "%s", auth );
  }
  else {
    snprintf( client_cert, sizeof( client_cert ), "%s", "" );
    use_ssl_client = 0;
  }
  if( auth_key ){
    snprintf( client_cert_key, sizeof( client_cert_key ), "%s", auth_key );
  }
  else {
    snprintf( client_cert_key, sizeof( client_cert_key ), "%s", "" );
  }

  if( ca ){
    snprintf( ca_cert, sizeof( ca_cert ), "%s", ca );
  }
  else {
    snprintf( ca_cert, sizeof( ca_cert ), "%s", "" );
  }
  g_mutex_unlock( &WebsocketMutex );
}


bool Websocket_SendCommand( const char *cmd, ... )
{
  bool retv = false;
  static char buf[1024];
  va_list args;

  g_mutex_lock( &WebsocketMutex );

  va_start( args, cmd );
  g_vsnprintf( buf, 1024, cmd, args );
  va_end( args );

  Log_printf( "websocket: SendCommand: %s\n", buf );

  if( isConnected ){
    if( ws_command_fifo_push( buf ) == 0 ){
      websocket_commander_do_send = 1;
      retv = true;
      cmd_count++;
      if( delayed_remove_overlay_tag != 0) g_source_remove( delayed_remove_overlay_tag ); // Cancel any pending timeout
      gtk_widget_set_opacity( GTK_WIDGET( commandStatusSending ), 1.0 );
      gtk_widget_set_opacity( GTK_WIDGET( commandStatusReady ), 0.0 );
      gtk_widget_set_opacity( GTK_WIDGET( commandStatusError ), 0.0 );
      gtk_widget_set_opacity( GTK_WIDGET( commandStatusIdle ), 0.0 );
      delayed_remove_overlay_tag = g_timeout_add_seconds( 5, delayed_remove_overlay, NULL );
    }
  }
  g_mutex_unlock( &WebsocketMutex );
  return retv;
}


int Websocket_SendCredentials( const char *sid, const char *username, const char *password )
{
  if( sid == NULL || !strlen( sid ) ) return 1;
  if( username == NULL || !strlen( username ) ) return 1;
  if( password == NULL || !strlen( password ) ) return 1;
  if( strlen( sid ) >= sizeof( Websocket_session_id ) ) return 1;
  if( strlen( username ) >= sizeof( Websocket_username ) ) return 1;
  if( strlen( password ) >= sizeof( Websocket_password ) ) return 1;

  g_mutex_lock( &WebsocketMutex );

  Log_printf( "Websocket_SendCredentials( %s, %s, %s )\n", sid, username, password );

  strcpy( Websocket_session_id, sid );
  strcpy( Websocket_username, username );
  strcpy( Websocket_password, password );

  do_send_authorization = 1;
  lws_callback_on_writable( wsi_commander );


  g_mutex_unlock( &WebsocketMutex );
  return 0;
}





