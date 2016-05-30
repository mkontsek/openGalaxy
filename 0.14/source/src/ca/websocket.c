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
 * Functions to connect to an openGalaxy server using libwebsockets and glib
 */

#include "atomic.h"

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

#include "websocket.h"

// Buffer sizes for in- and outgoing data
#define INPUT_BUFFER_SIZE 65536
#define OUTPUT_BUFFER_SIZE 65536

// in seconds
int websocket_connect_timeout = 5;

GThread *WebsocketThreadId = NULL; // ID for this thread
static GMutex WebsocketMutex;      // Mutex to safeguard thread data

static WebsocketCallbacks* callbacks = NULL; // the connection state callbacks

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

static struct lws_context_creation_info info;
static struct lws_context *context = NULL;
static struct lws *wsi_http = NULL;
static struct lws *wsi_galaxy = NULL;

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
static volatile int mustQuit = 0;         // Set to non-zero to exit this thread
static volatile int isInitialized = 0;    // non-zero when this thread has been initialized
static volatile int isConnected = 0;      // non-zero when we are connected to a server
static volatile int doConnect = 0;        // Set to non-zero to connect using the connection parameters
static volatile int doDisconnect = 0;     // Set to non-zero to disconnect
static volatile int was_closed = 0;       // Set to non-zero (by the protocol cb) when the connection was closed
static volatile int forceDisconnect = 0;  // Set to non-zero to force a disconnect (even when still trying to connect)

static int deny_deflate;
static int deny_mux;

static guint waitForWebsocketConnect_tag = 0;

enum websocket_protocols {
  PROTOCOL_HTTP = 0,
  PROTOCOL_OPENGALAXY,
  PROTOCOL_COUNT
};

struct websocket_per_session_data_http_protocol {
  ;// no data
};

struct websocket_per_session_data_opengalaxy_protocol {
  ;// no data
};

static int callback_http( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len );
static int callback_galaxy( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len );

static struct lws_protocols protocols[] = {
  {
    "openGalaxy-http-protocol",
    callback_http,
    sizeof( struct websocket_per_session_data_http_protocol ),
    INPUT_BUFFER_SIZE,
  },
  {
    "openGalaxy-websocket-protocol",
    callback_galaxy,
    sizeof( struct websocket_per_session_data_opengalaxy_protocol ),
    OUTPUT_BUFFER_SIZE,
  },
  { NULL, NULL, 0, 0 } // end of list
};

// Define a type that can be used as linked list of commands to send
typedef struct command_list_t {
  char *cmd;
  struct command_list_t *next;
} command_list_entry;

// linked-list of commands to send
static struct command_list_t *command_list = NULL;

// The current command
static char* current_command = NULL;


// Logging function for libwebsockets
static void emit_log( int level,  const char *msg )
{
//  printf( "websocket: %s\n", msg );
}


// Push a (copy of a) command to the list of commands to send
static inline int add_command(const char *cmd)
{
  command_list_entry *i = g_malloc(sizeof(command_list_entry));

  if(i){
    i->cmd = g_strdup(cmd);
    i->next = NULL;
    if(!i->cmd) goto err;
    if(command_list){
      command_list_entry *l = command_list;
      while( l->next ) l = l->next;
      l->next = i;
    }
    else {
      command_list = i;
    }
    return 1; // success
  }

err:
  if(i) g_free(i);
  return 0;
}


// Pop a command from the list of commands
static inline char* get_command(void)
{
  command_list_entry *e = command_list;

  if(e){
    command_list = e->next;
    current_command = e->cmd;
    g_free(e);
    return current_command;
  }

  return NULL;
}


gboolean G_MODULE_EXPORT waitForWebsocketConnect(gpointer user_data)
{
  if(callbacks && callbacks->connect_error) callbacks->connect_error(address, callbacks->user);
  waitForWebsocketConnect_tag = 0;
  Websocket_AsyncDisconnect();
  return FALSE;
}


// Callback for the http protocol
static int callback_http(
  struct lws *wsi,
  enum lws_callback_reasons reason,
  void *user,
  void *in,
  size_t len
)
{
  switch (reason) {
    case LWS_CALLBACK_PROTOCOL_INIT:
      // start a timed function, if it isn't cancelled by
      // LWS_CALLBACK_CLIENT_ESTABLISHED we know we could not connect
      if(!waitForWebsocketConnect_tag){
        waitForWebsocketConnect_tag =  g_timeout_add_seconds(websocket_connect_timeout, waitForWebsocketConnect, NULL);
      }
      break;

    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      // cancel the timed function, connect was successfull
      if(waitForWebsocketConnect_tag) g_source_remove(waitForWebsocketConnect_tag);
      waitForWebsocketConnect_tag = 0;
      break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
      return 1;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
      return 1;

    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
      if ((strcmp(in, "deflate-stream") == 0) && deny_deflate) {
        emit_log(LLL_ERR, "websocket: denied deflate-stream extension");
        return 1;
      }
      if ((strcmp(in, "deflate-frame") == 0) && deny_deflate) {
        emit_log(LLL_ERR, "websocket: denied deflate-frame extension");
        return 1;
      }
      if ((strcmp(in, "x-google-mux") == 0) && deny_mux) {
        emit_log(LLL_ERR, "websocket: denied x-google-mux extension");
        return 1;
      }
      break;

    default:
      break;
  }
  return 0;
}


//
//  Callback for the openGalaxy websocket protocol
//
static int callback_galaxy(
  struct lws *wsi,
  enum lws_callback_reasons reason,
  void *user,
  void *in,
  size_t len
)
{
  static unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + OUTPUT_BUFFER_SIZE];
  int l, n;
  char *cmd;


  switch(reason){

    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      // online callback
      g_mutex_unlock(&WebsocketMutex);
      if(callbacks && callbacks->online) callbacks->online(callbacks->user);
      g_mutex_lock(&WebsocketMutex);
      // start processing commands
      lws_callback_on_writable(wsi);
      break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
      if(forceDisconnect){
        // offline callback
        g_mutex_unlock(&WebsocketMutex);
        if(callbacks && callbacks->offline) callbacks->offline(callbacks->user);
        g_mutex_lock(&WebsocketMutex);
      }
      else {
        // connecting callback
        g_mutex_unlock(&WebsocketMutex);
        if(callbacks && callbacks->connecting) callbacks->connecting(callbacks->user);
        g_mutex_lock(&WebsocketMutex);
      }

      was_closed = 1;
      doDisconnect = 1;
      if(!forceDisconnect){
        doConnect = 1;
      }
      break;

    case LWS_CALLBACK_CLOSED:
      // offline callback
      g_mutex_unlock(&WebsocketMutex);
      if(callbacks && callbacks->offline) callbacks->offline(callbacks->user);
      g_mutex_lock(&WebsocketMutex);
      was_closed = 1;
      doDisconnect = 1;
      // Try to reconnect if the connection was not closed by us
      if(!forceDisconnect){
        doConnect = 1;
      }
      break;

    case LWS_CALLBACK_PROTOCOL_DESTROY:
      break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
      // recieve callback
      ((char *)in)[len] = '\0';
      g_mutex_unlock(&WebsocketMutex);
      if(callbacks && callbacks->receive) callbacks->receive(in, callbacks->user);
      g_mutex_lock(&WebsocketMutex);
      break;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
      // Output a single command from the commands list.
      cmd = get_command();
      if(cmd){
        l = strlen(cmd);
        if(l > OUTPUT_BUFFER_SIZE){
          l = OUTPUT_BUFFER_SIZE;
          emit_log(LLL_ERR, "command buffer overflow!");
        }
        memcpy((char*)&buf[LWS_SEND_BUFFER_PRE_PADDING], cmd, l);
        g_free(cmd);
        n = lws_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], l, LWS_WRITE_TEXT);
        if(n < 0){ // (sanity check, test for write error)
          emit_log(LLL_ERR, "ERROR writing to socket");
          return 1; // (fatal, close connection)
        }
      }
      // keep going
      lws_callback_on_writable(wsi);
      break;

    default:
      break;
  }
  return 0;
}


//
// Initialzes the libwebsockets library
//
static int websocket_lib_init(void)
{
  if(context) return 1; // success

  memset(&info, 0, sizeof(info));

  info.port = CONTEXT_PORT_NO_LISTEN; // no listen port, were a client only
  info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
  info.extensions = exts;
#endif
  info.gid = -1;
  info.uid = -1;

  // The CA and client cert to connect with
  if(use_ssl != 0){
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    if(strlen(ca_cert)) info.ssl_ca_filepath = ca_cert;
    if(strlen(client_cert)) info.ssl_cert_filepath = client_cert;
    if(strlen(client_cert_key)) info.ssl_private_key_filepath = client_cert_key;
    info.ssl_cipher_list = cipher_list;
  }

  lws_set_log_level( LLL_ERR | LLL_WARN /*| LLL_NOTICE | LLL_INFO | LLL_DEBUG | LLL_HEADER | LLL_EXT | LLL_CLIENT | LLL_LATENCY | LLL_PARSER*/, emit_log );

  context = lws_create_context(&info);
  if( context == NULL ){
    emit_log(LLL_ERR, "Creating libwebsocket context failed");
    return 0;
  }

  return 1;
}


//
// Destroys the current websockets library context
//
static void websocket_lib_exit(void)
{
  if(context){
    lws_context_destroy(context);
    context = NULL;
  }
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
    if(isConnected && doDisconnect){
      websocket_lib_exit();
      doDisconnect = 0;
      isConnected = 0;
      g_mutex_unlock(&WebsocketMutex);
      g_thread_yield();
      continue;
    }

    // (re)initialize library and connect?
    if(!isConnected && doConnect && !mustQuit && !forceDisconnect){

      // connecting callback
      g_mutex_unlock( &WebsocketMutex );
      if(callbacks && callbacks->connecting) callbacks->connecting(callbacks->user);
      g_mutex_lock( &WebsocketMutex );

      if( websocket_lib_init() ){
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

        if(wsi_http == NULL){
          // Error
          emit_log(LLL_ERR, "HTTP protocol failed to connect.");
          doDisconnect = 1; // un-init the websocket library on failure (on the next loop iteration)
        }
        else {
          // connect second protocol (websocket)
          //info_http.parent_wsi = wsi_http;
          wsi_galaxy = lws_client_connect_via_info(&info_ws);
          if(wsi_galaxy == NULL ){
            // Error
            emit_log(LLL_ERR, "OpenGalaxy protocol failed to connect.");
            doDisconnect = 1; // un-init the websocket library on failure (on the next loop iteration)
          }
        }

      }
      else {
        doDisconnect = 0;
        doConnect = 0;
      }
      g_mutex_unlock(&WebsocketMutex);
      g_thread_yield();
      continue;
    }

    // Service the websockets
    if(context && !was_closed){
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
    if(forceDisconnect && !isConnected){
      forceDisconnect = 0;
      doDisconnect = 0;
      doConnect = 0;
    }

    g_mutex_unlock(&WebsocketMutex);
    g_thread_yield();
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 50000000; // 50ms
    nanosleep(&ts, NULL);

  }
  g_thread_exit(0);
  return NULL;
}

//
// Exported functions
//

//
// Initialize thread and set the default connection parameters
// Returns the GThread or NULL on error
//
GThread *Websocket_InitThread(void)
{
  g_mutex_lock(&WebsocketMutex);
  if(!isInitialized){
    isInitialized = 1;
    g_mutex_unlock(&WebsocketMutex);
    WebsocketThreadId = g_thread_try_new("", Websocket_ThreadMain, NULL, NULL);
    if(!WebsocketThreadId){
      g_mutex_lock(&WebsocketMutex);
      isInitialized = 0;
      g_mutex_unlock(&WebsocketMutex);
    }
  }
  else g_mutex_unlock(&WebsocketMutex);
  if(WebsocketThreadId){
    Websocket_SetConnectParameters(default_address, default_port, default_use_ssl, NULL, NULL, NULL);
  }
  return WebsocketThreadId;
}


void Websocket_ExitThread(void)
{
  g_mutex_lock( &WebsocketMutex );
  doDisconnect = 1;
  forceDisconnect = 1;
  mustQuit = 1;
  g_mutex_unlock( &WebsocketMutex );

  (gpointer) g_thread_join( WebsocketThreadId );

  g_mutex_lock( &WebsocketMutex );
  if( isInitialized ){
    isInitialized = 0;
  }
  g_mutex_unlock( &WebsocketMutex );
}

// disconnected: 0
// connected using http: 1
// connected using https: 2
// using client certificate: 3
int Websocket_IsConnected( void )
{
  int retv = 0;
  g_mutex_lock( &WebsocketMutex );
  retv = isConnected && !doConnect;
  if(retv && use_ssl){
    retv++;
    if(use_ssl_client) retv++;
  }
  g_mutex_unlock( &WebsocketMutex );
  return retv;
}


int Websocket_AsyncConnect(WebsocketCallbacks* cb)
{
  if(!cb) return 0;
  g_mutex_lock(&WebsocketMutex);
  callbacks = cb;
  doConnect = 1;
  g_mutex_unlock( &WebsocketMutex );
  return 1;
}

void Websocket_AsyncDisconnect( void )
{
  g_mutex_lock( &WebsocketMutex );
  doDisconnect = 1;
  forceDisconnect = 1;
  g_mutex_unlock( &WebsocketMutex );
}


void Websocket_SetConnectParameters( char *addr, int prt, int ssl, char* cert, char* cert_key, char *ca )
{
  g_mutex_lock(&WebsocketMutex);

  if(addr){
    g_snprintf(address, sizeof(address), "%s", addr);
  }
  else {
    g_snprintf(address, sizeof( address ), "%s", default_address);
  }

  if(prt) port = prt;
  else port = default_port;

  if(ssl) use_ssl = 2; // allow selfsigned certs
  else use_ssl = 0;

  if(cert){
    use_ssl_client = default_use_ssl_client;
    g_snprintf(client_cert, sizeof( client_cert ), "%s", cert);
  }
  else {
    g_snprintf( client_cert, sizeof( client_cert ), "%s", "" );
    use_ssl_client = 0;
  }
  if(cert_key){
    g_snprintf(client_cert_key, sizeof(client_cert_key), "%s", cert_key);
  }
  else {
    g_snprintf(client_cert_key, sizeof(client_cert_key), "%s", "");
  }

  if(ca){
    g_snprintf(ca_cert, sizeof(ca_cert), "%s", ca);
  }
  else {
    g_snprintf(ca_cert, sizeof( ca_cert ), "%s", "");
  }
  g_mutex_unlock( &WebsocketMutex );
}


int Websocket_SendCommand(const char *cmd, ...)
{
  static char *buf;
  char b;
  va_list args;
  size_t len;

  g_mutex_lock(&WebsocketMutex);

  va_start(args, cmd);
  len = g_vsnprintf(&b, 1, cmd, args);
  va_end(args);

  if(len > OUTPUT_BUFFER_SIZE){
    emit_log(LLL_ERR, "Message is to large, unable to send!");
    return 1;
  }

  va_start(args, cmd);
  buf = g_malloc(len+1);
  g_vsnprintf(buf, len+1, cmd, args);
  va_end(args);


  if(!add_command(buf)){
    g_free(buf);
    g_mutex_unlock(&WebsocketMutex);
    return 1;
  }

  g_free(buf);
  g_mutex_unlock(&WebsocketMutex);
  return 0;
}


int Websocket_SendCredentials( const char *sid, const char *username, const char *password )
{
  if(!sid) sid = "";
  if(!username) username = "";
  if(!password) password = "";
  return Websocket_SendCommand("%s\n%s\n%s", sid, username, password);
}

