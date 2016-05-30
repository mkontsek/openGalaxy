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

 /* For libwebsockets API v1.7.5 */

#ifndef __OPENGALAXY_SERVER_WEBSOCKET_HPP__
#define __OPENGALAXY_SERVER_WEBSOCKET_HPP__

// increase/decrease verbosity
// for certificates parsing
//#define MAX_VERBOSE_CERTS
#undef MAX_VERBOSE_CERTS

#include "atomic.h"
#include <limits>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <iostream>

#include "Array.hpp"
#include "opengalaxy.hpp"
#include "session_id.hpp"
#include "Session.hpp"
#include "context_options.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#endif
#include "libwebsockets.h"
//#include "private-libwebsockets.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

// Some HTTP status codes
#ifndef HTTP_STATUS_MOVED_PERMANENTLY
#define HTTP_STATUS_MOVED_PERMANENTLY 301
#endif
#ifndef HTTP_STATUS_FOUND
#define HTTP_STATUS_FOUND 302
#endif
#ifndef HTTP_STATUS_TEMPORARY_REDIRECT
#define HTTP_STATUS_TEMPORARY_REDIRECT 307
#endif
#ifndef HTTP_STATUS_PERMANENT_REDIRECT
#define HTTP_STATUS_PERMANENT_REDIRECT 308
#endif

namespace openGalaxy {

// Encodes the given ASCII C-string into an UTF-8 string object.
void utf8encode(const char *in, std::string& out);


// Per session data for each implemented protocol.
// Each contains at least a class session_id to keep track of the session.
//
struct per_session_data_http_protocol {
  session_id session;
  int fd; // fd for the file we are currently serving
};
struct per_session_data_opengalaxy_protocol {
  session_id session;
  bool send_data; // true when there is a command reply to send
};


class Websocket {

public:
  constexpr static int WS_BUFFER_SIZE = 4096;

  // Make good use of libwebsockets's context user-data facility.
  // (Use it to keep track of this Websocket instance and all of its sessions)
  class ContextUserData {
  public:
    class Websocket *websocket;
    ObjectArray<class Session*> sessions;
  } ctx_user_data;

private:

  constexpr static const char *www_root_document = "/index.html";
  constexpr static const char *fmt_redirect_uri = "%s?%s%llX"; // uri?query=id

  // Used to format a decoded SIA message (itself a JSON object) as a 'command reply' JSON object.
  constexpr static const char* json_sia_message_fmt =
    "{\"typeId\":0,\"typeDesc\":\"SIA Message\",\"sia\":%s}";


  // Count of all protocols
  enum {
    PROTOCOL_HTTP = 0,
    PROTOCOL_OPENGALAXY,
    PROTOCOL_COUNT
  };

  // Provide a method that refers back to openGalaxy
  class openGalaxy *m_openGalaxy;

  // Supported extentions
  static const struct lws_extension exts[];

  // List of SIA messages to be 'broadcasted' to all clients
  struct BroadcastedMessage { // <- allocated by tmalloc() !
    char *data; // <- allocated by tmalloc() !
    size_t len;
  };
  class BroadcastedMessagesArray : public Array<BroadcastedMessage*> {
  public:
    ~BroadcastedMessagesArray();
    void remove(int nIndex);
  };

  // List of messages the panel has send us in response to commands that were executed.
  struct CommandReplyMessage { // <- allocated by tmalloc() !
    session_id session;
    char *reply; // <- allocated by tmalloc() !
  };
  class CommandReplyMessagesArray : public Array<CommandReplyMessage*> {
  public:
    ~CommandReplyMessagesArray();
    void remove(int nIndex);
  };

  // List of blacklisted IP addresses
  class BlacklistedIpAddress {
  public:
    std::string ip;
    long long timeout_minutes;
    std::chrono::high_resolution_clock::time_point start;

    BlacklistedIpAddress(const char* ip_address, unsigned long minutes)
      : ip(ip_address), timeout_minutes(minutes) {
      start = std::chrono::high_resolution_clock::now();
    }
  };

  // Thread data for this instance of class Websocket
  std::thread *m_thread;

  // Context of our libwebsocket 'instance'
  struct lws_context *context;

  // List of messages to send to all websocket clients
  BroadcastedMessagesArray broadcast_msg;
  // A mutex to protect the list.
  std::mutex m_broadcast_mutex;

  // List of status messages added by the commander thread in response to
  // each command, to be sent to their 'owning' session.
  CommandReplyMessagesArray command_replies;
  // A mutex to protect the list.
  std::mutex m_command_mutex;

  // A list of IP addresses that were blacklisted after not being able
  // to authenticate a client connection.
  class ObjectArray<BlacklistedIpAddress*> blacklist;

  // Called periodicly to remove IP addresses from the blacklist after an amount of time has passed.
  void check_blacklist_timeouts(void);

  // An empty callback function (used when executing a 'CODE-ALARM' command in
  // response to a client certificate that failed authentication).
  static void blacklist_dummy_callback(openGalaxy&,char*,int);

  // Non-zero indicates there is at least 1 SIA message
  // to be broadcasted to all clients
  volatile int broadcast_do_send;

  // Count of connected clients
  volatile int broadcast_nclients;

  // Counter that keeps track of how many clients the current
  // SIA message has been send to.
  volatile int broadcast_nclients_done;

  // set to 1 after certs were downloaded, restarts after 5..10 seconds
  int restart_server;

  //
  // Buffers used by the callback for the HTTP protocol:
  //
  char http_path_buffer[8192];
  unsigned char http_file_buffer[
    LWS_SEND_BUFFER_PRE_PADDING +
    WS_BUFFER_SIZE
  ];
  // The last client ip address and dns name received by:
  // LWS_CALLBACK_FILTER_NETWORK_CONNECTION
  char http_last_client_name[ 256 ];
  char http_last_client_ip[ 50 ];

  //
  // Buffers used by the callback for the openGalaxy websocket protocol:
  //
  unsigned char _command_output_buffer[
    LWS_SEND_BUFFER_PRE_PADDING +
    WS_BUFFER_SIZE
  ];
  unsigned char _sia_output_buffer[
    LWS_SEND_BUFFER_PRE_PADDING +
    WS_BUFFER_SIZE
  ];
  unsigned char* command_output_buffer =
    &_command_output_buffer[LWS_SEND_BUFFER_PRE_PADDING];
  unsigned char* sia_output_buffer =
    &_sia_output_buffer[LWS_SEND_BUFFER_PRE_PADDING];

  // Strings used to access the SSL certificates:
  // - complete path to CA certificate
  // - complete path to Server certificate
  // - complete path to Server private key
  // - complete path to CRL certificate
  // - complete path to CRL certificate directory
  // - complete path to the directory with the client certs
  // - complete path to the RSA private key for decrypting user credentials
  std::string fn_ca_cert;
  std::string fn_srv_cert;
  std::string fn_srv_key;
  std::string fn_crl_cert;
  std::string path_crl_cert;
  std::string path_user_certs;
  std::string fn_credentials_key;
  std::string fn_verify_key;

  // Function that loads the CA-certificate bundle and
  // enables the certificate revocation list (CRL).
  static int ssl_load_certs(SSL_CTX *ctx, struct lws_context *context);

  // Called as the OpenSSL
  // 'int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);'
  // callback by LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION.
  // (lws return conventions apply.)
  static int ssl_verify_client_cert(struct lws_context *context, SSL *ssl, X509_STORE_CTX *store, int preverify_ok);

  // The libwebsocket callback functions for each implemented protocol.
  static int http_protocol_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
  static int opengalaxy_protocol_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

  // List of supported protocols and their callbacks
  struct lws_protocols protocols[3] = {
    // first protocol must always be HTTP handler
    {
      "openGalaxy-http-protocol",
      http_protocol_callback,
      sizeof (struct per_session_data_http_protocol),
      WS_BUFFER_SIZE,
    },
    {
      "openGalaxy-websocket-protocol",
      opengalaxy_protocol_callback,
      sizeof(struct per_session_data_opengalaxy_protocol),
      WS_BUFFER_SIZE,
    },
    { nullptr, nullptr, 0, 0 } // terminator
  };

  // Handles all thread instances of this class
  static void Thread(class Websocket *websocket);

  // Sends a message (JSON object) to a specific client (in response to a command that was executed)
  static void write(class openGalaxy& opengalaxy, session_id *session, void *user, char *message);

  // Replacement emit_log() for libwebsockets (implemented in main.cpp)
  static void emit_log(int level, const char *msg);

public:

  inline class openGalaxy& opengalaxy(){ return *m_openGalaxy; }

  // The RSA public key used to verify user credential authenticity.
  EVP_PKEY *verify_key;

  // The RSA private key used to decrypt user credentials.
  EVP_PKEY *credentials_key;

  // Complete path to the www root directory
  std::string path_www_root;

  // paths to some important files, use
  // std::string Settings::certificates_directory
  // to complete the path
  constexpr static const char* fmt_ca_cert  = "certs/openGalaxyCA.pem";
  constexpr static const char* fmt_srv_cert = "certs/server.pem";
  constexpr static const char* fmt_srv_key  = "private/serverKEY.pem";
  constexpr static const char* fmt_crl_cert = "certs/openGalaxyCRL.pem";
  constexpr static const char* fmt_path_crl_cert = "certs";
  constexpr static const char* fmt_path_client_certs = "certs/users";
  constexpr static const char* fmt_credentials_key = "private/credentialsKEY.pem";
  constexpr static const char* fmt_verify_key = "private/openGalaxyCAPUBKEY.pem";

  // used to create the SSL certs directory tree
  constexpr static const char* fmt_certs_path = "certs/users";
  constexpr static const char* fmt_keys_path = "private/users";


  // Serve nothing other then our whitelisted files
  // TODO: Make this list a file @ www_root/../whitelist.txt ???
  const char* valid_files_to_serve[33-2] = {
    "", // serves the default file (index.html)
    "tiles.png",
    "RIO.png",
    "favicon.ico",
    "old.html",
    "index.html",
    "opengalaxy.css",
    "opengalaxy.js",
    /* JQuery */
    "external/jquery/jquery-2.2.3.js",
    "external/jquery/jquery-2.2.3.min.js",
    "external/jquery-ui/index.html",
    "external/jquery-ui/jquery-ui.css",
    "external/jquery-ui/jquery-ui.js",
    "external/jquery-ui/jquery-ui.min.css",
    "external/jquery-ui/jquery-ui.min.js",
    "external/jquery-ui/jquery-ui.structure.css",
    "external/jquery-ui/jquery-ui.structure.min.css",
    "external/jquery-ui/jquery-ui.theme.css",
    "external/jquery-ui/jquery-ui.theme.min.css",
    /* JQuery smoothness theme images */
    "external/jquery-ui/images/ui-bg_glass_55_fbf9ee_1x400.png",
    "external/jquery-ui/images/ui-bg_glass_65_ffffff_1x400.png",
    "external/jquery-ui/images/ui-bg_glass_75_dadada_1x400.png",
    "external/jquery-ui/images/ui-bg_glass_75_e6e6e6_1x400.png",
    "external/jquery-ui/images/ui-bg_glass_95_fef1ec_1x400.png",
    "external/jquery-ui/images/ui-bg_highlight-soft_75_cccccc_1x100.png",
    "external/jquery-ui/images/ui-icons_222222_256x240.png",
    "external/jquery-ui/images/ui-icons_2e83ff_256x240.png",
    "external/jquery-ui/images/ui-icons_454545_256x240.png",
    "external/jquery-ui/images/ui-icons_888888_256x240.png",
    "external/jquery-ui/images/ui-icons_cd0a0a_256x240.png",
    nullptr
  };
  // 1 = allow the browser to cache this file
  // 0 = do not allow the browser to cache this file
  const int valid_files_to_cache[33-2] = {
    0, // "", // serves the default file (index.html)
    1, // "tiles.png",
    1, // "RIO.png",
    1, // "favicon.ico",
    0, // "old.html",
    0, // "index.html",
    0, // "opengalaxy.css",
    0, // "opengalaxy.js",
    /* JQuery */
    1, // "external/jquery/jquery-2.2.3.js",
    1, // "external/jquery/jquery-2.2.3.min.js",
    1, // "external/jquery-ui/index.html",
    1, // "external/jquery-ui/jquery-ui.css",
    1, // "external/jquery-ui/jquery-ui.js",
    1, // "external/jquery-ui/jquery-ui.min.css",
    1, // "external/jquery-ui/jquery-ui.min.js",
    1, // "external/jquery-ui/jquery-ui.structure.css",
    1, // "external/jquery-ui/jquery-ui.structure.min.css",
    1, // "external/jquery-ui/jquery-ui.theme.css",
    1, // "external/jquery-ui/jquery-ui.theme.min.css",
    /* JQuery smoothness theme images */
    1, // "external/jquery-ui/images/ui-bg_glass_55_fbf9ee_1x400.png",
    1, // "external/jquery-ui/images/ui-bg_glass_65_ffffff_1x400.png",
    1, // "external/jquery-ui/images/ui-bg_glass_75_dadada_1x400.png",
    1, // "external/jquery-ui/images/ui-bg_glass_75_e6e6e6_1x400.png",
    1, // "external/jquery-ui/images/ui-bg_glass_95_fef1ec_1x400.png",
    1, // "external/jquery-ui/images/ui-bg_highlight-soft_75_cccccc_1x100.png",
    1, // "external/jquery-ui/images/ui-icons_222222_256x240.png",
    1, // "external/jquery-ui/images/ui-icons_2e83ff_256x240.png",
    1, // "external/jquery-ui/images/ui-icons_454545_256x240.png",
    1, // "external/jquery-ui/images/ui-icons_888888_256x240.png",
    1, // "external/jquery-ui/images/ui-icons_cd0a0a_256x240.png",
    0
  };

  // The list of chipers SSL uses
  std::string ssl_cipher_list =
    "-ALL:-COMPLEMENTOFALL:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"         // ssllabs nr1 in chrome/firefox
    "ECDHE-RSA-AES128-GCM-SHA256:"           // ssllabs nr2 in chrome/firefox
    "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256:"  // ssllabs nr3/5 in chrome
    "ECDHE-RSA-CHACHA20-POLY1305-SHA256";    // ssllabs nr4/6 in chrome

  // Sends an authorization required/accepted message to the specified session
  //  ctxpss = our context userdata
  //  n_id = numerical session id to send
  //  name = the fullname of the client (not the username)
  //  s_id = the session_id to use while sending the message
  static void WriteAuthorizationRequiredMessage(ContextUserData *ctxpss, unsigned long long int n_id, std::string& name, session_id* s_id);
  static void WriteAuthorizationAcceptedMessage(ContextUserData *ctxpss, session_id* s_id);

  // default ctor
  Websocket(class openGalaxy*);
  // default dtor
  ~Websocket();

  // Broadcast a SIA message to all clients
  void broadcast(std::string&);

};

} // ends namespace openGalaxy
#endif

