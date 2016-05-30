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

#include "atomic.h"
#include "opengalaxy.hpp"
#include "credentials.h"
#include "Certificates.hpp"
#include <algorithm>
#include <string>
#include <sys/stat.h>
#if __linux__
#include <grp.h>
#endif

namespace openGalaxy {

//
// Returns 1 when fn is an existing regular file that is atleast 1 byte large
// Returns 0 when file does not exist, is not a regular file or has 0 length
//
static int is_regular_file( const char *fn )
{
  struct stat st;
  if( stat( fn, &st ) != 0 ){
    // Could not stat the file
    return 0;
  }
  else if( !S_ISREG( st.st_mode ) ){
    // Not a regular file
    return 0;
  }

  int retv = 1;
  FILE *fp = fopen( fn, "r" );
  fseek( fp, 0L, SEEK_END );
  if( ftell(fp) == 0 ){
    // file is empty
    retv = 0;
  }
  fclose( fp );

  return retv;
}


//
// On Linux this set a file's group ID to that of group 'staff'
//
// Returns: !0 on errror
//
static int set_opengalaxy_gid( const char *path )
{
#if __linux__
  struct group *grp = getgrnam( "staff" );
  if( grp == NULL ){
    return -1;
  }
  else {
    if( 0 != chown( path, getuid(), grp->gr_gid ) ){
      return -1;
    }
  }
#endif
  return 0;
}

//
// Check if a directory exists,
//  if it does not exist create it.
//
// Returns: !0 on errror
//
static int _mkdir( const char *path, mode_t mode )
{
  struct stat st;
  int retv = 0;
  // Get directory stats
  if( stat( path, &st ) != 0 ){
    // Could not get stats, create the directory
    if(
#if __linux__
      mkdir( path, mode ) != 0 && errno != EEXIST
#else
      mkdir( path ) != 0 && errno != EEXIST
#endif
    ){
      // Could not create the directory
      retv = -1;
    }
    // Set the correct group id
    if( set_opengalaxy_gid( path ) != 0 ){
      retv = -1;
    }
    if( chmod( path, mode ) != 0 ){
      retv = -1;
    }
  }
  // Verify that it is a directory
  else if( !S_ISDIR( st.st_mode ) ){
    errno = ENOTDIR;
    retv = -1;
  }

  // set the group id to 'staff'
//  if( retv == 0 ){
//  }

  return( retv );
}

//
// 'mkdir -p' like function to create a path
//
// Returns: 0 on errror
//
static int mkpath( const char *path, mode_t mode )
{
  int retv = 0;
  char *pp, *sp, *p = strdup( path );
  if( p == NULL ){
    errno = ENOMEM;
    return 0;
  }
  pp = p;
  while ( retv == 0 && ( sp = strchr( pp, '/' ) ) != 0 ){
    if( sp != pp ){
      *sp = '\0';
#if ! __linux__
      if( p[strlen(p)-1] != ':' ){ // skip 'creating' the drive letter part of path on windows
#endif
        retv = _mkdir( p, mode );
#if ! __linux__
      }
#endif
      *sp = '/';
    }
    pp = sp + 1;
  }
  if(retv == 0) retv = _mkdir( path, mode );
  free( p );
  return !retv;
}

// Encodes a standard ASCII (ISO-8859-1) C string as UTF-8
void utf8encode(const char *in, std::string& out)
{
  out.erase();
  out.reserve(strlen(in) * 2);
  for(unsigned int i=0; i<strlen(in); i++){
    if(in[i] < 128){
      out += in[i];
    }
    else {
      out += 0xC0 | (in[i] >> 6);
      out += 0x80 | (in[i] & 0x3F);
    }
  }
}


const struct lws_extension Websocket::exts[] = {
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
	{ NULL, NULL, NULL /* terminator */ }
};



// class Websocket::BroadcastedMessagesArray dtor
Websocket::BroadcastedMessagesArray::~BroadcastedMessagesArray()
{
  for(int i = 0; i < Array<BroadcastedMessage*>::size(); i++){
    thread_safe_free(Array<BroadcastedMessage*>::m_ptData[i]->data);
    thread_safe_free(Array<BroadcastedMessage*>::m_ptData[i]);
  }
}


// Delete a given message from the array.
void Websocket::BroadcastedMessagesArray::remove(int nIndex)
{
  if( !(nIndex >= 0 && nIndex < Array<BroadcastedMessage*>::m_nLength) ){
    throw new std::runtime_error("Websocket::BroadcastedMessagesArray::remove: nIndex out of bounds.");
  }
  thread_safe_free(Array<BroadcastedMessage*>::m_ptData[nIndex]->data);
  thread_safe_free(Array<BroadcastedMessage*>::m_ptData[nIndex]);
  Array<BroadcastedMessage*>::remove(nIndex);
}


// class Websocket::CommandReplyMessagesArray dtor
Websocket::CommandReplyMessagesArray::~CommandReplyMessagesArray()
{
  for(int i = 0; i < Array<CommandReplyMessage*>::size(); i++){
    thread_safe_free(Array<CommandReplyMessage*>::m_ptData[i]->reply);
    thread_safe_free(Array<CommandReplyMessage*>::m_ptData[i]);
  }
}


// Delete a given message from the array.
void Websocket::CommandReplyMessagesArray::remove(int nIndex)
{
  if( !(nIndex >= 0 && nIndex < Array<CommandReplyMessage*>::m_nLength) ){
    throw new std::runtime_error("Websocket::CommandReplyMessagesArray::remove: nIndex out of bounds.");
  }
  thread_safe_free(Array<CommandReplyMessage*>::m_ptData[nIndex]->reply);
  thread_safe_free(Array<CommandReplyMessage*>::m_ptData[nIndex]);
  Array<CommandReplyMessage*>::remove(nIndex);
}


// class Websocket ctor
Websocket::Websocket(openGalaxy *opengalaxy)
{
  restart_server = 0;

  // Set the backref. to our openGalaxy instance
  m_openGalaxy = opengalaxy;

  // Set the ref. to our Websocket instance in the context data passed
  // to libwebsockets
  ctx_user_data.websocket = this;

  // Set the WWW root directory from global settings
  path_www_root.assign(m_openGalaxy->settings().www_root_directory.c_str());

  // Assign the configured values to certificate paths/filenames
  //

#undef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))

  char buf[
    m_openGalaxy->settings().certificates_directory.length() +
    8192
   ];

  const char *ssldir = m_openGalaxy->settings().certificates_directory.c_str();
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_ca_cert);
  fn_ca_cert.assign(buf);
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_srv_cert);
  fn_srv_cert.assign(buf);
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_srv_key);
  fn_srv_key.assign(buf);
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_crl_cert);
  fn_crl_cert.assign(buf);
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_path_crl_cert);
  path_crl_cert.assign(buf);
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_path_client_certs);
  path_user_certs.assign(buf);
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_credentials_key);
  fn_credentials_key.assign(buf);
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_verify_key);
  fn_verify_key.assign(buf);

  // Make sure the SSL certificate directory tree exists
  mkpath( ssldir, 0775 );
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_certs_path);
  mkpath( buf, 0770 );
  snprintf(buf, sizeof(buf), "%s/%s", ssldir, fmt_keys_path);
  mkpath( buf, 0770 );

  struct stat st;
  if(( stat( ssldir, &st ) != 0 ) || (!S_ISDIR( st.st_mode ))){
    m_openGalaxy->syslog().error(
      "ERROR: The directory for SSL certificates does not exist or is not writeable! (%s)",
      ssldir
    );
  }

  // Initially there a no clients and there is nothing to be send to them
  broadcast_do_send = 0;
  broadcast_nclients = 0;
  broadcast_nclients_done = 0;

  // Create/start a new thread to handle this Websocket instance
  m_thread = new std::thread(Websocket::Thread, this);
}


// class Websocket dtor
Websocket::~Websocket()
{
  m_thread->join(); // wait for Thread() to finish
  delete m_thread;  // delete the instance
}


// static function:
void Websocket::blacklist_dummy_callback(openGalaxy&,char*,int)
{
  // (Dummy) callback used when sending a code alarm
  return;
}


// checks the blacklist and removes any ip addresses that timed out.
void Websocket::check_blacklist_timeouts(void)
{
  using namespace std::chrono;

  auto end_tp = high_resolution_clock::now();
  auto end_minutes = time_point_cast<minutes>(end_tp);
  auto end_value = duration_cast<minutes>(end_minutes.time_since_epoch());

  for(int i = 0; i < opengalaxy().websocket().blacklist.size(); i++){
    auto start_minutes = time_point_cast<minutes>(opengalaxy().websocket().blacklist[i]->start);
    auto start_value = duration_cast<minutes>(start_minutes.time_since_epoch());
    auto delta = end_value - start_value;

    if(
      (delta.count() < 0) ||
      (delta.count() > (opengalaxy().websocket().blacklist[i]->timeout_minutes))
    ){
      opengalaxy().syslog().debug(
        "Websocket: Removing IP address from blacklist after timeout: %s",
        opengalaxy().websocket().blacklist[i]->ip.c_str()
      );
      opengalaxy().websocket().blacklist.remove(i);
    }
  }
}


// static function:
// This is the main() function for all threads of class Websocket
void Websocket::Thread(Websocket *_this)
{
  try {
    struct lws_context_creation_info context_info;
    int do_server_restart = 0;

    // If SSL is used then register the OID openGalaxy uses to store user credentials
    // in the client certificates with openSSL and load the verify and decrytion keys needed
    // to authenticate and decrypt this data.
    if(
      !is_regular_file(_this->fn_verify_key.c_str()) ||
      !is_regular_file(_this->fn_credentials_key.c_str())
    ){
      // No, no keys
      _this->opengalaxy().syslog().error("WARNING: Could not load the verify/decrypt key.");
      _this->verify_key = nullptr;
      _this->credentials_key = nullptr;
    }
    else {
      // Yes, register OID and load keys
      Credentials::register_OID_with_openssl();
      if(
        !ssl_evp_rsa_load_public_key(_this->fn_verify_key.c_str(), &_this->verify_key) ||
        !ssl_evp_rsa_load_private_key(_this->fn_credentials_key.c_str(), &_this->credentials_key, NULL, NULL)
      ){
        _this->opengalaxy().syslog().error("ERROR: RSA verify/decrypt keys could NOT be read! (Please generate certificates with the certificate manager...)");
        _this->opengalaxy().exit();
        return;
      }
    }

    // Enter the main loop
    while(_this->opengalaxy().isQuit() == false){

      // Prepare a structure with information about the libwebsockets context
      // we wish to create.
      memset(&context_info, 0, sizeof context_info);
      if(_this->opengalaxy().m_options.no_ssl != 0){
        context_info.port = _this->opengalaxy().settings().http_port;
      }
      else {
        context_info.port = _this->opengalaxy().settings().https_port;
      }
      if( _this->opengalaxy().settings().iface.compare("") == 0){
        context_info.iface = nullptr;
        _this->opengalaxy().syslog().info("Binding socket to all network interfaces.");
      }
      else {
        context_info.iface = _this->opengalaxy().settings().iface.c_str();
        _this->opengalaxy().syslog().info(
          "Binding socket to network interface: %s.",
          _this->opengalaxy().settings().iface.c_str()
        );
      }
      context_info.protocols = _this->protocols;
      context_info.extensions = Websocket::exts;
      context_info.gid = -1;
      context_info.uid = -1;
      context_info.max_http_header_pool = 16;
      context_info.ka_time = 30;     // Send KeepAlive packets every 30 seconds
      context_info.ka_probes = 3;    // nr of times to try
      context_info.ka_interval = 10; // How long to wait before each attempt
      context_info.options =
      /*  LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME | */
        LWS_SERVER_OPTION_VALIDATE_UTF8 |
        LWS_SERVER_OPTION_DISABLE_IPV6 |
        LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS /*|
        LWS_SERVER_OPTION_EXPLICIT_VHOSTS*/ /*|
        LWS_SERVER_OPTION_SSL_ECDH */;

      // Do we want SSL
      if(_this->opengalaxy().m_options.no_ssl == 0){
        // Yes, test if the certificates exist
        if(
          !is_regular_file(_this->fn_srv_cert.c_str()) ||
          !is_regular_file(_this->fn_srv_key.c_str()) ||
          !is_regular_file(_this->fn_ca_cert.c_str())
        ){
          // No they do not exist, start in non SSL mode
          _this->opengalaxy().syslog().error(
            "WARNING: Could not find all SSL certificates, starting in HTTP mode."
          );
          _this->opengalaxy().m_options.no_ssl = 1;
          _this->opengalaxy().m_options.no_client_certs = 1;
          _this->opengalaxy().m_options.auto_logoff = 0;
          context_info.port = _this->opengalaxy().settings().http_port;
        }
        else {
          // Yes they do, start in SSL mode (by setting the paths in context_info)
          context_info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
          context_info.ssl_cert_filepath = _this->fn_srv_cert.c_str();
          context_info.ssl_private_key_filepath = _this->fn_srv_key.c_str();
          context_info.ssl_cipher_list = _this->ssl_cipher_list.c_str();
          context_info.ssl_ca_filepath = _this->fn_ca_cert.c_str();
          // Do we want client certificates?
          if(_this->opengalaxy().m_options.no_client_certs != 1){
            // Yes, so set the option
            context_info.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
          }
        }

      }

      // Let the libwebsockets context user-data point
      //  to struct Websocket::ctx_user_data
      context_info.user = &_this->ctx_user_data;

// Get this from the server cert (commonName) ?
//context_info.vhost_name = "localhost";

      // tell the libwebsockets library what debug level to
      // emit and to send it to openGalaxy's syslog
      if(_this->opengalaxy().syslog().get_level() >= Syslog::Level::Debug){
        lws_set_log_level(LLL_NOTICE/*LLL_ERR | LLL_INFO | LLL_NOTICE | LLL_WARN  | LLL_DEBUG | LLL_HEADER | LLL_EXT | LLL_CLIENT | LLL_LATENCY | LLL_PARSER */, _this->emit_log);
      }
      else {
        lws_set_log_level(0 /*LLL_ERR | LLL_WARN*/, _this->emit_log);
      }

      _this->opengalaxy().syslog().info(
        "Listening for %s connections on port %d.",
        (_this->opengalaxy().m_options.no_ssl) ? "HTTP" : "HTTPS",
        (_this->opengalaxy().m_options.no_ssl) ? _this->opengalaxy().settings().http_port : _this->opengalaxy().settings().https_port
      );

      // Create a new libwebsockets context
      // (also initializes OpenSSL).
      _this->context = lws_create_context(&context_info);
      if(_this->context == nullptr){
        throw new std::runtime_error("Could not create a websocket context, is the port allready used?");
      }

// create a vhost
//lws_create_vhost(_this->context, &context_info, nullptr);

      // Enter the service loop
      int n = 0;
      int timeout_count = 0;
      while(n >= 0 && _this->opengalaxy().isQuit() == false){

        // If there are any SIA messages waiting, then send them to all clients
        if(_this->broadcast_do_send){
          lws_callback_on_writable_all_protocol(
            _this->context,
            &_this->protocols[PROTOCOL_OPENGALAXY]
          );
        }

        // If there are any replies to commands a client has executed,
        // then send it to that client

        // TODO: if needed, make sure any previous reply was send (and not interrupted by a broadcasted SIA message)

        if(_this->command_replies.size() > 0){
          _this->m_command_mutex.lock();
          Session *s = Session::get(
            _this->command_replies[0]->session,
            _this->context
          );
          if(s && s->websocket_connected){
            strncpy(
              (char*)_this->command_output_buffer,
              _this->command_replies[0]->reply,
              WS_BUFFER_SIZE - 1
            );
            _this->command_output_buffer[WS_BUFFER_SIZE - 1] = '\0';
            s->websocket_pss->send_data = true;
            lws_callback_on_writable(s->websocket_wsi);
          }
          else {
            _this->opengalaxy().syslog().debug(
              "Websocket: Session (re)moved, dropping message(s)."
            );
            if(s) Session::remove(s->session, _this->context);
          }
          _this->command_replies.remove(0);
          _this->m_command_mutex.unlock();
        }

        if(timeout_count++ > 50 ){ // times 50 ms == 5 seconds
          timeout_count = 0;
          // Update the list of blacklisted ip addresses
          _this->opengalaxy().websocket().check_blacklist_timeouts();
          // logoff timed-out sessions
          if(_this->opengalaxy().m_options.auto_logoff == 1){
            Session::logoff_timed_out_clients(_this->context);
          }
          // cleanup unused sessions
          Session::check_timeouts_and_remove_unused_sessions(_this->context);
          // Do we need to restart?
          if(do_server_restart) {
            _this->opengalaxy().syslog().error("Info: Restarting server!\n\n");
            _this->opengalaxy().exit_status = openGalaxy::EXIT_STATUS_CERTS_UPDATED;
            _this->opengalaxy().exit();
          }
          if(_this->restart_server) {
            do_server_restart = 1; // restart in 5 seconds
            _this->restart_server = 0;
          }
        }

        // Service libwebsockets (and throttle the service loop)
        n = lws_service(_this->context, 100 /* ms */);
      }

      lws_cancel_service(_this->context);
      lws_context_destroy(_this->context);

      // Cleanup any left over sessions
      _this->ctx_user_data.sessions.erase();
    }

    // Free the pkeys used to verify/decrypt the user credentials stored
    // in the client certificates and clean up OpenSSLs internal object table.
    if(_this->opengalaxy().m_options.no_ssl == 0){
      if(_this->opengalaxy().m_options.no_client_certs == 0){
        ssl_pkey_free(_this->credentials_key);
        ssl_pkey_free(_this->verify_key);
        Credentials::unregister_OID_from_openssl();
      }
    }

    _this->opengalaxy().syslog().debug("Websocket::Thread exited normally");
  }
  catch(...){
    // pass any exception on to the main() thread
    _this->opengalaxy().m_Websocket_exptr = std::current_exception();
    _this->opengalaxy().exit();
  }
}


// Broadcast a SIA message to all clients
// in: SIA message (as JSON object)
void Websocket::broadcast(std::string& in)
{
  char buf[in.size() + strlen(json_sia_message_fmt) + 32]; // make sure buf is large enough
  sprintf(buf, json_sia_message_fmt, in.c_str());
  m_broadcast_mutex.lock();
  if(broadcast_nclients){
    // Encode the string (JSON data) as UTF-8
    std::string utf8;
    utf8encode(buf, utf8);
    // Add it to the array of messages to te broadcast and trigger
    // a libwebsockets write by setting broadcast_do_send
    struct BroadcastedMessage *msg;
    msg = (struct BroadcastedMessage*)thread_safe_malloc(
      sizeof(struct BroadcastedMessage)
    );
    msg->len = utf8.size() + 1;
    msg->data = (char*)thread_safe_malloc(msg->len);
    memcpy(msg->data, utf8.data() , msg->len);
    broadcast_msg.append(msg);
    broadcast_do_send = 1;
  }
  m_broadcast_mutex.unlock(); 
}


// static function:
// Adds a reply to the list of (command) replies,
// called as callback from Commander::execute
void Websocket::write(
  openGalaxy& opengalaxy,
  struct session_id *session,
  void *unused,
  char *reply
){
  // Encode the reply message (JSON data) as UTF-8
  std::string utf8;
  utf8encode(reply, utf8);

  struct CommandReplyMessage *l;
  l = (struct CommandReplyMessage*)thread_safe_malloc(
    sizeof(struct CommandReplyMessage)
  );

  memcpy(&(l->session), session, sizeof(session_id));
  l->reply = (char*)thread_safe_malloc(utf8.size()+1);
  strcpy(l->reply, utf8.data());

  opengalaxy.websocket().m_command_mutex.lock();
  opengalaxy.websocket().command_replies.append(l);
  opengalaxy.websocket().m_command_mutex.unlock();
}


// static functions
// Sends the 'authorization_required' message to a client.
void Websocket::WriteAuthorizationAcceptedMessage(ContextUserData *ctxpss, session_id* s_id)
{
  char reply[
    strlen(ctxpss->websocket->opengalaxy().commander().json_authentication_accepted_fmt)
    + 10
    + strlen(ctxpss->websocket->opengalaxy().commander().CommanderTypeDesc[
        static_cast<int>(Commander::json_reply_id::authentication_accepted)
      ])
    + 1
  ];
  snprintf(
    reply,
    sizeof reply,
    ctxpss->websocket->opengalaxy().commander().json_authentication_accepted_fmt,
    static_cast<unsigned int>(Commander::json_reply_id::authentication_accepted),
    ctxpss->websocket->opengalaxy().commander().CommanderTypeDesc[
      static_cast<int>(Commander::json_reply_id::authentication_accepted)
    ]
  );
  Websocket::write(
    ctxpss->websocket->opengalaxy(),
    s_id,
    nullptr,
    reply
  );
}

void Websocket::WriteAuthorizationRequiredMessage(ContextUserData *ctxpss, unsigned long long int n_id, std::string& name, session_id* s_id)
{
  char reply[
    strlen(ctxpss->websocket->opengalaxy().commander().json_authorization_required_fmt)
    + 10
    + 16
    + name.size()
    + 1
  ];
  snprintf(
    reply,
    sizeof reply,
    ctxpss->websocket->opengalaxy().commander().json_authorization_required_fmt,
    static_cast<unsigned int>(Commander::json_reply_id::authorization_required),
    n_id,
    name.c_str()
  );
  Websocket::write(
    ctxpss->websocket->opengalaxy(),
    s_id,
    nullptr,
    reply
  );
}

// static function:
// libwebsockets callback for the openGalaxy websocket protocol
int Websocket::opengalaxy_protocol_callback(
  struct lws *wsi,                  // websocket instance
  enum lws_callback_reasons reason, // reason code for callback invocation
  void *user,                       // per session user data
  void *in,                         // incoming data
  size_t len                        // length of incoming data
){
  static std::stringstream in_stream;

  int n = 0;
  int m;
  struct per_session_data_opengalaxy_protocol *pss = (struct per_session_data_opengalaxy_protocol *)user;

  struct lws_context *context = nullptr;
  ContextUserData *ctxpss = nullptr;
  Session *s = nullptr;

  switch(reason){

    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);

      // Start a (new) session, but first check if this client's certificate
      // is allready in use by another session.
      if(
        (ctxpss->websocket->opengalaxy().m_options.no_ssl == 0) &&
        (ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0)
      ){
        // Get the client certificate
        SSL* ssl = lws_get_ssl(wsi);
        X509* x509 = (ssl) ? SSL_get_peer_certificate(ssl) : nullptr;
        if(!x509){
          ctxpss->websocket->opengalaxy().syslog().error(
            "Session: Unable to get the client SSL certificate."
          );
          return 1;
        }
        // Get the SHA-256 fingerprint for this client (certificate)
        char *ftmp = ssl_calculate_sha256_fingerprint(x509);
        if(!ftmp){
          ctxpss->websocket->opengalaxy().syslog().error(
            "Session: "
            "Unable to get the SHA-256 fingerprint for a client SSL certificate."
          );
          return 1;
        }
        // Locate any connected session that is allready
        // using this certificate.
        for(int i = 0; i < ctxpss->sessions.size(); i++){
          if(ctxpss->sessions[i]->auth->sha256().compare(ftmp) == 0){
            if(ctxpss->sessions[i]->websocket_connected != 0){
              // Logoff and delete the 'old' session before starting the new one.
              ctxpss->websocket->opengalaxy().syslog().debug(
                "Session: "
                "Deleting the session of '%s' before starting a new one.",
                ctxpss->sessions[i]->auth->fullname().c_str()
              );
              ctxpss->sessions[i]->logoff();
              ctxpss->sessions[i]->websocket_connected = 0;
              break;
            }
          }
        }
        ssl_free(ftmp);
      }

      // Start a (new) session
      if(!pss) ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no per session data in LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION");
      n = Session::start(wsi, pss->session, &s);
      if(!n){
        s->websocket_wsi = wsi;
        s->websocket_pss = pss;
      }
      else ctxpss->websocket->opengalaxy().syslog().error(
        "Session: Error, could not create a session (LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION)."
      );
      return n;
    }

    case LWS_CALLBACK_ESTABLISHED: {
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);
      if(pss) {
        s = Session::get(pss->session, context);
      }
      else {
        ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no per session data in LWS_CALLBACK_ESTABLISHED");
        s = Session::get(wsi, context);
      }
      if(!s){
        // No session available, block the connection
        ctxpss->websocket->opengalaxy().syslog().error(
          "Session: Error, could not retrieve the session (LWS_CALLBACK_ESTABLISHED)."
        );
        return 1;
      }
      // Set the status to 'connected'
      s->websocket_connected = 1;

      // IF using ssl AND require client certs AND require username/password THEN
      if(
        (ctxpss->websocket->opengalaxy().m_options.no_ssl == 0) &&
        (ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0) &&
        (ctxpss->websocket->opengalaxy().m_options.no_password == 0)
      ){
        // IF NOT authorized THEN
        //  Force logoff
        //  Send a JSON_AUTHORIZATION_REQUIRED message to the client
        if(!s->authorized()){
          s->logoff();
          WriteAuthorizationRequiredMessage(ctxpss, s->session.id, s->auth->fullname(), &pss->session);
        }
      }

      pss->send_data = false; // initially there are no command replies to send
      ctxpss->websocket->broadcast_nclients++; // increment the number of connected clients
      return 0;
    }

    case LWS_CALLBACK_CLOSED: {
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);
      if(pss) {
        s = Session::get(pss->session, context);
      }
      else {
        ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no per session data in LWS_CALLBACK_CLOSED");
        s = Session::get(wsi, context);
      }
      if(s){
        // Log out of the session when the websocket is closed
        // and stop polling
        if(ctxpss) ctxpss->websocket->opengalaxy().poll().disable(s->session);
        s->logoff();
        s->websocket_connected = 0;
      }
      if(ctxpss){
        // decrement the number of clients
        ctxpss->websocket->broadcast_nclients--;
      }
      break;
    }

    case LWS_CALLBACK_SERVER_WRITEABLE: {
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);
      if(!pss) ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no per session data in LWS_CALLBACK_SERVER_WRITEABLE");

      // Broadcast SIA message(s)?
      //
      // Output a single messages from the list to all clients.
      // The last client removes the list entry.
      // Schedule another write if the list is not yet empty.
      if(
        ctxpss &&
        ctxpss->websocket->broadcast_do_send &&
        !ctxpss->websocket->opengalaxy().isQuit()
      ){
        // yes, get the first message and
        ctxpss->websocket->m_broadcast_mutex.lock(); 
        if(ctxpss->websocket->broadcast_msg.size() > 0){
          struct BroadcastedMessage& msg = *ctxpss->websocket->broadcast_msg[0];
          // copy it to the write buffer and
          if(msg.len > WS_BUFFER_SIZE) msg.len = WS_BUFFER_SIZE;
          memcpy(ctxpss->websocket->sia_output_buffer, msg.data, msg.len);
          // send it to this client
          n = lws_write(
            wsi,
            ctxpss->websocket->sia_output_buffer,
            msg.len,
            LWS_WRITE_TEXT
          );
          if(n < 0){ // (sanity check, test for write error)
            ctxpss->websocket->opengalaxy().syslog().error(
              "WebSocket: ERROR %d writing to socket",
              n
            );
            ctxpss->websocket->m_broadcast_mutex.unlock(); 
            n = -1; // (fatal, close connection)
            break;
          }
        }
        // increment the 'number of clients done' counter
        ctxpss->websocket->broadcast_nclients_done++;
        // Did we send this message to all clients?
        if(
          ctxpss->websocket->broadcast_nclients_done >=
          ctxpss->websocket->broadcast_nclients
        ){
          // Yes, reset the counter and signal that we are done and
          ctxpss->websocket->broadcast_nclients_done = 0;
          ctxpss->websocket->broadcast_do_send = 0;
          // delete the current message from the fifo list
          //(sanity check first, test for null message)
          if(ctxpss->websocket->broadcast_msg.size() > 0){
            ctxpss->websocket->broadcast_msg.remove(0);
            // Another message to send?
            if(ctxpss->websocket->broadcast_msg.size() > 0){
              // Yes, signal we need to send a message
              ctxpss->websocket->broadcast_do_send = 1;
              // And trigger a write callback for all clients
              lws_callback_on_writable_all_protocol(
                context,
                lws_get_protocol(wsi)
              );
            }
          }
        }
        ctxpss->websocket->m_broadcast_mutex.unlock(); 
      }

      // Command reply to send?
      else if(
        pss &&
        ctxpss &&
        (pss->send_data == true) &&
        !ctxpss->websocket->opengalaxy().isQuit()
      ){

        // Send the message to the client
        n = strlen((char*)ctxpss->websocket->command_output_buffer);
        m = lws_write(
          wsi,
          ctxpss->websocket->command_output_buffer,
          n,
          LWS_WRITE_TEXT
        );
        if(m < n){
          ctxpss->websocket->opengalaxy().syslog().error(
            "ERROR %d writing to socket", n
          );
          n = 1;
          break;
        }

        pss->send_data = false;
      }

      n = 0;
      break;
    }

    case LWS_CALLBACK_RECEIVE: {
      int final_fragment = lws_is_final_fragment(wsi);
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);

      if(!ctxpss->websocket->opengalaxy().isQuit()){
        if(pss) {
          s = Session::get(pss->session, context);
        }
        else {
          ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no per session data in LWS_CALLBACK_RECEIVE");
          s = Session::get(wsi, context);
        }
        if(!s){
          std::string noname = "no username available";
          // No session, block the connection
          ctxpss->websocket->opengalaxy().syslog().error("Session: Error, no session (LWS_CALLBACK_RECEIVE)");
          // let the client know we're blocking
          WriteAuthorizationRequiredMessage(ctxpss, pss->session.id, noname, &pss->session);
          n = -1;
          break;
        }
        else {
          // we have a session_id, are we authorized?
          if(
            ctxpss->websocket->opengalaxy().m_options.no_ssl ||          // we are if we do not use ssl
            ctxpss->websocket->opengalaxy().m_options.no_client_certs || // we are if we are note using client certs
            ctxpss->websocket->opengalaxy().m_options.no_password ||     // we are if passwords are disabled
            s->authorized()                                              // we are if we are logged on
          ){
            // yes we are
            // reset the activity timeout
            s->set_active();

            // Add the fragment to the input stringstream
            in_stream << (const char*)in;

            // When all fragments have arrived:
            if(final_fragment){

              // Is it a set of certificates from the cert. manager?
              if(in_stream.str().find((const char*)"CERTS") == 0){
                // Yes, so try to save them
                n = save_certificates(&in_stream.str().c_str()[5], ctxpss->websocket->opengalaxy());
                // success, retstart the server by signaling the service loop
                // that will call openGalaxy::exit() in about 5 seconds
                ctxpss->websocket->restart_server = 1;
                char buffer[256];
                snprintf(buffer, 256, Commander::json_standard_reply_fmt,
                  static_cast<unsigned int>(Commander::json_reply_id::standard),
                  Commander::CommanderTypeDesc[static_cast<int>(Commander::json_reply_id::standard)],
                  !n,
                  (const char*)"Upload Certificates"
                );
                ctxpss->websocket->write(ctxpss->websocket->opengalaxy(), &s->session, NULL, buffer);
                n = 0;
              }
              else {
                // No its a normal command, add the it to the list of commands
                ctxpss->websocket->opengalaxy().commander().execute(
                  ctxpss->websocket->m_openGalaxy,
                  &pss->session,
                  nullptr,
                  (const char*)in_stream.str().c_str(),
                  Websocket::write
                );
              }

              // Clear the input stringstream
              in_stream.str( "" );
              in_stream.clear();
            }

          }
          else {
            // no not authorized

            // Extract username/password (and session id) from the received data
            char *pwd;
            char *sid = strtok_r((char*)in, "\n", &pwd);
            char *user = strtok_r( nullptr, "\n", &pwd);
            unsigned long long int id = (sid) ? strtoull(sid, nullptr, 16) : 0;

            if(!user) user = (char*)"";
            if(!pwd) pwd = (char*)"";

            std::string sname;

            if(s->auth) {
              sname = s->auth->fullname();
            }
            else {
              if(user) sname = user;
              else sname = "???";
            }

            // Is it the correct session?
            if(s->session.id != id){
              // request authentication
              ctxpss->websocket->opengalaxy().syslog().debug(
                "Credentials: Failed to authenticate %s (no such session)!",
                s->auth->fullname().c_str()
              );
              WriteAuthorizationRequiredMessage(ctxpss, s->session.id, sname, &pss->session);
              break;
            }

            // Try to log on...
            if(!s->login(user, pwd)){
              // request authentication
              ctxpss->websocket->opengalaxy().syslog().debug(
                "Credentials: Failed to authenticate %s!",
                s->auth->fullname().c_str()
              );
              WriteAuthorizationRequiredMessage(ctxpss, s->session.id, sname, &pss->session);
              break;
            }

            // Success
            s->session_starting = 0;
            s->session_was_started = 1;
            s->set_active();

            // Also let the client know with a reply message
            WriteAuthorizationAcceptedMessage(ctxpss, &pss->session);
            break;
          }
        }
      }
      break;
    }

    default:
      break;

  }
  return n;
}

} // ends namespace openGalaxy

