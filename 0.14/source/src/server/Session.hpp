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

#ifndef __OPENGALAXY_WEBSOCKET_SESSION_HPP__
#define __OPENGALAXY_WEBSOCKET_SESSION_HPP__

#include "atomic.h"
#include "opengalaxy.hpp"
#include "session_id.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#endif
#include "libwebsockets.h"

namespace openGalaxy {

// User credentials are stored in the client certificates so we only
// use class Credentials when we have SSL support.
//
class Credentials {
private:

  // back-reference to the openGalaxy instance (set by ctor)
  class openGalaxy& m_openGalaxy;
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }

  // The OID used by our embedded data in client certificates
  // subjectAlternativeName->otherName
  static int nid_opengalaxy_embedded_data;

  // Structure of the data openGalaxy stores in each client certificate.
  struct x509_san_othername {
    std::string fullname; // Client (real) name
    std::string username; // Client (login) username
    std::string password; // Client (login) password
  };

  // Retrieved from client certificate by parse_cert():
  //  - serial number
  //  - sha256 fingerprint (used to identify the cert internally)
  //  - not before date
  //  - not after date
  //  - subject commonName (client full name)
  //  - subject emailAddress (client email address)
  //  - subject alternativename->otherName (embedded credentials)
  std::string cert_serial;
  std::string cert_sha256;
  std::string cert_not_before;
  std::string cert_not_after;
  std::string cert_subj_commonname;
  std::string cert_subj_emailaddress;
  struct x509_san_othername cert_san_othername;

public:

  // Certificate information
  std::string& serial(void){ return cert_serial; }
  std::string& sha256(void){ return cert_sha256; }
  std::string& not_valid_before(void){ return cert_not_before; }
  std::string& not_valid_after(void){ return cert_not_after; }
  std::string& commonname(void){ return cert_subj_commonname; }
  std::string& emailaddress(void){ return cert_subj_emailaddress; }

  // Credentials and privileges
  std::string& fullname(void){ return cert_san_othername.fullname; }
  std::string& username(void){ return cert_san_othername.username; }
  std::string& password(void){ return cert_san_othername.password; }


  // default ctor
  Credentials(class Websocket& websocket, const char *fingerprint);
  // copy ctor
  Credentials(Credentials& i);

  // Parses the client certificate, extracting all data.
  bool parse_cert(X509 *cert);

  // These two function are used to register/unregister the custom
  // Object Identifier (used by openGalaxy to stuff user credentials into
  // certificates) with OpenSSL.
  static void register_OID_with_openssl(void);
  static void unregister_OID_from_openssl(void);
};


// Sessions are used to keep track of whether a user is still connected
// or not. And when using SSL client certificates are used also
// to keep track of wheter the user has been authenticated or not.
//
class Session {
private:
  // back-reference to the openGalaxy instance
  class openGalaxy& m_openGalaxy;
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }

  std::string hostname;   // hostname of the client
  std::string ip_address; // ip address of the client

  // Timepoint representing the last client activity on all protocols.
  std::chrono::high_resolution_clock::time_point last_activity_tp;

public:
  // The number of seconds after which a session expires if left unused,
  // ie. a connection attempt was made but never established.
  constexpr static const int unused_timeout_seconds = 300;

  // The identifier for this session
  session_id session;

  // The authentication data retrieved from the peer certificate.
  Credentials *auth;

  // The name for our session id in an URI query string (must include the final '=').
  constexpr static const char *query_string = "session_id=";

  // The timepoint to use for the calculation of the activity timeout
  std::chrono::high_resolution_clock::time_point timeout_tp;

  // http protocol only:
  // Remains !0 while the session is starting up ie. the root document
  // has been requested (before) and was redirected to the new session.
  int session_starting;

  // http protocol only:
  // !0 when the root document /index.html has been send to the client,
  // effectivly starting the session.
  int session_was_started;

  // !0 when the client is connected to the protocol 
  // used to delete unused sessions in check_timeouts_and_remove_unused_sessions()
  int http_connected; // (only set whilst serving a file)
  int websocket_connected;

  // wsi/pss for the websocket.
  // only valid while websocket_connected != 0
  struct lws *websocket_wsi;
  struct per_session_data_opengalaxy_protocol *websocket_pss;

  // !0 when the client has logged on successfully
  // (ie. http_passwd is validated against cert_san_othername.password)
  int logged_on;

  // Compares http_user/htt_pass against the username/password from the client certificate.
  int login(const char *username, const char *password);

  int authorized(); // query the logon status
  void logoff();       // explicit logoff
  void set_active();   // reset auto logoff timeout

  // default ctor: creates new session id and initializes timeout_tp
  Session(class Websocket* websocket);
  // default dtor
  ~Session();

  // Called from LWS_CALLBACK_FILTER_HTTP_CONNECTION and
  // LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION by each of the protocol
  // callbacks. It retrieves or creates the Session for a connetion.
  static int start(struct lws *wsi, session_id& session, Session** s);

  // add a session to the global list off sessions
  static int add(Session *s, struct lws_context* context);

  // get a session from the global list off sessions
  static Session *get(session_id& session, struct lws_context* context);

  // - by SHA-256 fingerprint
  // (to be used from Session::start() and LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION only)
  static Session *get(const char *sha256str, struct lws_context* context);

  // get a session from the global list off sessions
  // - by wsi (struct lws*)
  static Session *get(struct lws *wsi, struct lws_context* context);

  // delete a session from the global list off sessions
  static void remove(session_id& session, struct lws_context* context);

  // called periodicly from the service loop to remove unused
  // sessions from the global list off sessions
  static void check_timeouts_and_remove_unused_sessions(struct lws_context* context);

  // Loops through the global session list and logout inactive
  // clients after opengalaxy->settings->session_timeout_seconds
  // called periodicly from Websocket::Thread
  static void logoff_timed_out_clients(struct lws_context* context);

};

}
#endif

