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

namespace openGalaxy {

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

static void get_headers(struct lws *wsi, std::string& ref, std::string& del)
{
  int n = 0;
  char buf[8192];
  const unsigned char *c;

  do {
    c = lws_token_to_string((lws_token_indexes)n);
    if(!c){
      n++;
      continue;
    }

    if (!lws_hdr_total_length(wsi, (lws_token_indexes)n)) {
      n++;
      continue;
    }

    lws_hdr_copy(wsi, buf, sizeof buf, (lws_token_indexes)n);

    if(n == WSI_TOKEN_HTTP_REFERER){ // referer
      ref.assign(buf);
    }

    if(n == WSI_TOKEN_HTTP_URI_ARGS){ // delete
      del.assign(buf);
    }

    n++;
  } while (c);
}


static const char *get_http_mimetype(const char *file)
{
  int n = strlen(file);
  if(n < 5) return nullptr;
  if(!strcmp(&file[n - 4], ".ico")) return "image/x-icon";
  if(!strcmp(&file[n - 3], ".js")) return "text/javascript";
  if(!strcmp(&file[n - 4], ".css")) return "text/css";
  if(!strcmp(&file[n - 4], ".png")) return "image/png";
  if(!strcmp(&file[n - 4], ".jpg")) return "image/jpeg";
  if(!strcmp(&file[n - 5], ".html")) return "text/html";
  return nullptr;
}


// static function:
// libwebsockets callback for the openGalaxy::HTTP protocol
int Websocket::http_protocol_callback(
  struct lws *wsi,
  enum lws_callback_reasons reason,
  void *user,
  void *in,
  size_t len
){
  int n = 1;
  const char *mimetype;
  int m;

  // We do not want the browser to cache (some of) our files,
  // these http header seem to work the best.
  const char *nocache_headers =
    "Cache-Control: no-cache, no-store, must-revalidate\x0d\x0a" // HTTP 1.1
    "Pragma: no-cache\x0d\x0a" // HTTP 1.0
    "Expires: 0\x0d\x0a"; // Proxies

  char *other_headers = nullptr;

  struct per_session_data_http_protocol *pss = (struct per_session_data_http_protocol *)user;
  struct lws_context *context = nullptr;
  ContextUserData *ctxpss = nullptr;
  Session *s = nullptr;

//if( reason != LWS_CALLBACK_GET_THREAD_ID)
//puts(reason2txt(reason));

  switch(reason){

    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS: {
      // Load the SSL certificates needed for verifying client certificates
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);

      if(ctxpss && ctxpss->websocket->opengalaxy().m_options.no_ssl == 0){
        return ssl_load_certs((SSL_CTX*)user, context); // load Certificate Revocation List.
      }
      break;
    }

    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION: {
      context = lws_get_context(wsi); // Note: the wsi if 'faked' (and just to be able to get the context...)
      ctxpss = (ContextUserData *) lws_context_user(context);

      // First check if this is a valid certificate
      n = ssl_verify_client_cert(context, (SSL*)in, (X509_STORE_CTX*)user, len);
      if(n){
        // final result (n) is nonzero, the certificate is invalid:
        // blacklist the ip address for a while
        ctxpss = (ContextUserData *) lws_context_user(context);
        ctxpss->websocket->opengalaxy().syslog().error(
          "Websocket: Failed to verify client "
          "SSL certificate, blacklisting IP address: %s",
          ctxpss->websocket->http_last_client_ip
        );
        ctxpss->websocket->opengalaxy().websocket().blacklist.append(
          new class BlacklistedIpAddress(
            ctxpss->websocket->http_last_client_ip,
            ctxpss->websocket->opengalaxy().settings().blacklist_timeout_minutes
          )
        );
        ctxpss->websocket->opengalaxy().galaxy().GenerateWrongCodeAlarm_nb(
          Galaxy::sia_module::rs232,
          Websocket::blacklist_dummy_callback
        );
      }
      return n;
    }

    case LWS_CALLBACK_FILTER_NETWORK_CONNECTION: {
      // Who is it? Get peer IP address (for use in
      // LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION)
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);
      ctxpss->websocket->http_last_client_name[0] =
        ctxpss->websocket->http_last_client_ip[0] = '\0';
      lws_get_peer_addresses(
        wsi,
        *((int*)(&in)),
        ctxpss->websocket->http_last_client_name,
        sizeof ctxpss->websocket->http_last_client_name,
        ctxpss->websocket->http_last_client_ip,
        sizeof ctxpss->websocket->http_last_client_ip
      );

      // Block blacklisted IP addresses
      for(
        int t = 0;
        t < ctxpss->websocket->opengalaxy().websocket().blacklist.size();
        t++
      ){
        if(
          ctxpss->websocket->opengalaxy().websocket().blacklist[t]->ip.compare(
            ctxpss->websocket->http_last_client_ip
          )==0
        ){
          ctxpss->websocket->opengalaxy().syslog().error(
            "Websocket: "
            "Blocking connection attempt from blacklisted IP address: %s",
            ctxpss->websocket->http_last_client_ip
          );
          return 1;
        }
      }
      break;
    }

    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: // opened as websocket
    case LWS_CALLBACK_FILTER_HTTP_CONNECTION: {   // opened as http
      n = 0;
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);
      if(!pss) ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no per session data in LWS_CALLBACK_FILTER_HTTP_CONNECTION");

      if(ctxpss->websocket->opengalaxy().m_options.no_ssl == 0){
        n = Session::start(wsi, pss->session, &s);
        if(!n){
          // Set the session status for this protocol to 'connected'
          s->http_connected = 1;
        }
      }

      return n;
    }

    case LWS_CALLBACK_CLOSED:         // opened as websocket
    case LWS_CALLBACK_CLOSED_HTTP: {  // opened as http
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);

      if(ctxpss->websocket->opengalaxy().m_options.no_ssl == 0){
        if(ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0){
          if(pss) {
            s = Session::get(pss->session, context);
          }
          else {
            ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no per session data in LWS_CALLBACK_CLOSED_HTTP");
            s = Session::get(wsi, context);
          }
        }
      }
      if(s){
        s->http_connected = 0;
      }

      break;
    }

    case LWS_CALLBACK_HTTP: {

      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);

      if(len < 1){
        lws_return_http_status(
          wsi,
          HTTP_STATUS_BAD_REQUEST,
          nullptr
        );
        goto try_to_reuse;
      }

      std::string http_delete;
      std::string http_referer;
      if(
        (ctxpss->websocket->opengalaxy().m_options.no_ssl == 0) &&
        (ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0)
      ){
        unsigned char *p;
        unsigned long long int s_id;

        // Get the session for this client
        if(pss) {
          s = Session::get(pss->session, context);
        }
        else {
          ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no per session data in LWS_CALLBACK_HTTP");
          s = Session::get(wsi, context);
        }
        if(!s){
          lws_return_http_status(
            wsi,
            HTTP_STATUS_FORBIDDEN,
            "No such session!"
          );
          goto try_to_reuse;
        }

        if(ctxpss->websocket->opengalaxy().m_options.no_password == 0){
          // Get the client's authentication info
          if(!s->auth){
            lws_return_http_status(
              wsi,
              HTTP_STATUS_FORBIDDEN,
              "Not authorized!"
            );
            goto try_to_reuse;
          }
        }

        // Get the session id from the query string
        // (ie. get it from the DELETE http header).
        get_headers(wsi, http_referer, http_delete);
        s_id = 0;
        int pos = http_delete.find(Session::query_string);
        if((unsigned)pos != std::string::npos){
          char *str = (char*)http_delete.c_str();
          s_id = strtoull((char*)&str[pos+strlen(Session::query_string)], nullptr, 16);
        }

        // Starting a new session? ie. is /index.html requested
        if(
          (strcmp((const char*)in, "/") == 0) ||
          (strcmp((const char*)in, ctxpss->websocket->www_root_document) == 0)
        ){
          // Yes /index.html is requested,
          // allready redirected to a new session?
          if(!s->session_starting && !s->session_was_started){
            // no not yet redirected,
            // Yes this is a new session, redirect to the new URI
            s->logoff();
            s->session_starting = 1;
            ssl_rand_pseudo_bytes((unsigned char*)&s->session.id, sizeof(s->session.id));
            p = ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING;
            snprintf(
              ctxpss->websocket->http_path_buffer,
              sizeof(ctxpss->websocket->http_path_buffer),
              ctxpss->websocket->fmt_redirect_uri,
              ctxpss->websocket->www_root_document,
              Session::query_string,
              s->session.id
            );
            unsigned char *end =
              p + sizeof(ctxpss->websocket->http_file_buffer) - LWS_SEND_BUFFER_PRE_PADDING;
            if(lws_add_http_header_status(wsi,
              HTTP_STATUS_TEMPORARY_REDIRECT, &p, end)) return 1;
            if(lws_add_http_header_by_name(
              wsi,
              (unsigned char *)"Location:",
              (unsigned char *)ctxpss->websocket->http_path_buffer,
              strlen(ctxpss->websocket->http_path_buffer),
              &p,
              end)
            ) return 1;
            if(lws_add_http_header_content_length(wsi, 0, &p, end)) return 1;
            if(lws_finalize_http_header(wsi, &p, end)) return 1;
            ctxpss->websocket->opengalaxy().syslog().debug(
              "Session: Redirecting %s to a new session with id: %llX",
              s->auth->fullname().c_str(), s->session.id
            );
            n = lws_write(
              wsi,
              ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING,
              p - (ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING),
              LWS_WRITE_HTTP_HEADERS
            );
            break;
          }
          else {
            s->session_starting = 0;
            // yes allready redirected,
            // there should be a valid session id in the query string
            if(s_id != s->session.id){
              s->logoff();
              // No valid s_id, start a new session
              s->session_starting = 1;
              ssl_rand_pseudo_bytes((unsigned char*)&s->session.id, sizeof(s->session.id));
              p = ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING;
              snprintf(
                ctxpss->websocket->http_path_buffer,
                sizeof(ctxpss->websocket->http_path_buffer),
                ctxpss->websocket->fmt_redirect_uri,
                ctxpss->websocket->www_root_document,
                Session::query_string,
                s->session.id
              );
              unsigned char *end =
                p + sizeof(ctxpss->websocket->http_file_buffer) - LWS_SEND_BUFFER_PRE_PADDING;
              if(lws_add_http_header_status(
                wsi,
                HTTP_STATUS_TEMPORARY_REDIRECT,
                &p,
                end)
              ) return 1;
              if(lws_add_http_header_by_name(
                wsi,
                (unsigned char *)"Location:",
                (unsigned char *)ctxpss->websocket->http_path_buffer,
                strlen(ctxpss->websocket->http_path_buffer),
                &p,
                end)
              ) return 1;
              if(lws_add_http_header_content_length(wsi, 0, &p, end)) return 1;
              if(lws_finalize_http_header(wsi, &p, end)) return 1;
              ctxpss->websocket->opengalaxy().syslog().debug(
                "Session: Redirecting %s to session id: %llX",
                s->auth->fullname().c_str(), s->session.id
              );
              n = lws_write(
                wsi,
                ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING,
                p - (ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING),
                LWS_WRITE_HTTP_HEADERS
              );
              break;


            }
            // Session id's match
            s->session_was_started = 1;
          }
        }
        else {
          // reset upon loading the file after index.html
          s->session_was_started = 0;
        }

        // If the URI does not have a (valid) session id in the query string,
        // but does have a session id appended to the REFERER header, then
        // use a server redirect to the url with !that! session id appended
        // to the query string.
        if(s_id != s->session.id){
          int pos = http_referer.find(Session::query_string);
          if((unsigned)pos != std::string::npos){
            char *str = (char*)http_referer.c_str();
            s_id = strtoull((char*)&str[pos+strlen(Session::query_string)], nullptr, 16);
            if(s_id != 0){
              p = ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING;
              snprintf(
                ctxpss->websocket->http_path_buffer,
                sizeof(ctxpss->websocket->http_path_buffer),
                ctxpss->websocket->fmt_redirect_uri,
                (char*)in,
                Session::query_string,
                s_id
              );
              unsigned char *end =
                p + sizeof(ctxpss->websocket->http_file_buffer) - LWS_SEND_BUFFER_PRE_PADDING;
              if(lws_add_http_header_status(
                wsi,
                HTTP_STATUS_TEMPORARY_REDIRECT,
                &p,
                end)
              ) return 1;
              if(lws_add_http_header_by_name(
                wsi,
                (const unsigned char *)"Location:",
                (unsigned char *)ctxpss->websocket->http_path_buffer,
                strlen(ctxpss->websocket->http_path_buffer),
                &p,
                end)
              ) return 1;
              if(lws_add_http_header_content_length(wsi, 0, &p, end)) return 1;
              if(lws_finalize_http_header(wsi, &p, end)) return 1;
              n = lws_write(
                wsi,
                ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING,
                p - (ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING),
                LWS_WRITE_HTTP_HEADERS
              );
              break;
            }
            else {
              // No session id at all
              // block serving the file but make an exception for /favicon.ico (firefox)
              if(strcmp("/favicon.ico",(char*)in)!=0){
                s->logoff();
                ctxpss->websocket->opengalaxy().syslog().debug(
                  "Session: no valid session whilst serving \"%s\", blocking!",
                  (char*)in
                );
                lws_return_http_status(
                  wsi,
                  HTTP_STATUS_FORBIDDEN,
                  "You do not own this session!"
                );
                return -1;
              }
              // fall through
            }
          }
        }

        // If the session does not match
        // block serving the file but make an exception for /favicon.ico
        // (firefox does not add the REFERER tag when requesting this file)
        if(s_id != s->session.id){
          if(strcmp("/favicon.ico",(char*)in)!=0){
            s->logoff();
            ctxpss->websocket->opengalaxy().syslog().error(
              "Session: session mismatch, blocking!"
            );
            lws_return_http_status(
              wsi,
              HTTP_STATUS_FORBIDDEN,
              "You do not own this session!"
            );
            return -1;
          }
        }

        // Valid session, reset the 'unused session' timeout timer
        s->timeout_tp = std::chrono::high_resolution_clock::now();

        // Reset the activity timeout for this session
        s->set_active();
      }

      // do not accept post data
      if(lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) return 1;

      // this server has no knowledge of directories
      // So only serve files that were explicitly approved by us
      for(m = 0, n = 1; ctxpss->websocket->valid_files_to_serve[m]; m++){
        n = strcmp((char*)in + 1, ctxpss->websocket->valid_files_to_serve[m]);
        if(n == 0) break;
      }
      if(n != 0){
        ctxpss->websocket->opengalaxy().syslog().error("Websocket: HTTP GET Request denied for unregistered file: '%s'", (char*)in);
        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "Not a registered file.");
        goto try_to_reuse;
      }

      // found it in the whitelist
      // disallow the browser to cache this file? then send some extra http headers
      if(ctxpss->websocket->valid_files_to_cache[m] == 0) other_headers = (char*)nocache_headers;

      // Compile a path to the file to serve in http_path_buffer
      strncpy(
        ctxpss->websocket->http_path_buffer,
        ctxpss->websocket->path_www_root.data(),
        sizeof(ctxpss->websocket->http_path_buffer)
      );
      if(strcmp((const char*)in, "/")){
        if(*((const char *)in) != '/') strcat(
          ctxpss->websocket->http_path_buffer, "/"
        );
        strncat(
          ctxpss->websocket->http_path_buffer,
          (const char*)in,
          sizeof(ctxpss->websocket->http_path_buffer) - 1 -
            ctxpss->websocket->path_www_root.size()
        );
      }
      else {
        // default file to serve
        strncat(
          ctxpss->websocket->http_path_buffer,
          ctxpss->websocket->www_root_document,
          sizeof(ctxpss->websocket->http_path_buffer) - 1
        );
      }
      ctxpss->websocket->http_path_buffer[
        sizeof(ctxpss->websocket->http_path_buffer) - 1
      ] = '\0';

      // Get the MIME type
      mimetype = get_http_mimetype(ctxpss->websocket->http_path_buffer);

      // Check the MIME type and refuse to serve files we don't understand
      if(!mimetype){
        ctxpss->websocket->opengalaxy().syslog().error(
          "Websocket: Unknown mimetype for %s",
          ctxpss->websocket->http_path_buffer
        );
        lws_return_http_status(
          wsi,
          HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
          "Unsupported MIME type!"
        );
        return -1;
      }

	    n = lws_serve_http_file(
        wsi,
        ctxpss->websocket->http_path_buffer,
        mimetype,
        other_headers,
        (other_headers) ? strlen(other_headers) : 0
      );
      // error or can't reuse connection: close the socket
	    if(n < 0 || ((n > 0) && lws_http_transaction_completed(wsi))) return -1;

	    // notice that the sending of the file completes asynchronously,
	    // we'll get a LWS_CALLBACK_HTTP_FILE_COMPLETION callback when
	    // it's done
      break;
    }


    case LWS_CALLBACK_HTTP_WRITEABLE: {

      ctxpss->websocket->opengalaxy().syslog().debug(
        "Websocket: serving file: %s",
        ctxpss->websocket->http_path_buffer
      );

      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);
      // we can send more of whatever it is we were sending
      do {
        // we'd like the send this much
        n = sizeof(ctxpss->websocket->http_file_buffer) - LWS_SEND_BUFFER_PRE_PADDING;
        // but if the peer told us he wants less, we can adapt
        m = lws_get_peer_write_allowance(wsi);
        // -1 means not using a protocol that has this info
        if(m == 0) goto later; // right now, peer can't handle anything
        if(m != -1 && m < n) n = m; // he couldn't handle that much
        n = read(pss->fd, ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING, n);
        if(n < 0)	goto bail; // problem reading, close conn
        if(n == 0) goto flush_bail; // sent it all, close conn
        //
        // To support HTTP2, must take care about preamble space
        //
        // identification of when we send the last payload frame
        // is handled by the library itself if you sent a
        // content-length header
        //
        m = lws_write(
          wsi,
          ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING,
          n,
          LWS_WRITE_HTTP
        );
        if(m < 0) goto bail; // write failed, close conn
        //
        // http2 won't do this
        //
        if(m != n){
          // partial write, adjust
          if(lseek(pss->fd, m - n, SEEK_CUR) < 0) goto bail;
        }
        // while still active, extend timeout
        if(m) lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 5);
        // if we have indigestion, let him clear it before eating more
        if(lws_partial_buffered(wsi)) break;
      }
      while(!lws_send_pipe_choked(wsi));

later:
      lws_callback_on_writable(wsi);
      break;

flush_bail:
      // true if still partial pending
      if(lws_partial_buffered(wsi)){
        lws_callback_on_writable(wsi);
        break;
      }
      close(pss->fd);
      goto try_to_reuse;

bail:
      close(pss->fd);
      return -1;
    }

    default:
      break;
  }

  return 0;

try_to_reuse:
	if(lws_http_transaction_completed(wsi)) return -1;
	return 0;
}


} // ends namespace openGalaxy

