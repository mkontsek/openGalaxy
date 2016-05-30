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

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#ifdef __linux__
#include <sys/utsname.h>
#endif

namespace openGalaxy {

// Loads the CA-certificate bundle and
// loads/enables the certificate revocation list (CRL).
int Websocket::ssl_load_certs(SSL_CTX *ctx, struct lws_context *context)
{
  int n;
  char errbuf[160];
  ContextUserData *ctxpss = (ContextUserData *) lws_context_user(context);

  // Load the CA bundle
  n = SSL_CTX_load_verify_locations(
    ctx, ctxpss->websocket->fn_ca_cert.c_str(), nullptr
  );
  if( n != 1 ){
    n = ERR_get_error();
    ctxpss->websocket->opengalaxy().syslog().error(
      "Websocket: Problem loading the CA certificate bundle: %s",
      ERR_error_string( n, errbuf )
    );
    ctxpss->websocket->opengalaxy().syslog().error(
      "Did you remember to setup the SSL certificates with opengalaxy-ca?"
    );
    ctxpss->websocket->opengalaxy().syslog().error(
      "(To disable SSL start opengalaxy with the --disable-ssl option)"
    );
    return 1;
  }

  // Enable CRL Checking
  X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
  X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
  SSL_CTX_set1_param(ctx, param);

  // Load the CRL into memory
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
  n = X509_load_cert_crl_file(
    lookup, ctxpss->websocket->fn_crl_cert.c_str(), X509_FILETYPE_PEM
  );
  if(n != 1){
    n = ERR_get_error();
    ctxpss->websocket->opengalaxy().syslog().error(
      "Websocket: problem loading CRL: %s : %s",
      ctxpss->websocket->fn_crl_cert.data(),
      ERR_error_string(n, errbuf)
    );
    ctxpss->websocket->opengalaxy().syslog().error(
      "Did you remember to setup the SSL certificates with opengalaxy-ca?"
    );
    ctxpss->websocket->opengalaxy().syslog().error(
      "(To disable SSL start opengalaxy with the --disable-ssl option)"
    );
    return 1;
  }

  X509_VERIFY_PARAM_free(param);
  return 0;
}


// Called as the OpenSSL
// 'int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);'
// callback by LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION.
// (lws return conventions apply.)
int Websocket::ssl_verify_client_cert(struct lws_context *context, SSL *ssl, X509_STORE_CTX *store, int preverify_ok)
{
  int n = 0;
  ContextUserData *ctxpss = (ContextUserData *) lws_context_user(context);

  n = !preverify_ok;
  if(n){
    // The peer certificate failed to be verified, log the error.
    int err = X509_STORE_CTX_get_error(store);
    int depth = X509_STORE_CTX_get_error_depth(store);
    const char* msg = X509_verify_cert_error_string(err);
    ctxpss->websocket->opengalaxy().syslog().error(
      "Websocket: SSL client certificate error: %s (0x%02X), depth: %d",
      msg,
      err,
      depth
    );
  }
  else {
    // Assume the peer certificate is invalid OR could not be authenticated
    n = 1;
    // Do not trust preverify_ok, check the result with SSL_get_verify_result()
    if(SSL_get_verify_result(ssl) == X509_V_OK){
      n = 0; // verified ok
    }
    else {
      // The peer certificate failed to be verified, log the error.
      int err = X509_STORE_CTX_get_error(store);
      int depth = X509_STORE_CTX_get_error_depth(store);
      const char* msg = X509_verify_cert_error_string(err);
      ctxpss->websocket->opengalaxy().syslog().error(
        "Websocket: SSL client certificate error: %s (0x%02X), depth: %d",
        msg,
        err,
        depth
      );
    }
  }

  return n;
}

} // ends namespace openGalaxy

