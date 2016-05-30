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

#include "atomic.h"
#include "opengalaxy.hpp"
#include "json.h"
#include "credentials.h"

namespace openGalaxy {

//
// class Session implementation:
//

// ctor
Session::Session(class Websocket* websocket)
 : m_openGalaxy(websocket->opengalaxy()), session(websocket->opengalaxy().m_options)
{
  auth = nullptr;
  session.sha256str[0] = '\0';
  session.id = rand();
  ssl_rand_pseudo_bytes((unsigned char*)&session.id, sizeof(session.id));
  session_starting = 0;
  session_was_started = 0;
  last_activity_tp = timeout_tp = std::chrono::high_resolution_clock::now();
  logged_on = 0;
  http_connected = 0;
  websocket_connected = 0;
  websocket_wsi = nullptr;
  websocket_pss = nullptr;
}


// dtor
Session::~Session()
{
  logoff();
  if(auth) delete auth;
}


// static function:
// Retrieve or create session
int Session::start(
  struct lws *wsi,
  struct session_id& session,
  Session** s
){
  // Sanity check arguments
  if(!wsi || !s) return 1;

  int n = 0;
  *s = nullptr;

  // Get lws context
  struct lws_context *context = lws_get_context(wsi);
  if(!context) return 1;

  // Get lws context userdata
  Websocket::ContextUserData *ctxpss = (Websocket::ContextUserData *) lws_context_user(context);
  if(!ctxpss) return 1;

  // get the ip address and hostname of the client
  char hostname[1024], ipaddress[256];
  lws_get_peer_addresses(
    wsi,
    lws_get_socket_fd(wsi),
    hostname, sizeof hostname,
    ipaddress, sizeof ipaddress
  );
  if(strlen(ipaddress) == 0){
    ctxpss->websocket->opengalaxy().syslog().error(
      "Session: Error, could not retrieve client ip address"
    );
    return 1;
  }

  X509 *x509 = nullptr;
  std::string sha256finger;
  if(
    (ctxpss->websocket->opengalaxy().m_options.no_ssl == 0) &&
    (ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0)
  ){
    // Obtain pointer to SSL from lws and get the peer certificate
    SSL *ssl = lws_get_ssl(wsi);

    x509 = (ssl) ? SSL_get_peer_certificate(ssl) : nullptr;
    if(!x509){
      ctxpss->websocket->opengalaxy().syslog().error(
        "Session: Unable to get the client SSL certificate from the SSL library."
      );
      return 1;
    }

    // calculate the SHA-256 fingerprint for this client (certificate)
    char *ftmp = ssl_calculate_sha256_fingerprint(x509);
    if(!ftmp){
      ctxpss->websocket->opengalaxy().syslog().error(
        "Session: "
        "Unable to calculate SHA-256 fingerprint for client SSL certificate."
      );
      return 1;
    }
    sha256finger.assign(ftmp);
    ssl_free(ftmp);

    *s = Session::get(sha256finger.c_str(), context);
  }
  else {
    *s = Session::get(wsi, context);
  }

  // Existing session?
  if(!*s){
    // No, create and add a new one
    *s = new Session(ctxpss->websocket);
    Session::add(*s, context);
    (*s)->hostname.assign(hostname);
    (*s)->ip_address.assign(ipaddress);
  }
  else {
    // Yes, traverse the list of clients to see if this client cert is already
    // in use at another ip address
    for(int i = 0; i < ctxpss->sessions.size(); i++){
      if(ctxpss->sessions[i]->session == (*s)->session){
        // found it in the list, is it another address
        if(
          ctxpss->sessions[i]->ip_address.compare(ipaddress) != 0 ||
          ctxpss->sessions[i]->hostname.compare(hostname) != 0
        ){
          // Yes it is another address,
          // do not allow the connection untill that session times out.
          ctxpss->websocket->opengalaxy().syslog().error(
            "Session: Error, client is allready connected from %s (%s).",
            ctxpss->sessions[i]->hostname.c_str(),
            ctxpss->sessions[i]->ip_address.c_str()
          );
          return 1;
        }
        // connected from the same address: allow this new connection
        break;
      }
    }
  }

  session.id = (*s)->session.id;

  if(
    (ctxpss->websocket->opengalaxy().m_options.no_ssl == 0) &&
    (ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0)
  ){
    strncpy((*s)->session.sha256str, sha256finger.c_str(), 2*SSL_SHA256LEN+1);
    strncpy(session.sha256str, sha256finger.c_str(), 2*SSL_SHA256LEN+1);

    // Existing Credentials?
    if(!(*s)->auth){
      // No, create a new auth:
      (*s)->auth = new Credentials(
        *(ctxpss->websocket),
        sha256finger.c_str()
      );
    }

    if((*s)->auth->parse_cert(x509) == false){
      delete (*s)->auth;
      (*s)->auth = nullptr;
      n = 1;
    }
  }
  else {
    (*s)->session.websocket_wsi = wsi;
    session.websocket_wsi = wsi;
  }

  return n;
}


// static function:
// Add a session to the global session array
// out: 0 if the session was added
int Session::add(Session *s, struct lws_context* context)
{
  Websocket::ContextUserData *ctxpss =
    (Websocket::ContextUserData *) lws_context_user(context);

  for(int i=0; i < ctxpss->sessions.size(); i++){
    if(ctxpss->sessions[i]->session == s->session){
      return -1;
    }
  }
  ctxpss->sessions.append(s);
  return 0;
}


// static function:
// Get a session from the global session array
// - by session_id
Session *Session::get(
  session_id& session,
  struct lws_context* context
){
  Websocket::ContextUserData *ctxpss =
    (Websocket::ContextUserData *) lws_context_user(context);

  Session *s = nullptr;
  for(int i=0; i < ctxpss->sessions.size(); i++){
    if(ctxpss->sessions[i]->session == session){
      s = ctxpss->sessions[i];
      break;
    }
  }
  return s;
}
// - by SHA-256 fingerprint
Session *Session::get(
  const char *sha256str,
  struct lws_context* context
){
  Websocket::ContextUserData *ctxpss =
    (Websocket::ContextUserData *) lws_context_user(context);

  Session *s = nullptr;
  for(int i=0; i < ctxpss->sessions.size(); i++){
    if(strcmp(ctxpss->sessions[i]->session.sha256str, sha256str) == 0){
      s = ctxpss->sessions[i];
      break;
    }
  }
  return s;
}
// - by wsi
Session *Session::get(
  struct lws* wsi,
  struct lws_context* context
){
  Websocket::ContextUserData *ctxpss =
    (Websocket::ContextUserData *) lws_context_user(context);

  Session *s = nullptr;
  for(int i=0; i < ctxpss->sessions.size(); i++){
    if(ctxpss->sessions[i]->session.websocket_wsi == wsi){
      s = ctxpss->sessions[i];
      break;
    }
  }
  return s;
}


// static function:
// Delete a session from the global session array
void Session::remove(
  session_id& session,
  struct lws_context* context
){
  Websocket::ContextUserData *ctxpss =
    (Websocket::ContextUserData *) lws_context_user(context);

  for(int i=0; i < ctxpss->sessions.size(); i++){
    if(ctxpss->sessions[i]->session == session){
      ctxpss->websocket->opengalaxy().syslog().debug(
        "Session: Deleting session %llX", ctxpss->sessions[i]->session.id
      );
      ctxpss->sessions.remove(i);
      break;
    }
  }
}


// static function:
// Remove sessions that have a disconnected client or were
// started but never used, called periodicly by Websocket::Thread()
void Session::check_timeouts_and_remove_unused_sessions(struct lws_context* context)
{
  using namespace std::chrono;

  Websocket::ContextUserData *ctxpss =
    (Websocket::ContextUserData *) lws_context_user(context);

  auto end_tp = high_resolution_clock::now();
  auto end_seconds = time_point_cast<seconds>(end_tp);
  auto end_value = duration_cast<seconds>(end_seconds.time_since_epoch());

  for(int i = 0; i < ctxpss->sessions.size(); i++){ // loop over all (unconnected) sessions
    if(ctxpss->sessions[i]->http_connected == 0 && ctxpss->sessions[i]->websocket_connected == 0) {
      auto start_seconds = time_point_cast<seconds>(ctxpss->sessions[i]->timeout_tp);
      auto start_value = duration_cast<seconds>(start_seconds.time_since_epoch());
      auto delta = end_value - start_value;

      if(delta.count() < 0 || delta.count() > Session::unused_timeout_seconds){
        ctxpss->websocket->opengalaxy().syslog().debug(
          "Session: Timeout, deleting session %llX", ctxpss->sessions[i]->session.id
        );
        ctxpss->sessions.remove(i); // Timed out: Delete the unused session.
      }
    }
  }
}


int Session::login(const char *username, const char *password)
{
  logged_on = 0;
  if(!auth){
    opengalaxy().syslog().debug("Session: could not locate authentication!");
  }
  else{
    if(auth->username().compare(username) == 0){
      if(auth->password().compare(password) == 0){
        logged_on = 1;
      }
      else {
        opengalaxy().syslog().debug("Session: password does not match!");
      }
    }
    else {
      opengalaxy().syslog().debug("Session: username does not match!");
    }
  }
  return logged_on;
}


int Session::authorized()
{
  return logged_on;
}


void Session::logoff()
{
  logged_on = 0;
  timeout_tp = std::chrono::high_resolution_clock::now();
}


// reset the activity timeout
void Session::set_active()
{
  last_activity_tp = std::chrono::high_resolution_clock::now();
}


// static function:
// logoff clients whoms activity timer has timed out.
// called periodicly by Websocket::Thread()
void Session::logoff_timed_out_clients(struct lws_context* context)
{
  using namespace std::chrono;
  Websocket::ContextUserData *ctxpss =
    (Websocket::ContextUserData *) lws_context_user(context);

  auto end_tp = high_resolution_clock::now();
  auto end_seconds = time_point_cast<seconds>(end_tp);
  auto end_value = duration_cast<seconds>(end_seconds.time_since_epoch());

  for(int i = 0; i < ctxpss->sessions.size(); i++){
    if(ctxpss->sessions[i]->authorized()){
      auto start_seconds = time_point_cast<seconds>(ctxpss->sessions[i]->last_activity_tp);
      auto start_value = duration_cast<seconds>(start_seconds.time_since_epoch());
      auto delta = end_value - start_value;

      if(
        (delta.count() < 0) ||
        (
          delta.count() >=
          ctxpss->websocket->opengalaxy().settings().session_timeout_seconds
        )
      ){
        ctxpss->sessions[i]->logoff();
        ctxpss->websocket->opengalaxy().syslog().debug(
          "Session: Logging off %s due to %d seconds of inactivity",
          ctxpss->sessions[i]->auth->fullname().c_str(),
          ctxpss->websocket->opengalaxy().settings().session_timeout_seconds
        );
        // Timed out: Logoff the client
        ctxpss->websocket->WriteAuthorizationRequiredMessage(
          ctxpss,
          ctxpss->sessions[i]->session.id,
          ctxpss->sessions[i]->auth->fullname(),
          &ctxpss->sessions[i]->session
        );
      }
    }
  }
}

//
// class Credentials implementation:
//

int Credentials::nid_opengalaxy_embedded_data = 0;


void Credentials::register_OID_with_openssl(void)
{
  // Create the NID used by our embedded data in client certificates
  // subjectAlternativeName->otherName and add it to OpenSSLs internal table.
  // (1.2.3.4 is the OID that was given to the data by openGalaxy-CA)
  nid_opengalaxy_embedded_data = OBJ_create("1.2.3.4", "OGALAXY", "openGalaxy client credentials");
}


void Credentials::unregister_OID_from_openssl(void)
{
  // Cleanup OpenSSLs internal object table
  OBJ_cleanup();
}


// default ctor
Credentials::Credentials(
  Websocket& websocket,
  const char *fingerprint
)
: m_openGalaxy(websocket.opengalaxy())
{
  cert_sha256.assign(fingerprint);
}


// copy ctor
Credentials::Credentials(Credentials& i) : m_openGalaxy(i.m_openGalaxy)
{
  cert_serial.assign(i.cert_serial);
  cert_sha256.assign(i.cert_sha256);
  cert_not_before.assign(i.cert_not_before);
  cert_not_after.assign(i.cert_not_after);
  cert_subj_commonname.assign(i.cert_subj_commonname);
  cert_subj_emailaddress.assign(i.cert_subj_emailaddress);
  cert_san_othername = i.cert_san_othername;
}


// Retrieve all the information we need from a client certificate
bool Credentials::parse_cert(X509 *cert)
{
  int i;
  char field_oid[128];
#ifdef MAX_VERBOSE_CERTS
  char field_name[128];
#endif
  unsigned char *field_str;
  X509_NAME_ENTRY *ne;
  ASN1_OBJECT *asn1_obj;
  ASN1_STRING *asn1_str;

  // Subject: iterate over all entries (instead of using X509_NAME_oneline)
  X509_NAME *x509_subj = X509_get_subject_name(cert);
  for (i = 0; i < X509_NAME_entry_count(x509_subj); i++) {
    ne = X509_NAME_get_entry(x509_subj, i);
    asn1_obj = X509_NAME_ENTRY_get_object(ne);

    // !0 means it will prefer a numerical representation
    OBJ_obj2txt(field_oid, sizeof(field_oid), asn1_obj, 1);

    asn1_str = X509_NAME_ENTRY_get_data(ne);
    field_str = ASN1_STRING_data(asn1_str);

#ifdef MAX_VERBOSE_CERTS
    // 0 means it will prefer a textual representation (if available)
    OBJ_obj2txt(field_name, sizeof(field_name), asn1_obj, 0);
    opengalaxy().syslog().info(
      "Certificate Subject %s (%s): %s",
      field_name,
      field_oid,
      field_str
    );
#endif
    // openGalaxy stores the clients full name in the subject commonname
    if(strcmp(field_oid, "2.5.4.3" /* commonName */) == 0){
      cert_subj_commonname.assign((char*)field_str);
    }
    // openGalaxy stores the clients email address in the subject emailaddress
    if(strcmp(field_oid, "1.2.840.113549.1.9.1" /* emailAddress */) == 0){
      cert_subj_emailaddress.assign((char*)field_str);
    }
	}

#ifdef MAX_VERBOSE_CERTS
  // Issuer: iterate over all entries (instead of using X509_NAME_oneline)
  X509_NAME *x509_issuer = X509_get_issuer_name(cert);
  for (i = 0; i < X509_NAME_entry_count(x509_issuer); i++) {
    ne = X509_NAME_get_entry(x509_issuer, i);
    asn1_obj = X509_NAME_ENTRY_get_object(ne);

    // !0 means it will prefer a numerical representation
    OBJ_obj2txt(field_oid, sizeof(field_oid), asn1_obj, 1);

    // 0 means it will prefer a textual representation (if available)
    OBJ_obj2txt(field_name, sizeof(field_name), asn1_obj, 0);

    asn1_str = X509_NAME_ENTRY_get_data(ne);
    unsigned char *field_str = ASN1_STRING_data(asn1_str);
    opengalaxy().syslog().info(
      "Certificate Issuer %s (%s): %s",
      field_name,
      field_oid,
      field_str
    );
	}
#endif

#ifdef MAX_VERBOSE_CERTS
  opengalaxy().syslog().debug(
    "Certificate SHA-256 fingerprint: %s",
    cert_sha256.c_str()
  );
#endif

#ifdef MAX_VERBOSE_CERTS
  // Get the certificate version
  int version = ((int) X509_get_version(cert)) + 1;
  opengalaxy().syslog().debug("Certificate Version: %d", version);
#endif

  // Get the certificate serialnumber.
  ASN1_INTEGER *serial = X509_get_serialNumber(cert);
  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, nullptr);
  if (!bn) {
    opengalaxy().syslog().error("Credentials: unable to convert ASN1 INTEGER to BN");
    return false;
  }
  char *sn_str = BN_bn2hex(bn);
  if(!sn_str) {
    opengalaxy().syslog().error("Credentials: unable to convert BN to hexadecimal string.");
    BN_free(bn);
    return false;
  }
#ifdef MAX_VERBOSE_CERTS
  opengalaxy().syslog().debug("Certificate Serialnumber: %s", sn_str);
#endif
  cert_serial.assign(sn_str);
  BN_free(bn);
  OPENSSL_free(sn_str);

#ifdef MAX_VERBOSE_CERTS
  // Get the Signature Algorithm
  int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if(pkey_nid == NID_undef){
    opengalaxy().syslog().error("Credentials: Unable to find specified signature algorithm name.");
    return false;
  }
  const char* sslbuf = OBJ_nid2ln(pkey_nid);
  std::string pkey_algo = sslbuf;
  opengalaxy().syslog().debug(
    "Certificate Public Key Signature Algorithm: %s",
    pkey_algo.c_str()
  );
#endif

#ifdef MAX_VERBOSE_CERTS
  // Get the Public Key (type specific: RSA, DSA)
  if(pkey_nid == NID_rsaEncryption || pkey_nid == NID_dsa){
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if(!pkey){
      opengalaxy().syslog().error("Credentials: Unable to extract public key from certificate");
      return false;
    }
    RSA *rsa_key;
    DSA *dsa_key;
    char *rsa_e_dec, *rsa_n_hex, *dsa_p_hex;
    char *dsa_q_hex, *dsa_g_hex, *dsa_y_hex;
    switch(pkey_nid){

      case NID_rsaEncryption:
        rsa_key = pkey->pkey.rsa;
        if(!rsa_key){
          opengalaxy().syslog().error("Credentials: Unable to extract RSA public key");
        }

        rsa_e_dec = BN_bn2dec(rsa_key->e);
        if(!rsa_e_dec){
          opengalaxy().syslog().error("Credentials: Unable to extract rsa exponent");
        }
        else {
          opengalaxy().syslog().debug(
            "Certificate Public Key RSA Exponent (dec.): %s",
            rsa_e_dec
          );
        }
        OPENSSL_free(rsa_e_dec);

        rsa_n_hex = BN_bn2hex(rsa_key->n);
        if(!rsa_n_hex){
          opengalaxy().syslog().error("Credentials: Unable to extract rsa modulus");
        }
        else {
          opengalaxy().syslog().debug(
            "Certificate Public Key RSA Modules (hex.): %s",
            rsa_n_hex
          );
        }
        OPENSSL_free(rsa_n_hex);
        break;

      case NID_dsa:
        dsa_key = pkey->pkey.dsa;
        if(!dsa_key){
          opengalaxy().syslog().error("Credentials: Unable to extract DSA pkey");
        }

        dsa_p_hex = BN_bn2hex(dsa_key->p);
        if(!dsa_p_hex){
          opengalaxy().syslog().error("Credentials: Unable to extract DSA p");
        }
        else {
          opengalaxy().syslog().debug(
            "Certificate Public Key DSA p (hex.): %s", dsa_p_hex
          );
        }
        OPENSSL_free(dsa_p_hex);

        dsa_q_hex = BN_bn2hex(dsa_key->q);
        if(!dsa_q_hex){
          opengalaxy().syslog().error("Credentials: Unable to extract DSA q");
        }
        else {
          opengalaxy().syslog().debug(
            "Certificate Public Key DSA q (hex.): %s",
            dsa_q_hex
          );
        }
        OPENSSL_free(dsa_q_hex);

        dsa_g_hex = BN_bn2hex(dsa_key->g);
        if(!dsa_g_hex){
          opengalaxy().syslog().error("Credentials: Unable to extract DSA g");
        }
        else {
          opengalaxy().syslog().debug(
            "Certificate Public Key DSA g (hex.): %s",
            dsa_g_hex
          );
        }
        OPENSSL_free(dsa_g_hex);

        dsa_y_hex = BN_bn2hex(dsa_key->pub_key);
        if(!dsa_y_hex){
          opengalaxy().syslog().error("Credentials: Unable to extract DSA y");
        }
        else {
          opengalaxy().syslog().debug(
            "Certificate Public Key DSA y (hex.): %s",
            dsa_y_hex
          );
        }
        OPENSSL_free(dsa_y_hex);
        break;

      default:
        break;
    }
    EVP_PKEY_free(pkey);
  }
  else {
    opengalaxy().syslog().error("Credentials: Unable to extract public key from certificate");
  }
#endif

  // Get Validity Period
#define DATE_LEN 128
  ASN1_TIME *not_before = X509_get_notBefore(cert);
  ASN1_TIME *not_after = X509_get_notAfter(cert);
  char not_after_str[DATE_LEN];
  char not_before_str[DATE_LEN];
  if(ssl_convert_ASN1TIME(not_after, not_after_str, DATE_LEN)){
    opengalaxy().syslog().error("Credentials: Unable to get certificate 'not after' date.");
    return false;
  }
  if(ssl_convert_ASN1TIME(not_before, not_before_str, DATE_LEN)){
    opengalaxy().syslog().error("Credentials: Unable to get certificate 'not before' date.");
    return false;
  }
#ifdef MAX_VERBOSE_CERTS
  opengalaxy().syslog().debug(
    "Certificate 'not-before' date: %s",
    not_before_str
  );
  opengalaxy().syslog().debug(
    "Certificate 'not-after' date: %s",
    not_after_str
  );
#endif
  cert_not_before.assign(not_before_str);
  cert_not_after.assign(not_after_str);
#undef DATE_LEN

  // Is the cert a CA
#ifdef MAX_VERBOSE_CERTS
  int isCA = X509_check_ca(cert);
  opengalaxy().syslog().debug(
    "Certificate is CA: %s",
    (isCA >= 1) ? "yes" : "no"
  );
#endif

  // Get any other X.509 extensions
#define EXTNAME_LEN 128
#define EXTVALUE_LEN 256
  STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;

  int nr_of_exts;
  if(exts){
    nr_of_exts = sk_X509_EXTENSION_num(exts);
  }
  else {
    nr_of_exts = 0;
  }

  if(!nr_of_exts){
    opengalaxy().syslog().error("Credentials: Error parsing number of X509v3 extensions.");
    return false;
  }

  for(i = 0; i < nr_of_exts; i++){
    X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
    if(!ex){
      opengalaxy().syslog().error("Credentials: Unable to extract extension from stack");
      return false;
    }
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    if(!obj){
      opengalaxy().syslog().error("Credentials: Unable to extract ASN1 object from extension");
      return false;
    }

    BIO *ext_bio = BIO_new(BIO_s_mem());
    if(!ext_bio){
      opengalaxy().syslog().error("Credentials: Unable to allocate memory for extension value BIO");
      return false;
    }
    if(!X509V3_EXT_print(ext_bio, ex, 0, 0)){
      M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(ext_bio, &bptr);
    int x __ATTR_NOT_USED__ = BIO_set_close(ext_bio, BIO_NOCLOSE);

    // remove newlines
    int lastchar = bptr->length;
    if(
      (lastchar > 1) &&
      ((bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r'))
    ){
      bptr->data[lastchar-1] = (char) 0;
    }
    if(
      (lastchar > 0) &&
      ((bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r'))
    ){
      bptr->data[lastchar] = (char) 0;
    }

    BIO_free(ext_bio);

    unsigned int nid = OBJ_obj2nid(obj);
    // get OID 
    char extname[EXTNAME_LEN];
    OBJ_obj2txt(extname, EXTNAME_LEN, (const ASN1_OBJECT *) obj, 1);
#ifdef MAX_VERBOSE_CERTS
    opengalaxy().syslog().debug(
      "Certificate X509v3 Extension (%d) OID: %s",
      i,
      extname
    );
#endif
    if(nid != NID_undef){
      // the OID translated to a NID which
      // implies that the OID has a known sn/ln
      const char *c_ext_name = OBJ_nid2ln(nid);
      if(!c_ext_name){
        opengalaxy().syslog().error(
          "Credentials: Invalid X509v3 extension name"
        );
        return false;
      }
#ifdef MAX_VERBOSE_CERTS
      opengalaxy().syslog().debug(
        "Certificate X509v3 Extension (%d) Name: %s",
        i,
        c_ext_name
      );
#endif
    }
#ifdef MAX_VERBOSE_CERTS
    else {
      opengalaxy().syslog().debug(
        "Certificate X509v3 Extension (%d) Name: %s",
        i,
        "(unknown)"
      );
    }
#endif

    // bptr->data is not 0 terminated!
    char ext_value[bptr->length + 1];
    strncpy(ext_value, bptr->data, bptr->length);
    ext_value[bptr->length] = '\0';
#ifdef MAX_VERBOSE_CERTS
    opengalaxy().syslog().debug(
      "Certificate X509v3 Extension (%d) Value: %s",
      i,
      ext_value
    );
#endif

    // Get our embedded data from X509v3 Subject Alternative Name
    // (OID=2.5.29.17, otherName OID 1.2.3.4)
    if(strcmp(extname, "2.5.29.17")==0){
      // Get General Names
      const unsigned char* in = ex->value->data;
      GENERAL_NAMES *names = d2i_GENERAL_NAMES(NULL, &in, ex->value->length);
      if(names){
        int nr_of_names = sk_GENERAL_NAME_num(names);
        // Loop over all General Names entries in the SAN
        for(int j = 0; j < nr_of_names; j++){
          const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(names, j);
          // What type of enrtry is it?
          switch(current_name->type){
            case GEN_OTHERNAME: {
              const int other_nid = OBJ_obj2nid(
                current_name->d.otherName->type_id
              );
              const char *other_nid_value = (char*)ASN1_STRING_data(
                current_name->d.otherName->value->value.asn1_string
              );
#ifdef MAX_VERBOSE_CERTS
              char other_nid_oid[EXTNAME_LEN];
              OBJ_obj2txt(
                other_nid_oid,
                EXTNAME_LEN,
                (const ASN1_OBJECT *) current_name->d.otherName->type_id,
                1
              );
              const char *other_nid_ln = OBJ_nid2ln(other_nid);
              opengalaxy().syslog().debug(
                "Certificate X509v3 Extension otherName (%d,%d) OID: %s",
                i,
                j,
                other_nid_oid
              );
              opengalaxy().syslog().debug(
                "Certificate X509v3 Extension "
                "otherName (%d,%d) Name: %s (%d)",
                i,
                j,
                other_nid_ln,
                other_nid
              );
              opengalaxy().syslog().debug(
                "Certificate X509v3 Extension otherName (%d,%d) Value: %s",
                i,
                j,
                other_nid_value
              );
#endif
              if(opengalaxy().m_options.no_password == 0){
                // otherName entry, is it our OID
                if(other_nid == nid_opengalaxy_embedded_data){
                  if(other_nid_value){
                    std::string embedded;
                    embedded.assign(other_nid_value);

                    // decrypt and store credentials and privileges
                    client_credentials* c = client_credentials_decrypt((const char*) embedded.c_str(), opengalaxy().websocket().verify_key, opengalaxy().websocket().credentials_key);
                    if(c){
                      if(!c->fullname || !c->login || !c->password){
                        ssl_free(c->fullname);
                        ssl_free(c->login);
                        ssl_free(c->password);
                        ssl_free(c);
                        opengalaxy().syslog().error("Credentials: Missing credentials data in client certificate!");
                        return false;
                      }
                      cert_san_othername.fullname.assign(c->fullname);
                      cert_san_othername.username.assign(c->login);
                      cert_san_othername.password.assign(c->password);
                      ssl_free(c->fullname);
                      ssl_free(c->login);
                      ssl_free(c->password);
                      ssl_free(c);

#ifdef MAX_VERBOSE_CERTS
                      opengalaxy().syslog().debug(
                        "Certificate X509v3 Extension "
                        "otherName (%d,%d) Name    : %s",
                        i,
                        j,
                        cert_san_othername.fullname.c_str()
                      );
                      opengalaxy().syslog().debug(
                        "Certificate X509v3 Extension "
                        "otherName (%d,%d) Username: %s",
                        i,
                        j,
                        cert_san_othername.username.c_str()
                      );
                      opengalaxy().syslog().debug(
                        "Certificate X509v3 Extension "
                        "otherName (%d,%d) Password: %s",
                        i,
                        j,
                        cert_san_othername.password.c_str()
                      );
#endif
                    }
                    else {
                      opengalaxy().syslog().error("Credentials: Failed to decrypt!");
                      return false;
                    }
                  }
                }
              }
              break;
            }
            default: {
              break;
            }
          }
        }
      }
      else {
        opengalaxy().syslog().error("Credentials: Error, could not list 'general names' from client certificate SAN");
      }
    }

#undef EXTNAME_LEN
#undef EXTVALUE_LEN
  }

  return true;
}

} // ends namespace openGalaxy

