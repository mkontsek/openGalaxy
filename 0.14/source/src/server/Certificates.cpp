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
#include "Certificates.hpp"
#include "tmalloc.hpp"
#include "json.h"
#include "ssl_evp.h"

namespace openGalaxy {

struct packed_certs_t {
  size_t ca_cert_size;
  char*  ca_cert;
  size_t server_cert_size;
  char*  server_cert;
  size_t server_key_size;
  char*  server_key;
  size_t crl_cert_size;
  char*  crl_cert;
  size_t verify_key_size;
  char*  verify_key;
  size_t decrypt_key_size;
  char*  decrypt_key;
};

// Verify/decrypt/decode and save a received 'certificates package' to disk
//
// The input data is expected to be encrypted only if the server is running
// in SSL mode. Otherwise the data is expected to be in a plaintext
// base64 encoded JSON object.
//
int save_certificates(const char* json, class openGalaxy& opengalaxy)
{
  rsa_aes_encrypted_data ciphertext;
  char* plaintext;
  size_t plaintext_size;
  unsigned char* tmp;
  struct packed_certs_t certs;
  int retv = 0; // 0 = error

  FILE* fp;
  const char* fmt = "%s/%s";
  char* fn_buffer;
  size_t fn_buffer_size;

  json_item *i;
  json_object *o;

  // Only decrypt if we have keys to verify/decrypt with
  if(opengalaxy.m_options.no_ssl != 0){
    // In non-SSL mode the data is not encrypted
    // since we do not have the RSA keys yet
    plaintext = (char*)json;
    goto decrypted;
  }

  // Parse the JSON object with the ciphertext
  o = json_parse_objects(json);
  if(!o){
    opengalaxy.syslog().error("Failed to decode certificates package");
    return 0;
  }
  memset(&ciphertext, 0, sizeof(struct rsa_aes_encrypted_data_t));
  i = o->items;
  while( i != NULL ){
    if( i->data != NULL ){
      switch( i->data->type ){
        case json_string_value:

          if( strcmp( i->name->value, "sig" ) == 0 ){
            if(ciphertext.signature) thread_safe_free(ciphertext.signature);
            ciphertext.signature = (unsigned char*)thread_safe_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "rsa" ) == 0 ){
            if(ciphertext.rsa_ciphertext) thread_safe_free(ciphertext.rsa_ciphertext);
            ciphertext.rsa_ciphertext = (unsigned char*)thread_safe_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "aes" ) == 0 ){
            if(ciphertext.aes_ciphertext) thread_safe_free(ciphertext.aes_ciphertext);
            ciphertext.aes_ciphertext = (unsigned char*)thread_safe_strdup( i->data->content.string->value );
          }
          else {
            if(ciphertext.signature) thread_safe_free(ciphertext.signature);
            if(ciphertext.rsa_ciphertext) thread_safe_free(ciphertext.rsa_ciphertext);
            if(ciphertext.aes_ciphertext) thread_safe_free(ciphertext.aes_ciphertext);
            json_free_objects( o );
            opengalaxy.syslog().error("%s: Bad JSON string value", __func__);;
            return 0;
          }
          break;

        case json_number_value:
          if( strcmp( i->name->value, "mode" ) == 0 ){
            ciphertext.aes_mode = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "keysize" ) == 0 ){
            ciphertext.aes_keysize = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "mdsize" ) == 0 ){
            ciphertext.md_size = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "siglen" ) == 0 ){
            ciphertext.signature_size = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "rsalen" ) == 0 ){
            ciphertext.rsa_ciphertext_size = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "aeslen" ) == 0 ){
            ciphertext.aes_ciphertext_size = i->data->content.number->value;
          }
          else {
            if(ciphertext.signature) thread_safe_free(ciphertext.signature);
            if(ciphertext.rsa_ciphertext) thread_safe_free(ciphertext.rsa_ciphertext);
            if(ciphertext.aes_ciphertext) thread_safe_free(ciphertext.aes_ciphertext);
            json_free_objects( o );
            opengalaxy.syslog().error("%s: Bad JSON number value", __func__);;
            return 0;
          }
          break;

        default:
          if(ciphertext.signature) thread_safe_free(ciphertext.signature);
          if(ciphertext.rsa_ciphertext) thread_safe_free(ciphertext.rsa_ciphertext);
          if(ciphertext.aes_ciphertext) thread_safe_free(ciphertext.aes_ciphertext);
          json_free_objects( o );
          opengalaxy.syslog().error("%s: JSON decode failed", __func__);;
          return 0;
      }
      i = i->next;
    }
  }
  json_free_objects(o);

  // The members are base64 encoded so reverse this

  if(ciphertext.signature){
    tmp = NULL;
    ssl_base64_decode((const char*)ciphertext.signature, strlen((const char*)ciphertext.signature), &tmp, &plaintext_size);
    thread_safe_free(ciphertext.signature);
    ciphertext.signature = tmp;
  }

  if(ciphertext.rsa_ciphertext){
    tmp = NULL;
    ssl_base64_decode((const char*)ciphertext.rsa_ciphertext, strlen((const char*)ciphertext.rsa_ciphertext), &tmp, &plaintext_size);
    thread_safe_free(ciphertext.rsa_ciphertext);
    ciphertext.rsa_ciphertext = tmp;
  }

  if(ciphertext.aes_ciphertext){
    tmp = NULL;
    ssl_base64_decode((const char*)ciphertext.aes_ciphertext, strlen((const char*)ciphertext.aes_ciphertext), &tmp, &plaintext_size);
    thread_safe_free(ciphertext.aes_ciphertext);
    ciphertext.aes_ciphertext = tmp;
  }

  // Verify the signature, test the correctness of the SHA512 hash and finally
  // decrypt the data.
  if(!rsa_aes_verify_and_decrypt(&ciphertext, (void**)&plaintext, &plaintext_size, opengalaxy.websocket().verify_key, opengalaxy.websocket().credentials_key)){
    opengalaxy.syslog().error("%s: Certificates decrypt failed", __func__);
    ssl_free(ciphertext.signature);
    ssl_free(ciphertext.rsa_ciphertext);
    ssl_free(ciphertext.aes_ciphertext);
    return 0;
  }
  ssl_free(ciphertext.signature);
  ssl_free(ciphertext.rsa_ciphertext);
  ssl_free(ciphertext.aes_ciphertext);

decrypted:

  // The plaintext is another JSON object with the certificates stored
  // as base64 encoded C-strings

  // Parse the JSON object
  o = json_parse_objects(plaintext);
  if(opengalaxy.m_options.no_ssl == 0) ssl_free(plaintext);
  if(!o){
    opengalaxy.syslog().error("Failed to decode certificates package");
    return 0;
  }
  memset(&certs, 0, sizeof(struct packed_certs_t));
  i = o->items;
  while( i != NULL ){
    if( i->data != NULL ){
      switch( i->data->type ){
        case json_string_value:

          if( strcmp( i->name->value, "ca_cert" ) == 0 ){
            if(certs.ca_cert) thread_safe_free(certs.ca_cert);
            certs.ca_cert = thread_safe_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "server_cert" ) == 0 ){
            if(certs.server_cert) thread_safe_free(certs.server_cert);
            certs.server_cert = thread_safe_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "server_key" ) == 0 ){
            if(certs.server_key) thread_safe_free(certs.server_key);
            certs.server_key = thread_safe_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "crl_cert" ) == 0 ){
            if(certs.crl_cert) thread_safe_free(certs.crl_cert);
            certs.crl_cert = thread_safe_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "verify_key" ) == 0 ){
            if(certs.verify_key) thread_safe_free(certs.verify_key);
            certs.verify_key = thread_safe_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "decrypt_key" ) == 0 ){
            if(certs.decrypt_key) thread_safe_free(certs.decrypt_key);
            certs.decrypt_key = thread_safe_strdup( i->data->content.string->value );
          }
          else {
            if(certs.ca_cert) thread_safe_free(certs.ca_cert);
            if(certs.server_cert) thread_safe_free(certs.server_cert);
            if(certs.server_key) thread_safe_free(certs.server_key);
            if(certs.crl_cert) thread_safe_free(certs.crl_cert);
            if(certs.verify_key) thread_safe_free(certs.verify_key);
            if(certs.decrypt_key) thread_safe_free(certs.decrypt_key);
            json_free_objects( o );
            opengalaxy.syslog().error("%s: Bad JSON string value", __func__);;
            return 0;
          }
          break;

        default:
          if(certs.ca_cert) thread_safe_free(certs.ca_cert);
          if(certs.server_cert) thread_safe_free(certs.server_cert);
          if(certs.server_key) thread_safe_free(certs.server_key);
          if(certs.crl_cert) thread_safe_free(certs.crl_cert);
          if(certs.verify_key) thread_safe_free(certs.verify_key);
          if(certs.decrypt_key) thread_safe_free(certs.decrypt_key);
          json_free_objects( o );
          opengalaxy.syslog().error("%s: JSON decode failed", __func__);;
          return 0;
      }
      i = i->next;
    }
  }
  json_free_objects(o);

  if(
    !certs.ca_cert || !certs.server_cert || !certs.server_key ||
    !certs.crl_cert || !certs.verify_key || !certs.decrypt_key
  ){
    opengalaxy.syslog().error("%s: incomplete certificates package", __func__);;
    goto exit;
  }

  // Final base64 decode of the certificates stored in the JSON object

  tmp = NULL;
  ssl_base64_decode((const char*)certs.ca_cert, strlen(certs.ca_cert), &tmp, &certs.ca_cert_size);
  thread_safe_free(certs.ca_cert);
  certs.ca_cert = (char*)tmp;

  tmp = NULL;
  ssl_base64_decode((const char*)certs.server_cert, strlen(certs.server_cert), &tmp, &certs.server_cert_size);
  thread_safe_free(certs.server_cert);
  certs.server_cert = (char*)tmp;

  tmp = NULL;
  ssl_base64_decode((const char*)certs.server_key, strlen(certs.server_key), &tmp, &certs.server_key_size);
  thread_safe_free(certs.server_key);
  certs.server_key = (char*)tmp;

  tmp = NULL;
  ssl_base64_decode((const char*)certs.crl_cert, strlen(certs.crl_cert), &tmp, &certs.crl_cert_size);
  thread_safe_free(certs.crl_cert);
  certs.crl_cert = (char*)tmp;

  tmp = NULL;
  ssl_base64_decode((const char*)certs.verify_key, strlen(certs.verify_key), &tmp, &certs.verify_key_size);
  thread_safe_free(certs.verify_key);
  certs.verify_key = (char*)tmp;

  tmp = NULL;
  ssl_base64_decode((const char*)certs.decrypt_key, strlen(certs.decrypt_key), &tmp, &certs.decrypt_key_size);
  thread_safe_free(certs.decrypt_key);
  certs.decrypt_key = (char*)tmp;

  // Store the certificates in the proper locations

//opengalaxy.syslog().error(certs.ca_cert);
//opengalaxy.syslog().error(certs.server_cert);
//opengalaxy.syslog().error(certs.server_key);
//opengalaxy.syslog().error(certs.crl_cert);
//opengalaxy.syslog().error(certs.verify_key);
//opengalaxy.syslog().error(certs.decrypt_key);

  fn_buffer_size =
    strlen(fmt) +
    strlen(opengalaxy.settings().certificates_directory.c_str()) +
    64; // should be enough to complete any used path

  fn_buffer = (char*)thread_safe_malloc(fn_buffer_size);

  // Save the CA certificate
  snprintf(fn_buffer, fn_buffer_size, fmt, opengalaxy.settings().certificates_directory.c_str(), opengalaxy.websocket().fmt_ca_cert);
  if(!(fp = fopen(fn_buffer, "wb+"))){
    opengalaxy.syslog().error("%s: could not open ca_cert file", __func__);;
    goto exit;
  }
  if(1 != fwrite(certs.ca_cert, strlen(certs.ca_cert), 1, fp)){
    fclose(fp);
    opengalaxy.syslog().error("%s: could not write ca_cert file", __func__);;
    goto exit;
  }
  fflush(fp);
  fclose(fp);

  // Save the server certificate
  snprintf(fn_buffer, fn_buffer_size, fmt, opengalaxy.settings().certificates_directory.c_str(), opengalaxy.websocket().fmt_srv_cert);
  if(!(fp = fopen(fn_buffer, "wb+"))){
    opengalaxy.syslog().error("%s: could not open server_cert file", __func__);;
    goto exit;
  }
  if(1 != fwrite(certs.server_cert, strlen(certs.server_cert), 1, fp)){
    fclose(fp);
    opengalaxy.syslog().error("%s: could not write server_cert file", __func__);;
    goto exit;
  }
  fflush(fp);
  fclose(fp);

  // Save the server RSA private key
  snprintf(fn_buffer, fn_buffer_size, fmt, opengalaxy.settings().certificates_directory.c_str(), opengalaxy.websocket().fmt_srv_key);
  if(!(fp = fopen(fn_buffer, "wb+"))){
    opengalaxy.syslog().error("%s: could not open server_key file", __func__);;
    goto exit;
  }
  if(1 != fwrite(certs.server_key, strlen(certs.server_key), 1, fp)){
    fclose(fp);
    opengalaxy.syslog().error("%s: could not write server_key file", __func__);;
    goto exit;
  }
  fflush(fp);
  fclose(fp);

  // Save the CRL
  snprintf(fn_buffer, fn_buffer_size, fmt, opengalaxy.settings().certificates_directory.c_str(), opengalaxy.websocket().fmt_crl_cert);
  if(!(fp = fopen(fn_buffer, "wb+"))){
    opengalaxy.syslog().error("%s: could not open crl_cert file", __func__);;
    goto exit;
  }
  if(1 != fwrite(certs.crl_cert, strlen(certs.crl_cert), 1, fp)){
    fclose(fp);
    opengalaxy.syslog().error("%s: could not write crl_cert file", __func__);;
    goto exit;
  }
  fflush(fp);
  fclose(fp);

  // Save the CA public RSA key
  snprintf(fn_buffer, fn_buffer_size, fmt, opengalaxy.settings().certificates_directory.c_str(), opengalaxy.websocket().fmt_verify_key);
  if(!(fp = fopen(fn_buffer, "wb+"))){
    opengalaxy.syslog().error("%s: could not open verify_key file", __func__);;
    goto exit;
  }
  if(1 != fwrite(certs.verify_key, strlen(certs.verify_key), 1, fp)){
    fclose(fp);
    opengalaxy.syslog().error("%s: could not write verify_key file", __func__);;
    goto exit;
  }
  fflush(fp);
  fclose(fp);

  // Save the (client) credentials private RSA key
  snprintf(fn_buffer, fn_buffer_size, fmt, opengalaxy.settings().certificates_directory.c_str(), opengalaxy.websocket().fmt_credentials_key);
  if(!(fp = fopen(fn_buffer, "wb+"))){
    opengalaxy.syslog().error("%s: could not open decrypt_key file", __func__);;
    goto exit;
  }
  if(1 != fwrite(certs.decrypt_key, strlen(certs.decrypt_key), 1, fp)){
    fclose(fp);
    opengalaxy.syslog().error("%s: could not write decrypt_key file", __func__);;
    goto exit;
  }
  fflush(fp);
  fclose(fp);

  // All done, restart the server to deploy the certificates
  opengalaxy.syslog().error("Certificates have been updated, restarting server in 5...10 seconds");
  retv = 1; // success

exit:
  if(certs.ca_cert) thread_safe_free(certs.ca_cert);
  if(certs.server_cert) thread_safe_free(certs.server_cert);
  if(certs.server_key) thread_safe_free(certs.server_key);
  if(certs.crl_cert) thread_safe_free(certs.crl_cert);
  if(certs.verify_key) thread_safe_free(certs.verify_key);
  if(certs.decrypt_key) thread_safe_free(certs.decrypt_key);
  return retv;
}


}


