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

//
// Used to automaticly upload and install the SSL certificates
// needed by the openGalaxy server application.
//

#include <stdio.h>
#include <string.h>
#include "ssl_evp.h"
#include "json.h"

static struct packed_certs_t {
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
} certs;

static const char* fmt_json =
  "{"
  "\"ca_cert\":\"%s\","
  "\"server_cert\":\"%s\","
  "\"server_key\":\"%s\","
  "\"crl_cert\":\"%s\","
  "\"verify_key\":\"%s\","
  "\"decrypt_key\":\"%s\""
  "}";

static const char* fmt_encrypted_json =
  "{"
  "\"mode\":%u,"       // AES Mode: 0=CBC, 1=GCM
  "\"keysize\":%u,"    // AES keysize (in bits)
  "\"mdsize\":%u,"     // SHA2 message digest size (in bits)
  "\"siglen\":%u,"     // Signature length (in bytes, without base64 encoding)
  "\"rsalen\":%u,"     // RSA ciphertext length (in bytes, without base64 encoding)
  "\"aeslen\":%u,"     // AES ciphertext length (in bytes, without base64 encoding)
  "\"sig\":\"%s\","    // Base64 encoded signature
  "\"rsa\":\"%s\","    // Base64 encoded RSA ciphertext
  "\"aes\":\"%s\""     // Base64 encoded AES ciphertext
  "}";

static void free_certs_struct(struct packed_certs_t *c)
{
  if(c->ca_cert){
    memset(c->ca_cert, 0, c->ca_cert_size);
    OPENSSL_free(c->ca_cert);
  }
  if(c->server_cert){
    memset(c->server_cert, 0, c->server_cert_size);
    OPENSSL_free(c->server_cert);
  }
  if(c->server_key){
    memset(c->server_key, 0, c->server_key_size);
    OPENSSL_free(c->server_key);
  }
  if(c->crl_cert){
    memset(c->crl_cert, 0, c->crl_cert_size);
    OPENSSL_free(c->crl_cert);
  }
  if(c->verify_key){
    memset(c->verify_key, 0, c->verify_key_size);
    OPENSSL_free(c->verify_key);
  }
  if(c->decrypt_key){
    memset(c->decrypt_key, 0, c->decrypt_key_size);
    OPENSSL_free(c->decrypt_key);
  }
}

#define READ_FILE(fname,buf,size,erv)\
  {\
    const char* fn = fname;\
    char* file_data;\
    size_t file_size;\
    FILE *fp = fopen(fn, "rb");\
    if(!fp){\
      if(error) *error = "Could not open file";\
      free_certs_struct(&certs);\
      return erv;\
    }\
    fseek(fp, 0, SEEK_END);\
    file_size = ftell(fp);\
    fseek(fp, 0, SEEK_SET);\
    if(!file_size){\
      if(error) *error = "Could not seek file";\
      free_certs_struct(&certs);\
      return erv;\
    }\
    file_data = OPENSSL_malloc(file_size+1);\
    if(!file_data){\
      if(error) *error = "Out of memory";\
      free_certs_struct(&certs);\
      return erv;\
    }\
    file_data[file_size] = '\0';\
    if(1 != fread(file_data, file_size, 1, fp)){\
      if(error) *error = "Could not read file";\
      free_certs_struct(&certs);\
      return erv;\
    }\
    fclose(fp);\
    buf = file_data;\
    size = file_size;\
  }

static char* read_server_certs(
  const char* fn_ca_cert,
  const char* fn_server_cert,
  const char* fn_server_key,
  const char* fn_crl_cert,
  const char* fn_verify_key,
  const char* fn_decrypt_key,
  const char** error
){
  char* json;
  size_t json_size;

  memset(&certs, 0, sizeof(struct packed_certs_t));

  // load all files into the certs struct
  READ_FILE(fn_ca_cert, certs.ca_cert, certs.ca_cert_size, NULL)
  READ_FILE(fn_server_cert, certs.server_cert, certs.server_cert_size, NULL)
  READ_FILE(fn_server_key, certs.server_key, certs.server_key_size, NULL)
  READ_FILE(fn_crl_cert, certs.crl_cert, certs.crl_cert_size, NULL)
  READ_FILE(fn_verify_key, certs.verify_key, certs.verify_key_size, NULL)
  READ_FILE(fn_decrypt_key, certs.decrypt_key, certs.decrypt_key_size, NULL)

  // base64 encode
  char* tmp;
  if(!ssl_base64_encode((unsigned char*)certs.ca_cert, certs.ca_cert_size+1, &tmp, &certs.ca_cert_size)) goto err_b64;
  OPENSSL_free(certs.ca_cert);
  certs.ca_cert = tmp;
  if(!ssl_base64_encode((unsigned char*)certs.server_cert, certs.server_cert_size+1, &tmp, &certs.server_cert_size)) goto err_b64;
  OPENSSL_free(certs.server_cert);
  certs.server_cert = tmp;
  if(!ssl_base64_encode((unsigned char*)certs.server_key, certs.server_key_size+1, &tmp, &certs.server_key_size)) goto err_b64;
  OPENSSL_free(certs.server_key);
  certs.server_key = tmp;
  if(!ssl_base64_encode((unsigned char*)certs.crl_cert, certs.crl_cert_size+1, &tmp, &certs.crl_cert_size)) goto err_b64;
  OPENSSL_free(certs.crl_cert);
  certs.crl_cert = tmp;
  if(!ssl_base64_encode((unsigned char*)certs.verify_key, certs.verify_key_size+1, &tmp, &certs.verify_key_size)) goto err_b64;
  OPENSSL_free(certs.verify_key);
  certs.verify_key = tmp;
  if(!ssl_base64_encode((unsigned char*)certs.decrypt_key, certs.decrypt_key_size+1, &tmp, &certs.decrypt_key_size)) goto err_b64;
  OPENSSL_free(certs.decrypt_key);
  certs.decrypt_key = tmp;

  // format as json string
  json_size =
    strlen(fmt_json) +
    6 * 10 +
    certs.ca_cert_size +
    certs.server_cert_size +
    certs.server_key_size +
    certs.crl_cert_size +
    certs.verify_key_size +
    certs.decrypt_key_size;
  json = OPENSSL_malloc(json_size);
  if(!json){
    if(error) *error = "Out of memory";
    goto error;
  }
  sprintf(
    json, fmt_json,
    certs.ca_cert,
    certs.server_cert,
    certs.server_key,
    certs.crl_cert,
    certs.verify_key,
    certs.decrypt_key
  );

  free_certs_struct(&certs);
  return json;

err_b64:
  if(error) *error = "Failed to base64 encode";
error:
  free_certs_struct(&certs);
  return NULL;
}


char* encrypt_certs_to_JSON(
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
){
  char* json;
  rsa_aes_encrypted_data* encrypted;
  size_t t;
  char *b64sig = NULL, *b64rsa = NULL, *b64aes = NULL;
//  int do_enc = 1;

  if(
    !fn_ca_cert || !fn_server_cert || !fn_server_key ||
    !fn_crl_cert || !fn_verify_key || !fn_decrypt_key
  ){
    if(error) *error = "Missing filename";
    return NULL;
  }
/*
  if(encrypt && (!sign_key || !encrypt_key)){
    if(error) *error = "Missing key(s)";
    return NULL;
  }
*/

  json = read_server_certs(fn_ca_cert, fn_server_cert, fn_server_key, fn_crl_cert, fn_verify_key, fn_decrypt_key, error);
  if(!json){
    return NULL;
  }

  if(encrypt){
    encrypted = rsa_aes_encrypt_and_sign(json, strlen(json) + 1, encrypt_key, sign_key, 256, 512, 0);
    memset(json, 0, strlen(json));
    OPENSSL_free(json);
    if(!encrypted){
      return NULL;
    }
    // - base64 encode the signature and ciphertexts of the resulting
    //   rsa_aes_encrypted_data object.
    if(
      !ssl_base64_encode(encrypted->signature, encrypted->signature_size, &b64sig, &t) ||
      !ssl_base64_encode(encrypted->rsa_ciphertext, encrypted->rsa_ciphertext_size, &b64rsa, &t) ||
      !ssl_base64_encode(encrypted->aes_ciphertext, encrypted->aes_ciphertext_size, &b64aes, &t)
    ){
      if(b64sig) OPENSSL_free(b64sig);
      if(b64rsa) OPENSSL_free(b64rsa);
      if(b64aes) OPENSSL_free(b64aes);
      OPENSSL_free(encrypted->signature);
      OPENSSL_free(encrypted->rsa_ciphertext);
      OPENSSL_free(encrypted->aes_ciphertext);
      OPENSSL_free(encrypted);
      return NULL;
    }
    OPENSSL_free(encrypted->signature);
    OPENSSL_free(encrypted->rsa_ciphertext);
    OPENSSL_free(encrypted->aes_ciphertext);

    // - format the encrypted/base64 encoded rsa_aes_encrypted_data object as
    //   an encrypted_credentials_json_fmt C-string.
    t = strlen(fmt_encrypted_json) +
        strlen(b64sig) +
        strlen(b64rsa) +
        strlen(b64aes) +
        (6 * 10); // Max number of digits for all UINT values
    json = OPENSSL_malloc(t);
    if(!json){
      OPENSSL_free(b64sig);
      OPENSSL_free(b64rsa);
      OPENSSL_free(b64aes);
      OPENSSL_free(encrypted);
      return 0;
    }
    sprintf(
      json,
      fmt_encrypted_json,
      encrypted->aes_mode,
      encrypted->aes_keysize,
      encrypted->md_size,
      encrypted->signature_size,
      encrypted->rsa_ciphertext_size,
      encrypted->aes_ciphertext_size,
      b64sig,
      b64rsa,
      b64aes
    );
    OPENSSL_free(b64sig);
    OPENSSL_free(b64rsa);
    OPENSSL_free(b64aes);
    OPENSSL_free(encrypted);
  }

  return json;
}


