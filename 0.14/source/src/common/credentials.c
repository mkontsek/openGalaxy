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
 * Functions to encode/decode user credentials and privileges
 * into a format we can safely insert into an SSL client certificate.
 *
 * openGalaxy uses client SSL certificates to both authenticate a
 * connecting client and to store user credentials and privileges associated
 * with that client.
 *
 * OpenSSL takes care of the authentication of a client certificate but has no
 * knowledge on how to store/extract user credentials and privileges in/from a
 * certificate.
 *
 * To store credentials and privileges inside a certificate openGalaxy uses
 * the 'SAN otherName' facility of the SSL certificates to embed a base64
 * encoded JSON object containing that client's user credentials and privileges.
 *
 * The data inside the JSON object has been encrypted using a combination
 * of both RSA and AES together with an RSA signature and an
 * SHA2 message digest.
 *
 * The signature is used to verify that openGalaxy is the creator of the
 * object and the SHA2 hash is used to make sure the data is authentic.
 */

#include "atomic.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ssl_evp.h"
#include "credentials.h"
#include "json.h"

// Number of digits in an 'unsigned int'
// If your 'unsigned int' is not 32bit you may need to change this
#define UINT_MAX_DIGITS ((10 * sizeof(char)))

/*
 * This is the format of the plaintext stored in an
 * encrypted_credentials_json_fmt formatted JSON object.
 */
static const char* credentials_json_fmt =
  "{"
  "\"fullname\":\"%s\","  // Base64 encoded user fullname
  "\"login\":\"%s\","     // Base64 encoded user login name
  "\"password\":\"%s\""   // Base64 encoded user password
  "}";

/*
 * This is the format of the ciphertext as stored in the certificate.
 */
static const char* encrypted_credentials_json_fmt =
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

/*
 * Encrypt user credentials and privileges.
 *
 * sign_key must be an RSA private key
 * encrypt_key must be an RSA public key
 *
 * Returns a C string containing the encrypted user credentials and privileges,
 * or NULL upon an error condition.
 */
char* client_credentials_encrypt(const client_credentials* cred, EVP_PKEY *sign_key, EVP_PKEY *encrypt_key)
{
  size_t ignored_size;
  unsigned char* plaintext;
  rsa_aes_encrypted_data* encrypted;
  char *encrypted_json;
  char *b64sig = NULL, *b64rsa = NULL, *b64aes = NULL;
  client_credentials *c;
  char *b64out;

  // (make sure not to modify 'cred')
  c = OPENSSL_malloc(sizeof(struct client_credentials_t));
  if(!cred || !encrypt_key || !sign_key || !c){
    if(c) OPENSSL_free(c);
    return NULL;
  }
  // (copy non-string members)
  memcpy(c, cred, sizeof(struct client_credentials_t));

  // - base64 encode all string members of 'cred'.
  c->fullname = NULL;
  c->login = NULL;
  c->password = NULL;
  if(
    !ssl_base64_encode((unsigned char*)cred->fullname, strlen(cred->fullname)+1, &c->fullname, &ignored_size) ||
    !ssl_base64_encode((unsigned char*)cred->login, strlen(cred->login)+1, &c->login, &ignored_size) ||
    !ssl_base64_encode((unsigned char*)cred->password, strlen(cred->password)+1, &c->password, &ignored_size)
  ){
    if(c->fullname) OPENSSL_free(c->fullname);
    if(c->login) OPENSSL_free(c->login);
    if(c->password) OPENSSL_free(c->password);
    OPENSSL_free(c);
    return NULL;
  }

  // - format a new credentials_json_fmt C-string with the members of 'cred'.
  plaintext = OPENSSL_malloc(
    strlen(credentials_json_fmt) +
    strlen(c->fullname) +
    strlen(c->login) +
    strlen(c->password) +
    1 // 0 byte
  );
  if(!plaintext){
    OPENSSL_free(c->fullname);
    OPENSSL_free(c->login);
    OPENSSL_free(c->password);
    OPENSSL_free(c);
    return NULL;
  }
  sprintf((char*)plaintext, credentials_json_fmt,
    c->fullname,
    c->login,
    c->password
  );
  memset(c->fullname, 0, strlen(c->fullname));
  memset(c->login, 0, strlen(c->login));
  memset(c->password, 0, strlen(c->password));
  OPENSSL_free(c->fullname);
  OPENSSL_free(c->login);
  OPENSSL_free(c->password);
  memset(c, 0, sizeof(struct client_credentials_t));
  OPENSSL_free(c);

  // - encrypt the formatted credentials_json_fmt C-string with
  //   RSA_WITH_AES_256_CBC_SHA512 and then sign it with openGalaxy's CA key
  //
  encrypted = rsa_aes_encrypt_and_sign(plaintext, strlen((char*)plaintext)+1, encrypt_key, sign_key, 256, 512, 0);

  // (destroy all temporary plaintext)
  memset(plaintext, 0, strlen((char*)plaintext));
  OPENSSL_free(plaintext);

  // (test if encryption was successfull)
  if(!encrypted) return NULL;

  // - base64 encode the signature and ciphertexts of the resulting
  //   rsa_aes_encrypted_data object.
  if(
    !ssl_base64_encode(encrypted->signature, encrypted->signature_size, &b64sig, &ignored_size) ||
    !ssl_base64_encode(encrypted->rsa_ciphertext, encrypted->rsa_ciphertext_size, &b64rsa, &ignored_size) ||
    !ssl_base64_encode(encrypted->aes_ciphertext, encrypted->aes_ciphertext_size, &b64aes, &ignored_size)
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
  encrypted_json = OPENSSL_malloc(
    strlen(encrypted_credentials_json_fmt) +
    strlen(b64sig) +
    strlen(b64rsa) +
    strlen(b64aes) +
    (6 * UINT_MAX_DIGITS) // Max number of digits for all UINT values
  );
  if(!encrypted_json){
    OPENSSL_free(b64sig);
    OPENSSL_free(b64rsa);
    OPENSSL_free(b64aes);
    OPENSSL_free(encrypted);
    return NULL;
  }
  sprintf(
    encrypted_json,
    encrypted_credentials_json_fmt,
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

  // final base64 encode
  if(!ssl_base64_encode((unsigned char*)encrypted_json, strlen(encrypted_json)+1, &b64out, &ignored_size)){
    OPENSSL_free(encrypted_json);
    return NULL;
  }
  OPENSSL_free(encrypted_json);

  // - return the resulting C string.
  return b64out;
}

/*
 * Decrypt user credentials and privileges
 *
 * verify_key must be an RSA public key
 * decrypt_key must be an RSA private key
 *
 * Returns the decrypted user credentials and privileges,
 * or NULL upon an error condition.
 */
client_credentials* client_credentials_decrypt(const char* data, EVP_PKEY *verify_key, EVP_PKEY *decrypt_key)
{
  size_t ignored_size;
  rsa_aes_encrypted_data *encrypted;
  char *b64sig = NULL, *b64rsa = NULL, *b64aes = NULL;
  char *plaintext;
  client_credentials *out;
  json_item *i;
  json_object *o;
  char *json;

  encrypted = OPENSSL_malloc(sizeof(struct rsa_aes_encrypted_data_t));
  if(!encrypted) return NULL;
  memset(encrypted, 0, sizeof(struct rsa_aes_encrypted_data_t));

  // first base64 decode the data
  if(!ssl_base64_decode(data, strlen(data), (unsigned char **)&json, &ignored_size)){
    OPENSSL_free(encrypted);
#ifdef SSL_EVP_DEBUG
    printf("%s: Could not base64 decode...\n", "client_credentials_decrypt");
#endif
    return NULL;
  }

  // - decode the JSON object to a new rsa_aes_encrypted_data object.
  o = json_parse_objects(json);
  if(!o) return NULL;
#ifdef SSL_EVP_DEBUG
  json_print_objects(o);
#endif
  i = o->items;
  while( i != NULL ){
    if( i->data != NULL ){
      switch( i->data->type ){

        case json_string_value:
          if( strcmp( i->name->value, "sig" ) == 0 ){
            b64sig = OPENSSL_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "rsa" ) == 0 ){
            b64rsa = OPENSSL_strdup( i->data->content.string->value );
          }
          else if( strcmp( i->name->value, "aes" ) == 0 ){
            b64aes = OPENSSL_strdup( i->data->content.string->value );
          }
          else {
            if(b64sig) OPENSSL_free(b64sig);
            if(b64rsa) OPENSSL_free(b64rsa);
            if(b64aes) OPENSSL_free(b64aes);
            json_free_objects( o );
#ifdef SSL_EVP_DEBUG
            printf("%s: Bad JSON string value\n", "client_credentials_decrypt");
#endif
            return NULL;
          }
          break;

        case json_number_value:
          if( strcmp( i->name->value, "mode" ) == 0 ){
            encrypted->aes_mode = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "keysize" ) == 0 ){
            encrypted->aes_keysize = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "mdsize" ) == 0 ){
            encrypted->md_size = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "siglen" ) == 0 ){
            encrypted->signature_size = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "rsalen" ) == 0 ){
            encrypted->rsa_ciphertext_size = i->data->content.number->value;
          }
          else if( strcmp( i->name->value, "aeslen" ) == 0 ){
            encrypted->aes_ciphertext_size = i->data->content.number->value;
          }
          else {
            if(b64sig) OPENSSL_free(b64sig);
            if(b64rsa) OPENSSL_free(b64rsa);
            if(b64aes) OPENSSL_free(b64aes);
            json_free_objects( o );
#ifdef SSL_EVP_DEBUG
            printf("%s: Bad JSON number value\n", "client_credentials_decrypt");
#endif
            return NULL;
          }
          break;

        default:
          if(b64sig) OPENSSL_free(b64sig);
          if(b64rsa) OPENSSL_free(b64rsa);
          if(b64aes) OPENSSL_free(b64aes);
          json_free_objects( o );
#ifdef SSL_EVP_DEBUG
          printf("%s: Bad JSON value type\n", "client_credentials_decrypt");
#endif
          return NULL;
      }
      i = i->next;
    }
  }
  json_free_objects(o);
  if(
    !b64sig || !b64rsa || !b64aes ||
    !((encrypted->aes_mode == 0) || (encrypted->aes_mode == 1)) ||
    !encrypted->aes_keysize ||
    !encrypted->md_size ||
    !encrypted->signature_size ||
    !encrypted->rsa_ciphertext_size ||
    !encrypted->aes_ciphertext_size
  ){
    if(b64sig) OPENSSL_free(b64sig);
    if(b64rsa) OPENSSL_free(b64rsa);
    if(b64aes) OPENSSL_free(b64aes);
#ifdef SSL_EVP_DEBUG
    printf("%s: \n", "client_credentials_decrypt");
    printf("encrypted->aes_mode            %u\n", encrypted->aes_mode);
    printf("encrypted->aes_keysize         %u\n", encrypted->aes_keysize);
    printf("encrypted->md_size             %u\n", encrypted->md_size);
    printf("encrypted->signature_size      %u\n", encrypted->signature_size);
    printf("encrypted->rsa_ciphertext_size %u\n", encrypted->rsa_ciphertext_size);
    printf("encrypted->aes_ciphertext_size %u\n", encrypted->aes_ciphertext_size);
    printf("b64sig = %p\n", b64sig);
    printf("b64rsa = %p\n", b64rsa);
    printf("b64aes = %p\n", b64aes);
#endif
    return NULL;
  }
#ifdef SSL_EVP_DEBUG
  printf("%s: \n", "client_credentials_decrypt");
  printf("encrypted->aes_mode            %u\n", encrypted->aes_mode);
  printf("encrypted->aes_keysize         %u\n", encrypted->aes_keysize);
  printf("encrypted->md_size             %u\n", encrypted->md_size);
  printf("encrypted->signature_size      %u\n", encrypted->signature_size);
  printf("encrypted->rsa_ciphertext_size %u\n", encrypted->rsa_ciphertext_size);
  printf("encrypted->aes_ciphertext_size %u\n", encrypted->aes_ciphertext_size);
  printf("b64sig = %s\n", b64sig);
  printf("b64rsa = %s\n", b64rsa);
  printf("b64aes = %s\n", b64aes);
#endif

  // - base64 decode the ciphertexts in the rsa_aes_encrypted_data object.
  if(
    !ssl_base64_decode(b64sig, strlen(b64sig), &encrypted->signature, &ignored_size) ||
    !ssl_base64_decode(b64rsa, strlen(b64rsa), &encrypted->rsa_ciphertext, &ignored_size) ||
    !ssl_base64_decode(b64aes, strlen(b64aes), &encrypted->aes_ciphertext, &ignored_size)
  ){
    if(encrypted->signature) OPENSSL_free(encrypted->signature);
    if(encrypted->rsa_ciphertext) OPENSSL_free(encrypted->rsa_ciphertext);
    if(encrypted->aes_ciphertext) OPENSSL_free(encrypted->aes_ciphertext);
    OPENSSL_free(b64sig);
    OPENSSL_free(b64rsa);
    OPENSSL_free(b64aes);
#ifdef SSL_EVP_DEBUG
    printf("%s: Failed to base64 decode the ciphertext...\n", "client_credentials_decrypt");
#endif
    return NULL;
  }
  OPENSSL_free(b64sig);
  OPENSSL_free(b64rsa);
  OPENSSL_free(b64aes);

  // - verify/decrypt the rsa_aes_encrypted_data object.
  if(!rsa_aes_verify_and_decrypt(encrypted, (void**)&plaintext, &ignored_size, verify_key, decrypt_key)){
    OPENSSL_free(encrypted->signature);
    OPENSSL_free(encrypted->rsa_ciphertext);
    OPENSSL_free(encrypted->aes_ciphertext);
#ifdef SSL_EVP_DEBUG
    printf("%s: Failed to verify or decrypt...\n", "client_credentials_decrypt");
#endif
    return NULL;
  }
  OPENSSL_free(encrypted->signature);
  OPENSSL_free(encrypted->rsa_ciphertext);
  OPENSSL_free(encrypted->aes_ciphertext);
  OPENSSL_free(encrypted);

  // - decode the resulting JSON object to a new client_credentials object.
  out = OPENSSL_malloc(sizeof(struct client_credentials_t));
  o = json_parse_objects(plaintext);
  if(!out || !o){
    OPENSSL_free(plaintext);
#ifdef SSL_EVP_DEBUG
    printf("%s: ENOMEM\n", "client_credentials_decrypt");
#endif
    return NULL;
  }
#ifdef SSL_EVP_DEBUG
  json_print_objects(o);
#endif
  memset(out, 0, sizeof(struct client_credentials_t));
  i = o->items;
  while( i != NULL ){
    if( i->data != NULL ){
      switch( i->data->type ){

        case json_string_value:
          if(strcmp(i->name->value, "fullname") == 0){
            out->fullname = OPENSSL_strdup(i->data->content.string->value);
          }
          else if(strcmp(i->name->value, "login") == 0){
            out->login = OPENSSL_strdup(i->data->content.string->value);
          }
          else if(strcmp(i->name->value, "password") == 0){
            out->password = OPENSSL_strdup(i->data->content.string->value);
          }
          else {
            if(out->fullname) OPENSSL_free(out->fullname);
            if(out->login) OPENSSL_free(out->login);
            if(out->password) OPENSSL_free(out->password);
            OPENSSL_free(out);
            OPENSSL_free(plaintext);
            json_free_objects( o );
            return NULL;
          }
          break;

        default:
          if(out->fullname) OPENSSL_free(out->fullname);
          if(out->login) OPENSSL_free(out->login);
          if(out->password) OPENSSL_free(out->password);
          OPENSSL_free(out);
          OPENSSL_free(plaintext);
          json_free_objects( o );
          return NULL;
      }
      i = i->next;
    }
  }
  json_free_objects(o);
  OPENSSL_free(plaintext);
  if(
    !out->fullname || !out->login || !out->password
  ){
    if(out->fullname) OPENSSL_free(out->fullname);
    if(out->login) OPENSSL_free(out->login);
    if(out->password) OPENSSL_free(out->password);
    OPENSSL_free(out);
    return NULL;
  }

  // - base64 decode the string members of the client_credentials object.
  if(!ssl_base64_decode(out->fullname, strlen(out->fullname), (unsigned char**)&plaintext, &ignored_size)){
    OPENSSL_free(out->fullname);
    OPENSSL_free(out->login);
    OPENSSL_free(out->password);
    OPENSSL_free(out);
    return NULL;
  }
  OPENSSL_free(out->fullname);
  out->fullname = plaintext;

  if(!ssl_base64_decode(out->login, strlen(out->login), (unsigned char**)&plaintext, &ignored_size)){
    OPENSSL_free(out->fullname);
    OPENSSL_free(out->login);
    OPENSSL_free(out->password);
    OPENSSL_free(out);
    return NULL;
  }
  OPENSSL_free(out->login);
  out->login = plaintext;

  if(!ssl_base64_decode(out->password, strlen(out->password), (unsigned char**)&plaintext, &ignored_size)){
    OPENSSL_free(out->fullname);
    OPENSSL_free(out->login);
    OPENSSL_free(out->password);
    OPENSSL_free(out);
    return NULL;
  }
  OPENSSL_free(out->password);
  out->password = plaintext;

  // - Return the resulting client_credentials object.
  return out;
}


