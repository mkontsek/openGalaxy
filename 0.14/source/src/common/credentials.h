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

#ifndef __SSL_EVP_CREDENTIALS_H__
#define __SSL_EVP_CREDENTIALS_H__

#include "atomic.h"
#include "ssl_evp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This struct describes all the credential and privilege data that
 * openGalaxy stores in an SSL certificate.
 */
typedef struct client_credentials_t {
  char *fullname;
  char *login;
  char *password;
} client_credentials;

/*
 * Encrypt user credentials and privileges.
 *
 * sign_key must be an RSA private key
 * encrypt_key must be an RSA public key
 *
 * Returns a C string containing the encrypted user credentials and privileges,
 * or NULL upon an error condition.
 */
char* client_credentials_encrypt(const client_credentials* cred, EVP_PKEY *sign_key, EVP_PKEY *encrypt_key);

/*
 * Decrypt user credentials and privileges
 *
 * verify_key must be an RSA public key
 * decrypt_key must be an RSA private key
 *
 * Returns the decrypted user credentials and privileges,
 * or NULL upon an error condition.
 */
client_credentials* client_credentials_decrypt(const char* data, EVP_PKEY *verify_key, EVP_PKEY *decrypt_key);

#ifdef __cplusplus
}
#endif

#endif

