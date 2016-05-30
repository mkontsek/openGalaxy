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
 * ssl_evp.c/ssl_evp.h:
 * Wrapper/helper functions for some of openssl's high-level cryptographic functions
 * and other usefull utility functions.
 */

#ifndef __SSL_EVP_H__
#define __SSL_EVP_H__

#include "atomic.h"
#ifndef HAVE_NO_SSL

#include <openssl/evp.h>

//#define SSL_EVP_DEBUG 1

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////////////////////////////
// Any pointer created by a ssl_????? function should be freed by these //
// functions:                                                           //
//////////////////////////////////////////////////////////////////////////

void ssl_free(void *p);              // calls OPENSSL_free
void ssl_pkey_free(EVP_PKEY *pkey);  // calls EVP_PKEY_free

//////////////////////////////////////////////////////////////////////////
//                     Base64 encoding/decoding                         //
//////////////////////////////////////////////////////////////////////////

// Base64 encode
// returns 1 on success, 0 otherwise.
int ssl_base64_encode(const unsigned char* in, size_t in_len, char**out, size_t *out_len);

// Base64 decode
// returns 1 on success, 0 otherwise.
int ssl_base64_decode(const char* in, size_t in_len, unsigned char** out, size_t* out_len);

//////////////////////////////////////////////////////////////////////////
//                         Random numbers                               //
//////////////////////////////////////////////////////////////////////////

// Generate a buffer filled with 'encryption grade' random data.
// returns 1 on success, 0 otherwise.
int ssl_rand_bytes(unsigned char *buf, int num);

// Generate a buffer filled with pseudo random data.
// returns 1 on success, 0 otherwise.
int ssl_rand_pseudo_bytes(unsigned char *buf, int num);

//////////////////////////////////////////////////////////////////////////
//           RSA Public/Private key encryption/decryption               //
//////////////////////////////////////////////////////////////////////////

// Load a PEM formatted public/private RSA key from file 'fn'.
//
// 'pkey' is only valid upon success and should be freed
// with ssl_pkey_free().
//
// !!! Make sure you have called OpenSSL_add_all_algorithms() !!!
// !!!   before loading a passphrase protected private key    !!!
//
// Both functions return 1 on success, 0 otherwise.
int ssl_evp_rsa_load_public_key(const char *fn, EVP_PKEY** pkey);
int ssl_evp_rsa_load_private_key(const char *fn, EVP_PKEY** pkey, int(*pass_cb)(char*,int,int,void*), void *user);

// Encrypt/decrypt a buffer using the given RSA key.
//
// The maximum 'in_len' depends on the key size, and is
// calculated with the formula: ((RSA key size) / 8) - 42
//
// 'out' and 'out_len' are only valid upon success and
// 'out' should be freed with ssl_free()
//
// Both functions return 1 on success, 0 otherwise.
int ssl_evp_rsa_encrypt(unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len, EVP_PKEY *public_key);
int ssl_evp_rsa_decrypt(unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len, EVP_PKEY *private_key);

//////////////////////////////////////////////////////////////////////////
//           Rijndael (AES) encryption/decryption functions for         //
//                CBC (Cipher Block Chaining) Mode and                  //
//                     GCM (Galois/Counter) Mode.                       //
//////////////////////////////////////////////////////////////////////////

// Generate a 128, 192 or 256 bit key for AES encryption.
// returns the key on success, NULL otherwise.
unsigned char* ssl_aes_key(int size);

// Generate a 128bit iv.
// returns the iv on success, NULL otherwise.
unsigned char* ssl_aes_initial_vector(void);

// Encrypt/decrypt a buffer with AES in CBC or GCM Mode.
//
// 'mode' 0=CBC 1=GCM
// 'type' must be one of:
//    EVP_aes_128_cbc(), EVP_aes_192_cbc(), EVP_aes_256_cbc()
//    EVP_aes_128_gcm(), EVP_aes_192_gcm() or EVP_aes_256_gcm().
// 'key' and 'iv' must be initialized and suitable for the requested AES key size.
// 'out' and 'out_len' are only valid upon success and
// 'out' should be freed with ssl_free()
//
// Both functions return 1 on success, 0 otherwise.
int ssl_evp_aes_encrypt(int mode, const EVP_CIPHER *type, unsigned char *key, unsigned char *iv, unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len);
int ssl_evp_aes_decrypt(int mode, const EVP_CIPHER *type, unsigned char *key, unsigned char *iv, unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len);

//////////////////////////////////////////////////////////////////////////
//                       Message digest functions                       //
//////////////////////////////////////////////////////////////////////////

// Create a hash for a message.
//
// 'md' must be one of: EVP_sha224(), EVP_sha256(),
//                      EVP_sha384() or EVP_sha512().
// 'digest' and 'digest_len' are only valid upon success and
// 'digest' should be freed with ssl_free()
//
// returns 1 on success, 0 otherwise.
int ssl_evp_md_create(const EVP_MD* md, unsigned char *msg, size_t msg_len, unsigned char **digest, unsigned int *digest_len);

// Compare two Message Digests
//
// Return value:
//  <0 : the first byte that does not match in both signatures has a lower
//       value in sig1 than in sig2 (if evaluated as unsigned char values)
//  0  : the contents of both memory blocks are equal
//  >0 : the first byte that does not match in both signatures has a greater
//       value in sig1 than in sig2 (if evaluated as unsigned char values)
//
// See: CRYPTO_memcmp()
int ssl_evp_md_compare(unsigned char *sig1, unsigned char *sig2, size_t sig_size);

//////////////////////////////////////////////////////////////////////////
//                    Signing and Verifying functions                   //
//////////////////////////////////////////////////////////////////////////

// Sign/verify a message using Message Digest 'md' and the provided
// RSA private/public key.
//
// 'md' must be one of: EVP_sha224(), EVP_sha256(),
//                      EVP_sha384() or EVP_sha512().
// For signing, 'signature' and 'signature_len' are only valid upon success and
// 'signature' should be freed with ssl_free()
//
// returns 1 on success, 0 otherwise.
int ssl_evp_rsa_sign(const EVP_MD* md, unsigned char* in, size_t in_len, unsigned char** signature, size_t* signature_len, EVP_PKEY* private_key);
int ssl_evp_rsa_verify(const EVP_MD* md, unsigned char* in, size_t in_len, unsigned char* signature, size_t signature_len, EVP_PKEY* public_key);

//////////////////////////////////////////////////////////////////////////
//        Helper functions to encrypt/decrypt a block of memory         //
//////////////////////////////////////////////////////////////////////////

// struct rsa_aes_encrypted_data
//
// Data that was encrypted with an RSA public key + AES in CBC or GCM mode,
// then signed with an RSA private key.
//
// The signature was made over both RSA and AES ciphertexts.
// After decryption the RSA plaintext contains the AES key, the initial
// vector and an SHA2 message digest for the AES ciphertext.
//
typedef struct rsa_aes_encrypted_data_t {
  int aes_mode;    // 0=CBC or 1=GCM
  int aes_keysize; // 128, 192 or 256
  int md_size;     // 224, 256, 384 or 512

  size_t signature_size; // in bytes
  size_t rsa_ciphertext_size; // in bytes
  size_t aes_ciphertext_size; // in bytes

  // The RSA-SHA2 signature for the (combined) ciphertext
  unsigned char* signature;

  // The ciphertext
  unsigned char* rsa_ciphertext;
  unsigned char* aes_ciphertext;
} rsa_aes_encrypted_data;

// Encrypt and sign a block of memory using RSA, AES and SHA2
//
// The data is first encrypted with AES, then the AES key, iv and
// the SHA2 message digest are encrypted using RSA.
// Afterwards the entire ciphertext is signed using RSA and SHA2.
//
// rsa_aes_encrypted_data*
// rsa_aes_encrypt_and_sign(
//   void* plaintext        : the data to encrypt
//   size_t plaintext_size  : size (in bytes) of the data to encrypt
//   EVP_PKEY* encrypt_key  : the (public) RSA key used to encrypt the credentials
//   EVP_PKEY* sign_key     : the (private) RSA key used to sign the encrypted data
//   int aes_keysize        : the size of the AES key in bits (128, 192, 256)
//   int md_size            : the size of the SHA2 message digest (224, 256, 284, 512)
//   int aes_mode           : 0 = CBC Mode, 1 = GCM Mode
// )
//
// Returns a pointer to the encrypted data structure on success, NULL otherwise.
rsa_aes_encrypted_data* rsa_aes_encrypt_and_sign(void *plaintext, size_t plaintext_size, EVP_PKEY *encrypt_key, EVP_PKEY *sign_key, int aes_keysize, int md_size, int aes_mode);

// Verify and decrypt a block of memory using RSA, AES and SHA2
//
// rsa_aes_verify_and_decrypt(
//   rsa_aes_encrypted_data* in,  : the data to decrypt
//   void** plaintext,            : pointer to the decrypted plaintext
//   size_t* plaintext_size,      : pointer to the size (in bytes) of the decrypted plaintext
//   ENV_PKEY* verify_key,        : the (public) RSA key used to verify the signature
//   EVP_PKEY* decrypt_key        : the (private) RSA key used to decrypt the ciphertext
// )
//
// returns 1 on success, 0 otherwise.
int rsa_aes_verify_and_decrypt(rsa_aes_encrypted_data* in, void **plaintext, size_t *plaintext_size, EVP_PKEY *verify_key, EVP_PKEY *decrypt_key);

//////////////////////////////////////////////////////////////////////////
//                       some other handy stuff                         //
//////////////////////////////////////////////////////////////////////////

// Encodes a BIGNUM as a hexadecimal C-string
void ssl_hex_encode(unsigned char* readbuf, void *writebuf, size_t len);

// SHA256 fingerprint length in bytes
#define SSL_SHA256LEN 32

// Calculate the SHA-256 fingerprint for the given certificate
// returns the fingerprint as a C string, or NULL otherwise
char* ssl_calculate_sha256_fingerprint(X509 *x509);

// Convert a date in ASN1 format to a C-string
// returns 0 on success, or 1 otherwise
int ssl_convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif

#endif

