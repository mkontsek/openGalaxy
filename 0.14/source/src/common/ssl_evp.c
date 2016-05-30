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
 * Wrapper functions for some of openssl's high-level cryptographic functions
 * and other usefull utility functions.
 */

#include "atomic.h"
#ifndef HAVE_NO_SSL

#include <stdlib.h>
#include <stdio.h>

#ifdef __linux__
#include <errno.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/types.h>
#endif

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "ssl_evp.h"

//#ifdef SSL_EVP_DEBUG
//    printf("%s: \n", __func__);
//#endif

//
// Any pointer created by a ssl_* function should be freed by these
// functions
//

void ssl_free(void *p)
{
  if(p) OPENSSL_free(p);
}

void ssl_pkey_free(EVP_PKEY *pkey)
{
  if(pkey) EVP_PKEY_free(pkey);
}

//
// Base64 encoding/decoding
//

int ssl_base64_encode(const unsigned char* in, size_t in_len, char**out, size_t *out_len)
{
  BIO *b64;
  BIO *mem;
  BUF_MEM *ptr;

  // sanity check input
  if(!in || !in_len || !out || !out_len) return 0;

  // setup BIO's
  b64 = BIO_new(BIO_f_base64());
  mem = BIO_new(BIO_s_mem());
  if(!b64 || !mem){
    if(b64) BIO_free_all(b64);
    if(mem) BIO_free_all(mem);
    return 0;
  }
  mem = BIO_push(b64, mem);
  BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value" 
  (void)BIO_set_close(mem, BIO_CLOSE); // allways returns 1
#pragma GCC diagnostic pop 

  // encode the input
  if(in_len != BIO_write(mem, in, in_len)){
    BIO_free_all(mem);
    return 0;
  }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
  (void)BIO_flush(mem); // not a blocking BIO, safe to ignore
#pragma GCC diagnostic pop 

  // copy encoded output to a memory block
  BIO_get_mem_ptr(mem, &ptr);
  *out_len = ptr->length;
  *out = OPENSSL_malloc(((*out_len) + 1) * sizeof(char));
  if(!*out){
    BIO_free_all(mem);
    return 0;
  }
  memcpy(*out, ptr->data, *out_len);

  // properly terminate the C string
  *(*out + (*out_len * sizeof(char))) = 0;

  // cleanup and report success to caller
  BIO_free_all(mem);
  return 1;
}

int ssl_base64_decode(const char* in, size_t in_len, unsigned char** out, size_t* out_len)
{
  BIO *b64;
  BIO *mem;

  // sanity check input
  if(!in || !in_len || !out || !out_len) return 0;

  // setup BIO's
  b64 = BIO_new(BIO_f_base64());
  mem = BIO_new_mem_buf((void *)in, in_len);
  if(!b64 || !mem){
    if(b64) BIO_free_all(b64);
    if(mem) BIO_free_all(mem);
    return 0;
  }
  mem = BIO_push(b64, mem);
  BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value" 
  (void)BIO_set_close(mem, BIO_CLOSE); // allways returns 1
#pragma GCC diagnostic pop 

  // allocate output buffer
  *out = OPENSSL_malloc(in_len * sizeof(unsigned char));

  // decode input
  if((*out_len = BIO_read(mem, *out, in_len)) < 1){
    BIO_free_all(mem);
    return 0;
  }

  // shrink output to fit the reduced size
  *out = OPENSSL_realloc((void *)*out, *out_len * sizeof(unsigned char));

  // cleanup and report success to caller
  BIO_free_all(mem);
  return 1;
}

//
// Random numbers
//

static void ssl_rand_init(void)
{
  // prepare some semi random data
  struct {
#ifdef __linux__
    struct utsname uname;
    int uname_1;
    int uname_2;
    uid_t uid;
    uid_t euid;
    gid_t gid;
    gid_t egid;
#endif
    pid_t pid;
    time_t time;
    void *stack;
  } data;
#ifdef __linux__
  data.uname_1 = uname(&data.uname);
  data.uname_2 = errno;
  data.uid = getuid();
  data.euid = geteuid();
  data.gid = getgid();
  data.egid = getegid();
#endif
  data.pid = getpid();
  data.time = time(NULL);
  data.stack = (void*)&data;

  // And use it to seed the random number generator
  RAND_seed((const void*)&data, sizeof(data));
}

static int rng_is_init = 0;

int ssl_rand_bytes(unsigned char *buf, int num)
{
  if(!rng_is_init){
    ssl_rand_init();
    rng_is_init = 1;
  }

  return RAND_bytes(buf, num);
}

int ssl_rand_pseudo_bytes(unsigned char *buf, int num)
{
  if(!rng_is_init){
    ssl_rand_init();
    rng_is_init = 1;
  }

  return RAND_pseudo_bytes(buf, num);
}

//
// RSA Public/Private key encryption/decryption
//

int ssl_evp_rsa_load_public_key(const char *fn, EVP_PKEY** pkey)
{
  int retv = 1;
  FILE *fp = NULL;
  if(pkey) *pkey = NULL;
  if(
    !pkey || !fn ||
    !(fp = fopen(fn, "rt")) ||
    !(*pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL))
  ) retv = 0;
  if(fp) fclose(fp);
  return retv;
}

int ssl_evp_rsa_load_private_key(const char *fn, EVP_PKEY** pkey, int(*pass_cb)(char*,int,int,void*), void* user)
{
  int retv = 1;
  FILE *fp = NULL;
  if(pkey) *pkey = NULL;
  if(
    !pkey || !fn ||
    !(fp = fopen(fn, "rt")) ||
    !(*pkey = PEM_read_PrivateKey(fp, NULL, pass_cb, user))
  ) retv = 0;
  if(fp) fclose(fp);
  return retv;
}

int ssl_evp_rsa_encrypt(unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len, EVP_PKEY *public_key)
{
  int retv = 1;
  EVP_PKEY_CTX *ctx = NULL;
  if(out) *out = NULL;
  if(
    !in || !in_len || !out || !out_len || !public_key ||
    !(ctx = EVP_PKEY_CTX_new(public_key, NULL)) ||
    (EVP_PKEY_encrypt_init(ctx) <= 0) ||
    (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) ||
    (EVP_PKEY_encrypt(ctx, NULL, out_len, in, in_len) <= 0) ||
    !(*out = (unsigned char*)OPENSSL_malloc(*out_len)) ||
    (EVP_PKEY_encrypt(ctx, *out, out_len, in, in_len) <= 0)
  ){
    if(out && *out){
      OPENSSL_free(*out);
      *out = NULL;
    }
    if(out_len) *out_len = 0;
    retv = 0;
  }
  if(ctx) EVP_PKEY_CTX_free(ctx);
  return retv;
}

int ssl_evp_rsa_decrypt(unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len, EVP_PKEY *private_key)
{
  int retv = 1;
  EVP_PKEY_CTX *ctx = NULL;
  if(out) *out = NULL;
  if(
    !in || !in_len || !out || !out_len || !private_key ||
    !(ctx = EVP_PKEY_CTX_new(private_key, NULL)) ||
    (EVP_PKEY_decrypt_init(ctx) <= 0) ||
    (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) ||
    (EVP_PKEY_decrypt(ctx, NULL, out_len, in, in_len) <= 0) ||
    !(*out = (unsigned char*)OPENSSL_malloc(*out_len)) ||
    (EVP_PKEY_decrypt(ctx, *out, out_len, in, in_len) <= 0)
  ){
    if(out && *out){
      OPENSSL_free(*out);
      *out = NULL;
    }
    if(out_len) *out_len = 0;
    retv = 0;
  }
  if(ctx) EVP_PKEY_CTX_free(ctx);
  return retv;
}

//
// Rijndael (AES) encryption/decryption functions for
// CBC (Cipher Block Chaining) Mode and
// GCM (Galois/Counter) Mode.
//

unsigned char* ssl_aes_key(int size)
{
  unsigned char *aes_key;
  if((size != 128) && (size != 192) && (size != 256)) return NULL;
  aes_key = OPENSSL_malloc(size>>3);
  if(aes_key){
    if (!ssl_rand_bytes(aes_key, size>>3)){
      memset(aes_key, 0, size>>3);
      OPENSSL_free(aes_key);
      return NULL;
    }
    return aes_key;
  }
  return NULL;
}

unsigned char* ssl_aes_initial_vector(void)
{
  unsigned char *aes_iv = OPENSSL_malloc(128/8);
  if(aes_iv){
    if(!ssl_rand_bytes(aes_iv, 128/8)){
      memset(aes_iv, 0, 128/8);
      OPENSSL_free(aes_iv);
      return NULL;
    }
    return aes_iv;
  }
  return NULL;
}

static int ssl_evp_aes_cbc_encrypt(
  const EVP_CIPHER *evp_type,
  unsigned char *key, unsigned char *iv,
  unsigned char *in, size_t in_len,
  unsigned char **out, size_t *out_len
)
{
  int retv = 1;
  int len, len_final;
  EVP_CIPHER_CTX *ctx;

  ctx = EVP_CIPHER_CTX_new();
  *out_len = ((in_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  *out = OPENSSL_malloc(*out_len);
  if(
    !ctx || !*out ||
    (1 != EVP_EncryptInit_ex(ctx, evp_type, NULL, key, iv)) ||
    (1 != EVP_EncryptUpdate(ctx, *out, &len, in, in_len)) ||
    (1 != EVP_EncryptFinal_ex(ctx, *out + len, &len_final))
  ){
    if(*out){
      OPENSSL_free(*out);
      *out = NULL;
    }
    *out_len = 0;
    retv = 0;
  }
  else {
    *out_len = len + len_final;
  }
  if(ctx) EVP_CIPHER_CTX_free(ctx);

  return retv;
}

#define GCM_TAG_SIZE 16
#define GCM_TAG "0000000000000000"
#define GCM_IV_SIZE 12
#define GCM_AAD_SIZE 4
#define GCM_AAD "0000"

static int ssl_evp_aes_gcm_encrypt(
  const EVP_CIPHER *evp_type,
  unsigned char *key, unsigned char *iv,
  unsigned char *in, size_t in_len,
  unsigned char **out, size_t *out_len
)
{
  int retv = 1;
  int len, len_final;
  EVP_CIPHER_CTX *ctx;

  ctx = EVP_CIPHER_CTX_new();
  *out_len = ((in_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  *out = OPENSSL_malloc(*out_len);
  if(
    !ctx || !*out ||
    (1 != EVP_EncryptInit_ex(ctx, evp_type, NULL, NULL, NULL)) ||
    (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL)) ||
    (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) ||
    (1 != EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char*)GCM_AAD, GCM_AAD_SIZE)) ||
    (1 != EVP_EncryptUpdate(ctx, *out, &len, in, in_len)) ||
    (1 != EVP_EncryptFinal_ex(ctx, *out + len, &len_final)) ||
    (1 != EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, *out + len))
  ){
    if(*out){
      OPENSSL_free(*out);
      *out = NULL;
    }
    *out_len = 0;
    retv = 0;
  }
  else {
    *out_len = len + len_final;
  }
  if(ctx) EVP_CIPHER_CTX_free(ctx);

printf("%s: len=%u len_final=%u\n",__func__,len,len_final);

  return retv;
}

int ssl_evp_aes_encrypt(
  int mode,
  const EVP_CIPHER *evp_type,
  unsigned char *key, unsigned char *iv,
  unsigned char *in, size_t in_len,
  unsigned char **out, size_t *out_len
)
{
  return (mode == 1) ?
    ssl_evp_aes_gcm_encrypt(evp_type, key, iv, in, in_len, out, out_len) :
    ssl_evp_aes_cbc_encrypt(evp_type, key, iv, in, in_len, out, out_len);
}


static int ssl_evp_aes_cbc_decrypt(
  const EVP_CIPHER *evp_type,
  unsigned char *key, unsigned char *iv,
  unsigned char *in, size_t in_len,
  unsigned char **out, size_t *out_len
)
{
  int retv = 1;
  int len, len_final;
  EVP_CIPHER_CTX *ctx = NULL;

  ctx = EVP_CIPHER_CTX_new();
  *out_len = ((in_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  *out = OPENSSL_malloc(*out_len);
  if(
    !ctx || !*out ||
    (1 != EVP_DecryptInit_ex(ctx, evp_type, NULL, key, iv)) ||
    (1 != EVP_DecryptUpdate(ctx, *out, &len, in, in_len)) ||
    (1 != EVP_DecryptFinal_ex(ctx, *out + len, &len_final))
  ){
    if(*out){
      OPENSSL_free(*out);
      *out = NULL;
    }
    *out_len = 0;
    retv = 0;
  }
  else {
    *out_len = len + len_final;
  }
  if(ctx) EVP_CIPHER_CTX_free(ctx);

  return retv;
}

static int ssl_evp_aes_gcm_decrypt(
  const EVP_CIPHER *evp_type,
  unsigned char *key, unsigned char *iv,
  unsigned char *in, size_t in_len,
  unsigned char **out, size_t *out_len
)
{
  int retv = 1;
  int len, len_final;
  EVP_CIPHER_CTX *ctx = NULL;

//printf("%s: in_len=%u\n",__func__,in_len);

  ctx = EVP_CIPHER_CTX_new();
  *out_len = ((in_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  *out = OPENSSL_malloc(*out_len);
  if(!ctx || !*out){
    if(*out){
      OPENSSL_free(*out);
      *out = NULL;
    }
    *out_len = 0;
    retv = 0;
  }
  else if( (1 != EVP_DecryptInit_ex(ctx, evp_type, NULL, NULL, NULL)) ){
    puts("hier 1");
    retv = 0;
  }
  else if( (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL)) ){
    puts("hier 2");
    retv = 0;
  }
  else if( (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, in + in_len)) ){
    puts("hier 3");
    retv = 0;
  }
  else if( (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) ){
    puts("hier 4");
    retv = 0;
  }
  else if( (1 != EVP_DecryptUpdate (ctx, NULL, &len, (const unsigned char *)GCM_AAD, GCM_AAD_SIZE)) ){
    puts("hier 5");
    retv = 0;
  }
  else if( (1 != EVP_DecryptUpdate(ctx, *out, &len, in, in_len)) ){
    puts("hier 6");
    retv = 0;
  }
  else if( (1 != EVP_DecryptFinal_ex(ctx, *out /*+ len*/, &len_final)) ){
    puts("hier 7");
    retv = 0;
  }

  if(retv==0){
    if(*out){
      OPENSSL_free(*out);
      *out = NULL;
    }
    *out_len = 0;
    return 0;
  }
  else *out_len = len + len_final;

  if(ctx) EVP_CIPHER_CTX_free(ctx);

  return retv;
}

int ssl_evp_aes_decrypt(
  int mode,
  const EVP_CIPHER *evp_type,
  unsigned char *key, unsigned char *iv,
  unsigned char *in, size_t in_len,
  unsigned char **out, size_t *out_len
)
{
  return (mode == 1) ?
    ssl_evp_aes_gcm_decrypt(evp_type, key, iv, in, in_len, out, out_len) :
    ssl_evp_aes_cbc_decrypt(evp_type, key, iv, in, in_len, out, out_len);
}

//
// Message digest functions
//

int ssl_evp_md_create(
  const EVP_MD* md,
  unsigned char *msg, size_t msg_len,
  unsigned char **digest, unsigned int *digest_len
){
  int retv = 1;
  EVP_MD_CTX *ctx = NULL;

  if(digest) *digest = OPENSSL_malloc(EVP_MD_size(md));
  ctx = EVP_MD_CTX_create();
  if(
    !ctx || !md || !msg || !msg_len || !digest || !*digest || !digest_len ||
    (1 != EVP_DigestInit_ex(ctx, md, NULL)) ||
    (1 != EVP_DigestUpdate(ctx, msg, msg_len)) ||
    (1 != EVP_DigestFinal_ex(ctx, *digest, digest_len))
  ){
    if(digest && *digest){
      OPENSSL_free(*digest);
      *digest = NULL;
    }
    if(digest_len) *digest_len = 0;
    retv = 0;
    goto exit;
  }

exit:
  if(ctx) EVP_MD_CTX_destroy(ctx);
  return retv;
}

int ssl_evp_md_compare(unsigned char *sig1, unsigned char *sig2, size_t sig_size)
{
  return CRYPTO_memcmp(sig1, sig2, sig_size);
}

//
// Signing and Verifying functions
//

int ssl_evp_rsa_sign(
  const EVP_MD* md,
  unsigned char* in, size_t in_len,
  unsigned char** sig, size_t* sig_len,
  EVP_PKEY* private_key
)
{
  int retv = 1; // assume success
  size_t req;
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  if(sig) *sig = NULL;
  if(
    // Sanity check
    !ctx || !md || !in || !in_len || !sig || !sig_len || !private_key ||
    // initialize ctx with the given message digest type
    (1 != EVP_DigestInit_ex(ctx, md, NULL)) ||
    // start the signing process using the private key and message digest
    (1 != EVP_DigestSignInit(ctx, NULL, md, NULL, private_key)) ||
    // digest the input
    (1 != EVP_DigestSignUpdate(ctx, in, in_len)) ||
    // create the signature, returning its required size
    (1 != EVP_DigestSignFinal(ctx, NULL, &req)) ||
    // assign required size to *sig_len and test that the size is larger than 0
    !((*sig_len = req) > 0) ||
    // allocate/verify the memory required for the signature
    !(*sig = OPENSSL_malloc(req)) ||
    // store the signature in the allocated memory
    (1 != EVP_DigestSignFinal(ctx, *sig, sig_len)) ||
    // test that the requested size matches the signature size
    (*sig_len != req)
  ){
    // something went wrong, free any allocated memory and sanitize the output
    if(sig && *sig){
      OPENSSL_free(*sig);
      *sig = NULL;
    }
    if(sig_len) *sig_len = 0;
    retv = 0; // signal failure to caller
  }
  if(ctx) EVP_MD_CTX_destroy(ctx);
  return retv; // notify the caller
}

int ssl_evp_rsa_verify(
  const EVP_MD* md,
  unsigned char* in, size_t in_len,
  unsigned char* sig, size_t sig_len,
  EVP_PKEY* public_key
)
{
  int retv = 1; // assume success
  EVP_MD_CTX *ctx = NULL;
  ctx = EVP_MD_CTX_create();
  if(
    // Sanity check
    !ctx || !md || !in || !in_len || !sig || !sig_len || !public_key ||
    // initialize ctx with the given message digest type
    (1 != EVP_DigestInit_ex(ctx, md, NULL)) ||
    // start the verify process using the private key and message digest
    (1 != EVP_DigestVerifyInit(ctx, NULL, md, NULL, public_key)) ||
    // digest the input
    (1 != EVP_DigestVerifyUpdate(ctx, in, in_len)) ||
    // verify the signature
    (1 != EVP_DigestVerifyFinal(ctx, sig, sig_len))
  ){
    retv = 0; // signal failure to caller
  }
  if(ctx) EVP_MD_CTX_destroy(ctx);
  return retv; // notify the caller
}

//
// Helper functions to encrypt/decrypt a block of memory
//

struct rsa_plaintext_t {
  unsigned char aes_key[32];
  unsigned char aes_iv[16];
  unsigned char aes_md[64];
};

rsa_aes_encrypted_data*
rsa_aes_encrypt_and_sign(
  void *plaintext,
  size_t plaintext_size,
  EVP_PKEY *encrypt_key,
  EVP_PKEY *sign_key,
  int aes_keysize,
  int md_size,
  int aes_mode
)
{
  struct rsa_plaintext_t rsa_plaintext;
  unsigned char *aes_key;
  unsigned char *aes_iv;
  unsigned char *aes_digest;
  unsigned int aes_digestsize;
  const EVP_CIPHER *aes_type;
  const EVP_MD* md_type;
  rsa_aes_encrypted_data *out;
  size_t req;
  EVP_MD_CTX *ctx;

  // sanity check the input
  if(!plaintext || !plaintext_size || !encrypt_key || !sign_key) return NULL;

  // Set the AES Mode
  switch(aes_mode){
    // CBC Mode
    default: aes_mode = 0;
    case 0: {
      switch(aes_keysize){
        case 128: aes_type = EVP_aes_128_cbc(); break;
        case 192: aes_type = EVP_aes_192_cbc(); break;
        case 256: aes_type = EVP_aes_256_cbc(); break;
        default: aes_keysize = 256; aes_type = EVP_aes_256_cbc(); break;
      }
      break;
    }
    // GCM Mode
    case 1: {
      switch(aes_keysize){
        case 128: aes_type = EVP_aes_128_gcm(); break;
        case 192: aes_type = EVP_aes_192_gcm(); break;
        case 256: aes_type = EVP_aes_256_gcm(); break;
        default: aes_keysize = 256; aes_type = EVP_aes_256_gcm(); break;
      }
      break;
    }
  }

  // Set the SHA2 Message Digest type
  switch(md_size){
    case 224: md_type = EVP_sha224(); break;
    case 256: md_type = EVP_sha256(); break;
    case 384: md_type = EVP_sha384(); break;
    case 512: md_type = EVP_sha512(); break;
    default: md_size = 512; md_type = EVP_sha512(); break;
  }

  // Allocate the output structure
  out = OPENSSL_malloc(sizeof(rsa_aes_encrypted_data));

  // Create a new AES key and iv
  aes_key = ssl_aes_key(aes_keysize);
  aes_iv = ssl_aes_initial_vector();

  // Sanity check
  if(!out || !aes_key || !aes_iv){
    if(out) OPENSSL_free(out);
    if(aes_key) OPENSSL_free(aes_key);
    if(aes_iv) OPENSSL_free(aes_iv);
    return NULL;
  }
  memset(out, 0, sizeof(rsa_aes_encrypted_data));

  // partial setup of the RSA plaintext
  memset(&rsa_plaintext, 0, sizeof(struct rsa_plaintext_t));
  memcpy(rsa_plaintext.aes_key, aes_key, aes_keysize>>3);
  memcpy(rsa_plaintext.aes_iv, aes_iv, 128/8);

  // encrypt the plaintext with AES then
  // calculate the message digest over the ciphertext
  aes_digest = NULL;
  if(
    !ssl_evp_aes_encrypt(
      aes_mode, aes_type, aes_key, aes_iv,
      (unsigned char*)plaintext,
      plaintext_size,
      &out->aes_ciphertext,
      &out->aes_ciphertext_size
    )
    ||
    !ssl_evp_md_create(
      md_type,
      out->aes_ciphertext,
      out->aes_ciphertext_size,
      &aes_digest, &aes_digestsize
    )
    ||
    (aes_digestsize != (md_size>>3))
  ){
    if((out->aes_ciphertext)) OPENSSL_free(out->aes_ciphertext);
    if(aes_digest) OPENSSL_free(aes_digest);
    OPENSSL_free(out);
    OPENSSL_free(aes_key);
    OPENSSL_free(aes_iv);
    return NULL;
  }

  // destroy the AES key and iv
  memset(aes_key, 0, aes_keysize>>3);
  memset(aes_iv, 0, 128/8);
  OPENSSL_free(aes_key);
  OPENSSL_free(aes_iv);

  // finish the setup of the RSA plaintext
  memcpy(rsa_plaintext.aes_md, aes_digest, md_size>>3);
  OPENSSL_free(aes_digest);

  // encrypt the RSA plaintext buffer with the public RSA key
  if(
    !ssl_evp_rsa_encrypt(
      (void*)&rsa_plaintext, sizeof(struct rsa_plaintext_t),
      &out->rsa_ciphertext, &out->rsa_ciphertext_size,
      encrypt_key
    )
  ){
    OPENSSL_free(out->aes_ciphertext);
    OPENSSL_free(out);
    return NULL;
  }

  // destroy the RSA plaintext
  memset(&rsa_plaintext, 0, sizeof(struct rsa_plaintext_t));

  // sign the ciphertext
  ctx = EVP_MD_CTX_create();
  if(
    !ctx ||
    (1 != EVP_DigestInit_ex(ctx, md_type, NULL)) ||
    (1 != EVP_DigestSignInit(ctx, NULL, md_type, NULL, sign_key)) ||
    (1 != EVP_DigestSignUpdate(ctx, out->rsa_ciphertext, out->rsa_ciphertext_size)) ||
    (1 != EVP_DigestSignUpdate(ctx, out->aes_ciphertext, out->aes_ciphertext_size)) ||
    (1 != EVP_DigestSignFinal(ctx, NULL, &req)) ||
    !((out->signature_size = req) > 0) ||
    !(out->signature = OPENSSL_malloc(req)) ||
    (1 != EVP_DigestSignFinal(ctx, out->signature, &out->signature_size)) ||
    (out->signature_size != req)
  ){
    if(out->signature) OPENSSL_free(out->signature);
    OPENSSL_free(out->rsa_ciphertext);
    OPENSSL_free(out->aes_ciphertext);
    OPENSSL_free(out);
    return NULL;
  }
  EVP_MD_CTX_destroy(ctx);

  out->aes_mode = aes_mode;
  out->aes_keysize = aes_keysize;
  out->md_size = md_size;

  return out;
}

int rsa_aes_verify_and_decrypt(
  rsa_aes_encrypted_data* in,
  void **plaintext, size_t *plaintext_size,
  EVP_PKEY *verify_key,
  EVP_PKEY *decrypt_key
)
{
  EVP_MD_CTX *ctx;
  const EVP_CIPHER *aes_type = NULL;
  const EVP_MD* md_type = NULL;
  size_t rsa_plaintext_size;
  unsigned char *calc_digest;
  unsigned int calc_digestsize;
  struct rsa_plaintext_t* rsa_plaintext;

  // sanity check the input
  if(!in || !in->signature || !in->rsa_ciphertext || !in->aes_ciphertext || !plaintext || !plaintext_size || !verify_key || !decrypt_key) return 0;
  if((in->aes_mode != 0) && (in->aes_mode != 1)) return 0;
  if((in->aes_keysize != 128) && (in->aes_keysize != 192) && (in->aes_keysize != 256)) return 0;
  if((in->md_size != 224) && (in->md_size != 256) && (in->md_size != 384) && (in->md_size != 512)) return 0;

  // Set the AES Mode
  switch(in->aes_mode){
    // CBC Mode
    case 0: {
#ifdef SSL_EVP_DEBUG
    printf("%s: CBC mode\n", __func__);
#endif
#ifdef SSL_EVP_DEBUG
    printf("%s: Key size %u\n", __func__, in->aes_keysize);
#endif
      switch(in->aes_keysize){
        case 128: aes_type = EVP_aes_128_cbc(); break;
        case 192: aes_type = EVP_aes_192_cbc(); break;
        case 256: aes_type = EVP_aes_256_cbc(); break;
      }
      break;
    }
    // GCM Mode
    case 1: {
#ifdef SSL_EVP_DEBUG
    printf("%s: GCM Mode\n", __func__);
#endif
#ifdef SSL_EVP_DEBUG
    printf("%s: Key size %u\n", __func__, in->aes_keysize);
#endif
      switch(in->aes_keysize){
        case 128: aes_type = EVP_aes_128_gcm(); break;
        case 192: aes_type = EVP_aes_192_gcm(); break;
        case 256: aes_type = EVP_aes_256_gcm(); break;
      }
      break;
    }
  }

  // Set the SHA2 Message Digest type
#ifdef SSL_EVP_DEBUG
    printf("%s: MD size %u\n", __func__, in->md_size);
#endif
  switch(in->md_size){
    case 224: md_type = EVP_sha224(); break;
    case 256: md_type = EVP_sha256(); break;
    case 384: md_type = EVP_sha384(); break;
    case 512: md_type = EVP_sha512(); break;
  }

  // Verify the signature
  ctx = EVP_MD_CTX_create();
  if(
    !ctx ||
    (1 != EVP_DigestInit_ex(ctx, md_type, NULL)) ||
    (1 != EVP_DigestVerifyInit(ctx, NULL, md_type, NULL, verify_key)) ||
    (1 != EVP_DigestVerifyUpdate(ctx, in->rsa_ciphertext, in->rsa_ciphertext_size)) ||
    (1 != EVP_DigestVerifyUpdate(ctx, in->aes_ciphertext, in->aes_ciphertext_size)) ||
    (1 != EVP_DigestVerifyFinal(ctx, in->signature, in->signature_size))
  ){
#ifdef SSL_EVP_DEBUG
    printf("%s: Failed to verify!\n", __func__);
#endif
    return 0;
  }
  EVP_MD_CTX_destroy(ctx);
#ifdef SSL_EVP_DEBUG
    printf("%s: Verify O.K.\n", __func__);
#endif

  // decrypt the RSA ciphertext
  if(
    !ssl_evp_rsa_decrypt(in->rsa_ciphertext, in->rsa_ciphertext_size, (unsigned char**)&rsa_plaintext, &rsa_plaintext_size, decrypt_key) ||
    (rsa_plaintext_size != sizeof(struct rsa_plaintext_t))
  ){
#ifdef SSL_EVP_DEBUG
    printf("%s: Failed to RSA decrypt!\n", __func__);
#endif
    return 0;
  }
#ifdef SSL_EVP_DEBUG
    printf("%s: RSA decrypt O.K.\n", __func__);
#endif

  // Verify the message digest
  if(
    !ssl_evp_md_create(md_type, in->aes_ciphertext, in->aes_ciphertext_size, &calc_digest, &calc_digestsize) ||
    ((in->md_size>>3) != calc_digestsize) ||
    (0 != ssl_evp_md_compare(calc_digest, rsa_plaintext->aes_md, calc_digestsize))
  ){
    if(calc_digest) OPENSSL_free(calc_digest);
    OPENSSL_free(rsa_plaintext);
#ifdef SSL_EVP_DEBUG
    printf("%s: Messsage Digest Failed!\n", __func__);
#endif
    return 0;
  }
  OPENSSL_free(calc_digest);
#ifdef SSL_EVP_DEBUG
    printf("%s: Message Digest O.K.\n", __func__);
#endif

  // decrypt the AES ciphertext
  if(
    !ssl_evp_aes_decrypt(
      in->aes_mode, aes_type,
      rsa_plaintext->aes_key, rsa_plaintext->aes_iv,
      in->aes_ciphertext, in->aes_ciphertext_size,
      (unsigned char**)plaintext, plaintext_size
    )
  ){
    OPENSSL_free(rsa_plaintext);
#ifdef SSL_EVP_DEBUG
    printf("%s: AES decrypt failed!\n", __func__);
#endif
    return 0;
  }
#ifdef SSL_EVP_DEBUG
    printf("%s: AES decrypt O.K.\n", __func__);
#endif

  // Cleanup
  OPENSSL_free(rsa_plaintext);

  return 1;
}

//
// some other handy stuff
//

// Encodes a BIGNUM as a hexadecimal C-string
void ssl_hex_encode(unsigned char* readbuf, void *writebuf, size_t len)
{
  for(size_t i=0; i < len; i++) {
    char *l = (char*) (2*i + ((intptr_t) writebuf));
    sprintf(l, "%02x", readbuf[i]);
  }
}

// Calculate the SHA-256 fingerprint for the given certificate
// returns the fingerprint as a C string, or NULL otherwise
char* ssl_calculate_sha256_fingerprint(X509 *x509)
{
  unsigned char sha256[SSL_SHA256LEN];
	char sha256str[2*SSL_SHA256LEN+1];
  const EVP_MD *digest = EVP_sha256();
  unsigned int len;
  int rc = X509_digest(x509, digest, sha256, &len);
  if (rc == 0 || len != SSL_SHA256LEN) return NULL;
  ssl_hex_encode(sha256, sha256str, SSL_SHA256LEN);
  return OPENSSL_strdup(sha256str);
}

// Convert a date in ASN1 format to a C-string
// returns 0 on success, or 1 otherwise
int ssl_convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len)
{
  int rc;
  BIO *b = BIO_new(BIO_s_mem());
  rc = ASN1_TIME_print(b, t);
  if(rc <= 0){
    BIO_free(b);
    return 1;
  }
  rc = BIO_gets(b, buf, len);
  if(rc <= 0){
    BIO_free(b);
    return 1;
  }
  BIO_free(b);
  return 0;
}

// ends HAVE_NO_SSL
#endif

