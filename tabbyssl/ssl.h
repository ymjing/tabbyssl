/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_SSL_H
#define TABBYSSL_SSL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <tabbyssl/options.h>
#include <tabbyssl/version.h>
#include <tabbyssl/visibility.h>
#include <tabbyssl/x509.h>
#include <tabbyssl/evp.h>

typedef struct TABBY_METHOD TABBY_METHOD;
typedef struct TABBY_CTX TABBY_CTX;
typedef struct TABBY_CIPHER TABBY_CIPHER;
typedef struct TABBY_SSL TABBY_SSL;

typedef enum tabby_verify_mode_t
{
  TABBY_SSL_VERIFY_NONE = 0,
  TABBY_SSL_VERIFY_PEER = 1,
  TABBY_SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
} tabby_verify_mode_t;

typedef enum tabby_constant_t
{
  TABBY_FAILURE = 0,
  TABBY_ERROR = -1,
  TABBY_SUCCESS = 1,

  TABBY_FILETYPE_PEM = 1,
  TABBY_FILETYPE_ASN1 = 2,
  TABBY_FILETYPE_DEFAULT = 2,
  TABBY_FILETYPE_RAW = 3,

  TABBY_SSL_SESS_CACHE_OFF = 0x0,
  TABBY_SSL_SESS_CACHE_CLIENT = 0x1,
  TABBY_SSL_SESS_CACHE_SERVER = 0x2,
  TABBY_SSL_SESS_CACHE_BOTH = 0x3,

  TABBY_SSL_EARLY_DATA_NOT_SENT = 0,
  TABBY_SSL_EARLY_DATA_REJECTED = 1,
  TABBY_SSL_EARLY_DATA_ACCEPTED = 2,
} tabby_constant_t;

TABBY_API int tabby_library_init(void);
TABBY_API int tabby_add_ssl_algorithms(void);
TABBY_API void tabby_SSL_load_error_strings(void);
TABBY_API void tabby_SSL_init_logger(void);
TABBY_API void tabby_ERR_load_error_strings(void);
TABBY_API void tabby_ERR_free_error_strings(void);

typedef TABBY_METHOD *(*tabby_method_func)(void);
TABBY_API TABBY_METHOD *tabby_TLS_method(void);
// Version-flexible methods
TABBY_API TABBY_METHOD *tabby_TLS_client_method(void);
TABBY_API TABBY_METHOD *tabby_SSLv23_client_method(void);

// Not supported
TABBY_API TABBY_METHOD *tabby_SSLv3_client_method(void);
TABBY_API TABBY_METHOD *tabby_TLSv1_client_method(void);
TABBY_API TABBY_METHOD *tabby_TLSv1_1_client_method(void);

// Version-specific methods
TABBY_API TABBY_METHOD *tabby_TLSv1_2_client_method(void);
TABBY_API TABBY_METHOD *tabby_TLSv1_3_client_method(void);
TABBY_API TABBY_METHOD *tabby_TLS_client_method(void);

// Version-flexible methods
TABBY_API TABBY_METHOD *tabby_SSLv23_server_method(void);
TABBY_API TABBY_METHOD *tabby_TLSv_server_method(void);

// Not supported
TABBY_API TABBY_METHOD *tabby_SSLv3_server_method(void);
TABBY_API TABBY_METHOD *tabby_TLSv1_server_method(void);
TABBY_API TABBY_METHOD *tabby_TLSv1_1_server_method(void);

// Version-specific methods
TABBY_API TABBY_METHOD *tabby_TLSv1_2_server_method(void);
TABBY_API TABBY_METHOD *tabby_TLSv1_3_server_method(void);

TABBY_API TABBY_CTX *tabby_SSL_CTX_new(TABBY_METHOD *);
TABBY_API int tabby_SSL_CTX_load_verify_locations(TABBY_CTX *,
                                                        const char *,
                                                        const char *);

TABBY_API int tabby_SSL_CTX_use_certificate(TABBY_CTX *,
                                                  TABBY_X509 *);
TABBY_API int tabby_SSL_CTX_add_extra_chain_cert(TABBY_CTX *,
                                                       TABBY_X509 *);
TABBY_API int tabby_SSL_CTX_use_certificate_chain_file(TABBY_CTX *,
                                                             const char *,
                                                             int);
TABBY_API int tabby_SSL_CTX_use_certificate_ASN1(TABBY_CTX *, int,
                                                       const unsigned char *);
TABBY_API int tabby_SSL_use_certificate_ASN1(TABBY_SSL *,
                                                   const unsigned char *, int);
TABBY_API int tabby_SSL_CTX_use_PrivateKey(TABBY_CTX *,
                                                 TABBY_EVP_PKEY *);
TABBY_API int tabby_SSL_CTX_use_PrivateKey_file(TABBY_CTX *,
                                                      const char *, int);
TABBY_API int tabby_SSL_CTX_check_private_key(const TABBY_CTX *);
TABBY_API int tabby_SSL_CTX_use_PrivateKey_ASN1(int, TABBY_CTX *,
                                                      const unsigned char *,
                                                      long);
TABBY_API int tabby_SSL_use_PrivateKey_ASN1(int, TABBY_SSL *,
                                                  const unsigned char *, long);
TABBY_API int tabby_SSL_CTX_check_private_key(const TABBY_CTX *);
TABBY_API int tabby_SSL_check_private_key(const TABBY_SSL *ctx);

TABBY_API int tabby_SSL_CTX_set_verify(TABBY_CTX *, int,
                                             int (*cb)(int, TABBY_CTX *));
TABBY_API long tabby_SSL_CTX_set_session_cache_mode(TABBY_CTX *,
                                                          long);
TABBY_API long tabby_SSL_CTX_get_session_cache_mode(TABBY_CTX *);
TABBY_API long tabby_SSL_CTX_sess_set_cache_size(TABBY_CTX *, long);
TABBY_API long tabby_SSL_CTX_sess_get_cache_size(TABBY_CTX *);
TABBY_API void tabby_SSL_CTX_free(TABBY_CTX *);

TABBY_API TABBY_SSL *tabby_SSL_new(TABBY_CTX *);
TABBY_API TABBY_CIPHER *tabby_SSL_get_current_cipher(TABBY_SSL *);
TABBY_API const char *tabby_SSL_CIPHER_get_name(const TABBY_CIPHER *);
TABBY_API int tabby_SSL_CIPHER_get_bits(const TABBY_CIPHER *, int *);
TABBY_API const char *tabby_SSL_CIPHER_get_version(
  const TABBY_CIPHER *);
TABBY_API const char *tabby_SSL_get_cipher_name(TABBY_SSL *);
TABBY_API int tabby_SSL_get_cipher_bits(TABBY_SSL *, int *);
TABBY_API const char *tabby_SSL_get_cipher_version(const TABBY_SSL *);
TABBY_API TABBY_X509 *tabby_SSL_get_peer_certificate(
  const TABBY_SSL *);
TABBY_API int tabby_SSL_set_tlsext_host_name(TABBY_SSL *,
                                                   const char *);
TABBY_API int tabby_SSL_do_handshake(TABBY_SSL *);

#ifdef HAVE_WINDOWS
#include <winsock2.h>
TABBY_API int tabby_SSL_set_socket(TABBY_SSL *, SOCKET);
TABBY_API SOCKET tabby_SSL_get_socket(const TABBY_SSL *);
#endif

TABBY_API int tabby_SSL_set_fd(TABBY_SSL *, int);
TABBY_API int tabby_SSL_get_fd(const TABBY_SSL *);

TABBY_API int tabby_SSL_connect(TABBY_SSL *);
TABBY_API int tabby_SSL_connect0(TABBY_SSL *);

TABBY_API int tabby_SSL_accept(TABBY_SSL *);

TABBY_API int tabby_SSL_write(TABBY_SSL *, const void *, int);
TABBY_API int tabby_SSL_read(TABBY_SSL *, void *, int);
TABBY_API int tabby_SSL_flush(TABBY_SSL *);
TABBY_API int tabby_SSL_write_early_data(TABBY_SSL *, const void *,
                                               int, size_t *);
TABBY_API int tabby_SSL_get_early_data_status(const TABBY_SSL *);
TABBY_API int tabby_SSL_shutdown(TABBY_SSL *);
TABBY_API TABBY_CTX *tabby_SSL_get_SSL_CTX(const TABBY_SSL *);
TABBY_API TABBY_CTX *tabby_SSL_set_SSL_CTX(TABBY_SSL *,
                                                    TABBY_CTX *);
TABBY_API const char *tabby_SSL_get_version(const TABBY_SSL *);
TABBY_API void tabby_SSL_free(TABBY_SSL *);

TABBY_API int tabby_SSL_get_error(const TABBY_SSL *, int);

TABBY_API void tabby_SSL_set_connect_state(TABBY_SSL *);
TABBY_API void tabby_SSL_set_accept_state(TABBY_SSL *);
TABBY_API int tabby_SSL_is_server(const TABBY_SSL *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_SSL_H */
