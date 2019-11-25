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

typedef struct TABBYSSL_METHOD TABBYSSL_METHOD;
typedef struct TABBYSSL_CTX TABBYSSL_CTX;
typedef struct TABBYSSL_CIPHER TABBYSSL_CIPHER;
typedef struct TABBYSSL_SSL TABBYSSL_SSL;

typedef enum tabbyssl_verify_mode_t
{
  TABBYSSL_SSL_VERIFY_NONE = 0,
  TABBYSSL_SSL_VERIFY_PEER = 1,
  TABBYSSL_SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
} tabbyssl_verify_mode_t;

typedef enum tabbyssl_constant_t
{
  TABBYSSL_FAILURE = 0,
  TABBYSSL_ERROR = -1,
  TABBYSSL_SUCCESS = 1,

  TABBYSSL_FILETYPE_PEM = 1,
  TABBYSSL_FILETYPE_ASN1 = 2,
  TABBYSSL_FILETYPE_DEFAULT = 2,
  TABBYSSL_FILETYPE_RAW = 3,

  TABBYSSL_SSL_SESS_CACHE_OFF = 0x0,
  TABBYSSL_SSL_SESS_CACHE_CLIENT = 0x1,
  TABBYSSL_SSL_SESS_CACHE_SERVER = 0x2,
  TABBYSSL_SSL_SESS_CACHE_BOTH = 0x3,

  TABBYSSL_SSL_EARLY_DATA_NOT_SENT = 0,
  TABBYSSL_SSL_EARLY_DATA_REJECTED = 1,
  TABBYSSL_SSL_EARLY_DATA_ACCEPTED = 2,
} tabbyssl_constant_t;

TABBYSSL_API int tabbyssl_library_init(void);
TABBYSSL_API int tabbyssl_add_ssl_algorithms(void);
TABBYSSL_API void tabbyssl_SSL_load_error_strings(void);
TABBYSSL_API void tabbyssl_SSL_init_logger(void);
TABBYSSL_API void tabbyssl_ERR_load_error_strings(void);
TABBYSSL_API void tabbyssl_ERR_free_error_strings(void);

typedef TABBYSSL_METHOD *(*tabbyssl_method_func)(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLS_method(void);
// Version-flexible methods
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLS_client_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_SSLv23_client_method(void);

// Not supported
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_SSLv3_client_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv1_client_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv1_1_client_method(void);

// Version-specific methods
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv1_2_client_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv1_3_client_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLS_client_method(void);

// Version-flexible methods
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_SSLv23_server_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv_server_method(void);

// Not supported
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_SSLv3_server_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv1_server_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv1_1_server_method(void);

// Version-specific methods
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv1_2_server_method(void);
TABBYSSL_API TABBYSSL_METHOD *tabbyssl_TLSv1_3_server_method(void);

TABBYSSL_API TABBYSSL_CTX *tabbyssl_SSL_CTX_new(TABBYSSL_METHOD *);
TABBYSSL_API int tabbyssl_SSL_CTX_load_verify_locations(TABBYSSL_CTX *,
                                                        const char *,
                                                        const char *);

TABBYSSL_API int tabbyssl_SSL_CTX_use_certificate(TABBYSSL_CTX *,
                                                  TABBYSSL_X509 *);
TABBYSSL_API int tabbyssl_SSL_CTX_add_extra_chain_cert(TABBYSSL_CTX *,
                                                       TABBYSSL_X509 *);
TABBYSSL_API int tabbyssl_SSL_CTX_use_certificate_chain_file(TABBYSSL_CTX *,
                                                             const char *,
                                                             int);
TABBYSSL_API int tabbyssl_SSL_CTX_use_certificate_ASN1(TABBYSSL_CTX *, int,
                                                       const unsigned char *);
TABBYSSL_API int tabbyssl_SSL_use_certificate_ASN1(TABBYSSL_SSL *,
                                                   const unsigned char *, int);
TABBYSSL_API int tabbyssl_SSL_CTX_use_PrivateKey(TABBYSSL_CTX *,
                                                 TABBYSSL_EVP_PKEY *);
TABBYSSL_API int tabbyssl_SSL_CTX_use_PrivateKey_file(TABBYSSL_CTX *,
                                                      const char *, int);
TABBYSSL_API int tabbyssl_SSL_CTX_check_private_key(const TABBYSSL_CTX *);
TABBYSSL_API int tabbyssl_SSL_CTX_use_PrivateKey_ASN1(int, TABBYSSL_CTX *,
                                                      const unsigned char *,
                                                      long);
TABBYSSL_API int tabbyssl_SSL_use_PrivateKey_ASN1(int, TABBYSSL_SSL *,
                                                  const unsigned char *, long);
TABBYSSL_API int tabbyssl_SSL_CTX_check_private_key(const TABBYSSL_CTX *);
TABBYSSL_API int tabbyssl_SSL_check_private_key(const TABBYSSL_SSL *ctx);

TABBYSSL_API int tabbyssl_SSL_CTX_set_verify(TABBYSSL_CTX *, int,
                                             int (*cb)(int, TABBYSSL_CTX *));
TABBYSSL_API long tabbyssl_SSL_CTX_set_session_cache_mode(TABBYSSL_CTX *,
                                                          long);
TABBYSSL_API long tabbyssl_SSL_CTX_get_session_cache_mode(TABBYSSL_CTX *);
TABBYSSL_API long tabbyssl_SSL_CTX_sess_set_cache_size(TABBYSSL_CTX *, long);
TABBYSSL_API long tabbyssl_SSL_CTX_sess_get_cache_size(TABBYSSL_CTX *);
TABBYSSL_API void tabbyssl_SSL_CTX_free(TABBYSSL_CTX *);

TABBYSSL_API TABBYSSL_SSL *tabbyssl_SSL_new(TABBYSSL_CTX *);
TABBYSSL_API TABBYSSL_CIPHER *tabbyssl_SSL_get_current_cipher(TABBYSSL_SSL *);
TABBYSSL_API const char *tabbyssl_SSL_CIPHER_get_name(const TABBYSSL_CIPHER *);
TABBYSSL_API int tabbyssl_SSL_CIPHER_get_bits(const TABBYSSL_CIPHER *, int *);
TABBYSSL_API const char *tabbyssl_SSL_CIPHER_get_version(
  const TABBYSSL_CIPHER *);
TABBYSSL_API const char *tabbyssl_SSL_get_cipher_name(TABBYSSL_SSL *);
TABBYSSL_API int tabbyssl_SSL_get_cipher_bits(TABBYSSL_SSL *, int *);
TABBYSSL_API const char *tabbyssl_SSL_get_cipher_version(const TABBYSSL_SSL *);
TABBYSSL_API TABBYSSL_X509 *tabbyssl_SSL_get_peer_certificate(
  const TABBYSSL_SSL *);
TABBYSSL_API int tabbyssl_SSL_set_tlsext_host_name(TABBYSSL_SSL *,
                                                   const char *);
TABBYSSL_API int tabbyssl_SSL_do_handshake(TABBYSSL_SSL *);

#ifdef HAVE_WINDOWS
#include <winsock2.h>
TABBYSSL_API int tabbyssl_SSL_set_socket(TABBYSSL_SSL *, SOCKET);
TABBYSSL_API SOCKET tabbyssl_SSL_get_socket(const TABBYSSL_SSL *);
#endif

TABBYSSL_API int tabbyssl_SSL_set_fd(TABBYSSL_SSL *, int);
TABBYSSL_API int tabbyssl_SSL_get_fd(const TABBYSSL_SSL *);

TABBYSSL_API int tabbyssl_SSL_connect(TABBYSSL_SSL *);
TABBYSSL_API int tabbyssl_SSL_connect0(TABBYSSL_SSL *);

TABBYSSL_API int tabbyssl_SSL_accept(TABBYSSL_SSL *);

TABBYSSL_API int tabbyssl_SSL_write(TABBYSSL_SSL *, const void *, int);
TABBYSSL_API int tabbyssl_SSL_read(TABBYSSL_SSL *, void *, int);
TABBYSSL_API int tabbyssl_SSL_flush(TABBYSSL_SSL *);
TABBYSSL_API int tabbyssl_SSL_write_early_data(TABBYSSL_SSL *, const void *,
                                               int, size_t *);
TABBYSSL_API int tabbyssl_SSL_get_early_data_status(const TABBYSSL_SSL *);
TABBYSSL_API int tabbyssl_SSL_shutdown(TABBYSSL_SSL *);
TABBYSSL_API TABBYSSL_CTX *tabbyssl_SSL_get_SSL_CTX(const TABBYSSL_SSL *);
TABBYSSL_API TABBYSSL_CTX *tabbyssl_SSL_set_SSL_CTX(TABBYSSL_SSL *,
                                                    TABBYSSL_CTX *);
TABBYSSL_API const char *tabbyssl_SSL_get_version(const TABBYSSL_SSL *);
TABBYSSL_API void tabbyssl_SSL_free(TABBYSSL_SSL *);

TABBYSSL_API int tabbyssl_SSL_get_error(const TABBYSSL_SSL *, int);

TABBYSSL_API void tabbyssl_SSL_set_connect_state(TABBYSSL_SSL *);
TABBYSSL_API void tabbyssl_SSL_set_accept_state(TABBYSSL_SSL *);
TABBYSSL_API int tabbyssl_SSL_is_server(const TABBYSSL_SSL *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_SSL_H */
