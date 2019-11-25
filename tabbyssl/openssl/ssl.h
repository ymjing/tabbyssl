/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

/* ssl.h defines the compatibility layer for OpenSSL */

#ifndef TABBYSSL_OPENSSL_SSL_H
#define TABBYSSL_OPENSSL_SSL_H

#include <tabbyssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSL_CTX TABBY_CTX
#define SSL TABBY_SSL
#define SSL_METHOD TABBY_METHOD
#define CIPHER TABBY_CIPHER

#define SSL_VERIFY_NONE TABBY_SSL_VERIFY_NONE
#define SSL_VERIFY_PEER TABBY_SSL_VERIFY_PEER
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT                                       \
  TABBY_SSL_VERIFY_FAIL_IF_NO_PEER_CERT

#define SSL_ERROR_NONE TABBY_ERROR_NONE
#define SSL_FAILURE TABBY_FAILURE
#define SSL_FATAL_ERROR TABBY_FATAL_ERROR
#define SSL_SUCCESS TABBY_SUCCESS

#define SSL_FILETYPE_PEM TABBY_FILETYPE_PEM
#define SSL_FILETYPE_ASN1 TABBY_FILETYPE_ASN1
#define SSL_FILETYPE_DEFAULT TABBY_FILETYPE_DEFAULT
#define SSL_FILETYPE_RAW TABBY_FILETYPE_RAW

#define SSL_SESS_CACHE_OFF TABBY_SSL_SESS_CACHE_OFF
#define SSL_SESS_CACHE_CLIENT TABBY_SSL_SESS_CACHE_CLIENT
#define SSL_SESS_CACHE_SERVER TABBY_SSL_SESS_CACHE_SERVER
#define SSL_SESS_CACHE_BOTH TABBY_SSL_SESS_CACHE_BOTH

#define SSL_EARLY_DATA_NOT_SENT TABBY_SSL_EARLY_DATA_NOT_SENT
#define SSL_EARLY_DATA_REJECTED TABBY_SSL_EARLY_DATA_REJECTED
#define SSL_EARLY_DATA_ACCEPTED TABBY_SSL_EARLY_DATA_ACCEPTED

#define SSL_library_init tabby_library_init
#define OpenSSL_add_ssl_algorithms tabby_add_ssl_algorithms
#define SSL_load_error_strings tabby_SSL_load_error_strings

#define TLS_method tabby_TLS_method
// Version-flexible methods
#define TLS_client_method tabby_TLS_client_method
#define SSLv23_client_method tabby_SSLv23_client_method

// Not supported
#define SSLv3_client_method tabby_SSLv3_client_method
#define TLSv1_client_method tabby_TLSv1_client_method
#define TLSv1_1_client_method tabby_TLSv1_1_client_method

// Version-specific methods
#define TLSv1_2_client_method tabby_TLSv1_2_client_method
#define TLSv1_3_client_method tabby_TLSv1_3_client_method

// Version-flexible methods
#define TLS_server_method tabby_TLS_server_method
#define SSLv23_server_method tabby_SSLv23_server_method

// Not supported
#define SSLv3_server_method tabby_SSLv3_server_method
#define TLSv1_server_method tabby_TLSv1_server_method
#define TLSv1_1_server_method tabby_TLSv1_1_server_method

// Version-specific methods
#define TLSv1_2_server_method tabby_TLSv1_2_server_method
#define TLSv1_3_server_method tabby_TLSv1_3_server_method

#define SSL_CTX_new tabby_SSL_CTX_new
#define SSL_CTX_load_verify_locations tabby_SSL_CTX_load_verify_locations
#define SSL_CTX_use_certificate tabby_SSL_CTX_use_certificate
#define SSL_CTX_add_extra_chain_cert tabby_SSL_CTX_add_extra_chain_cert
#define SSL_CTX_use_certificate_chain_file                                    \
  tabby_SSL_CTX_use_certificate_chain_file
#define SSL_CTX_use_certificate_ASN1 tabby_SSL_CTX_use_certificate_ASN1
#define SSL_use_certificate_ASN1 tabby_SSL_use_certificate_ASN1
#define SSL_CTX_use_PrivateKey tabby_SSL_CTX_use_PrivateKey
#define SSL_CTX_use_PrivateKey_file tabby_SSL_CTX_use_PrivateKey_file
#define SSL_CTX_use_PrivateKey_ASN1 tabby_SSL_CTX_use_PrivateKey_ASN1
#define SSL_use_PrivateKey_ASN1 tabby_SSL_use_PrivateKey_ASN1
#define SSL_CTX_check_private_key tabby_SSL_CTX_check_private_key
#define SSL_check_private_key tabby_SSL_check_private_key
#define SSL_CTX_set_verify tabby_SSL_CTX_set_verify
#define SSL_CTX_set_session_cache_mode tabby_SSL_CTX_set_session_cache_mode
#define SSL_CTX_get_session_cache_mode tabby_SSL_CTX_get_session_cache_mode
#define SSL_CTX_sess_set_cache_size tabby_SSL_CTX_sess_set_cache_size
#define SSL_CTX_sess_get_cache_size tabby_SSL_CTX_sess_get_cache_size
#define SSL_CTX_free tabby_SSL_CTX_free

#define SSL_new tabby_SSL_new
#define SSL_get_current_cipher tabby_SSL_get_current_cipher
#define SSL_CIPHER_get_name tabby_SSL_CIPHER_get_name
#define SSL_CIPHER_get_bits tabby_SSL_CIPHER_get_bits
#define SSL_CIPHER_get_version tabby_SSL_CIPHER_get_version
#define SSL_get_cipher_name tabby_SSL_get_cipher_name
#define SSL_get_cipher_bits tabby_SSL_get_cipher_bits
#define SSL_get_cipher_version tabby_SSL_get_cipher_version
#define SSL_get_peer_certificate tabby_SSL_get_peer_certificate
#define SSL_set_tlsext_host_name tabby_SSL_set_tlsext_host_name
#define SSL_get_SSL_CTX tabby_SSL_get_SSL_CTX
#define SSL_set_SSL_CTX tabby_SSL_set_SSL_CTX

#ifdef HAVE_WINDOWS
#define SSL_set_socket tabby_SSL_set_socket
#define SSL_get_socket tabby_SSL_get_socket
#endif

#define SSL_set_fd tabby_SSL_set_fd
#define SSL_get_fd tabby_SSL_get_fd

#define SSL_do_handshake tabby_SSL_do_handshake

#define SSL_connect tabby_SSL_connect
#define SSL_connect0 tabby_SSL_connect0
#define SSL_accept tabby_SSL_accept

#define SSL_write tabby_SSL_write
#define SSL_read tabby_SSL_read
#define SSL_write_early_data tabby_SSL_write_early_data
#define SSL_get_early_data_status tabby_SSL_get_early_data_status
#define SSL_flush tabby_SSL_flush
#define SSL_shutdown tabby_SSL_shutdown
#define SSL_get_version tabby_SSL_get_version
#define SSL_free tabby_SSL_free

#define SSL_get_error tabby_SSL_get_error

#define SSL_set_connect_state tabby_SSL_set_connect_state
#define SSL_set_accept_state tabby_SSL_set_accept_state
#define SSL_is_server tabby_SSL_is_server

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_SSL_H */
