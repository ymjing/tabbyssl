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

#define SSL_CTX TABBYSSL_CTX
#define SSL TABBYSSL_SSL
#define SSL_METHOD TABBYSSL_METHOD
#define CIPHER TABBYSSL_CIPHER

#define SSL_VERIFY_NONE TABBYSSL_SSL_VERIFY_NONE
#define SSL_VERIFY_PEER TABBYSSL_SSL_VERIFY_PEER
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT                                       \
  TABBYSSL_SSL_VERIFY_FAIL_IF_NO_PEER_CERT

#define SSL_ERROR_NONE TABBYSSL_ERROR_NONE
#define SSL_FAILURE TABBYSSL_FAILURE
#define SSL_FATAL_ERROR TABBYSSL_FATAL_ERROR
#define SSL_SUCCESS TABBYSSL_SUCCESS

#define SSL_FILETYPE_PEM TABBYSSL_FILETYPE_PEM
#define SSL_FILETYPE_ASN1 TABBYSSL_FILETYPE_ASN1
#define SSL_FILETYPE_DEFAULT TABBYSSL_FILETYPE_DEFAULT
#define SSL_FILETYPE_RAW TABBYSSL_FILETYPE_RAW

#define SSL_SESS_CACHE_OFF TABBYSSL_SSL_SESS_CACHE_OFF
#define SSL_SESS_CACHE_CLIENT TABBYSSL_SSL_SESS_CACHE_CLIENT
#define SSL_SESS_CACHE_SERVER TABBYSSL_SSL_SESS_CACHE_SERVER
#define SSL_SESS_CACHE_BOTH TABBYSSL_SSL_SESS_CACHE_BOTH

#define SSL_EARLY_DATA_NOT_SENT TABBYSSL_SSL_EARLY_DATA_NOT_SENT
#define SSL_EARLY_DATA_REJECTED TABBYSSL_SSL_EARLY_DATA_REJECTED
#define SSL_EARLY_DATA_ACCEPTED TABBYSSL_SSL_EARLY_DATA_ACCEPTED

#define SSL_library_init tabbyssl_library_init
#define OpenSSL_add_ssl_algorithms tabbyssl_add_ssl_algorithms
#define SSL_load_error_strings tabbyssl_SSL_load_error_strings

#define TLS_method tabbyssl_TLS_method
// Version-flexible methods
#define TLS_client_method tabbyssl_TLS_client_method
#define SSLv23_client_method tabbyssl_SSLv23_client_method

// Not supported
#define SSLv3_client_method tabbyssl_SSLv3_client_method
#define TLSv1_client_method tabbyssl_TLSv1_client_method
#define TLSv1_1_client_method tabbyssl_TLSv1_1_client_method

// Version-specific methods
#define TLSv1_2_client_method tabbyssl_TLSv1_2_client_method
#define TLSv1_3_client_method tabbyssl_TLSv1_3_client_method

// Version-flexible methods
#define TLS_server_method tabbyssl_TLS_server_method
#define SSLv23_server_method tabbyssl_SSLv23_server_method

// Not supported
#define SSLv3_server_method tabbyssl_SSLv3_server_method
#define TLSv1_server_method tabbyssl_TLSv1_server_method
#define TLSv1_1_server_method tabbyssl_TLSv1_1_server_method

// Version-specific methods
#define TLSv1_2_server_method tabbyssl_TLSv1_2_server_method
#define TLSv1_3_server_method tabbyssl_TLSv1_3_server_method

#define SSL_CTX_new tabbyssl_SSL_CTX_new
#define SSL_CTX_load_verify_locations tabbyssl_SSL_CTX_load_verify_locations
#define SSL_CTX_use_certificate tabbyssl_SSL_CTX_use_certificate
#define SSL_CTX_add_extra_chain_cert tabbyssl_SSL_CTX_add_extra_chain_cert
#define SSL_CTX_use_certificate_chain_file                                    \
  tabbyssl_SSL_CTX_use_certificate_chain_file
#define SSL_CTX_use_certificate_ASN1 tabbyssl_SSL_CTX_use_certificate_ASN1
#define SSL_use_certificate_ASN1 tabbyssl_SSL_use_certificate_ASN1
#define SSL_CTX_use_PrivateKey tabbyssl_SSL_CTX_use_PrivateKey
#define SSL_CTX_use_PrivateKey_file tabbyssl_SSL_CTX_use_PrivateKey_file
#define SSL_CTX_use_PrivateKey_ASN1 tabbyssl_SSL_CTX_use_PrivateKey_ASN1
#define SSL_use_PrivateKey_ASN1 tabbyssl_SSL_use_PrivateKey_ASN1
#define SSL_CTX_check_private_key tabbyssl_SSL_CTX_check_private_key
#define SSL_check_private_key tabbyssl_SSL_check_private_key
#define SSL_CTX_set_verify tabbyssl_SSL_CTX_set_verify
#define SSL_CTX_set_session_cache_mode tabbyssl_SSL_CTX_set_session_cache_mode
#define SSL_CTX_get_session_cache_mode tabbyssl_SSL_CTX_get_session_cache_mode
#define SSL_CTX_sess_set_cache_size tabbyssl_SSL_CTX_sess_set_cache_size
#define SSL_CTX_sess_get_cache_size tabbyssl_SSL_CTX_sess_get_cache_size
#define SSL_CTX_free tabbyssl_SSL_CTX_free

#define SSL_new tabbyssl_SSL_new
#define SSL_get_current_cipher tabbyssl_SSL_get_current_cipher
#define SSL_CIPHER_get_name tabbyssl_SSL_CIPHER_get_name
#define SSL_CIPHER_get_bits tabbyssl_SSL_CIPHER_get_bits
#define SSL_CIPHER_get_version tabbyssl_SSL_CIPHER_get_version
#define SSL_get_cipher_name tabbyssl_SSL_get_cipher_name
#define SSL_get_cipher_bits tabbyssl_SSL_get_cipher_bits
#define SSL_get_cipher_version tabbyssl_SSL_get_cipher_version
#define SSL_get_peer_certificate tabbyssl_SSL_get_peer_certificate
#define SSL_set_tlsext_host_name tabbyssl_SSL_set_tlsext_host_name
#define SSL_get_SSL_CTX tabbyssl_SSL_get_SSL_CTX
#define SSL_set_SSL_CTX tabbyssl_SSL_set_SSL_CTX

#ifdef HAVE_WINDOWS
#define SSL_set_socket tabbyssl_SSL_set_socket
#define SSL_get_socket tabbyssl_SSL_get_socket
#endif

#define SSL_set_fd tabbyssl_SSL_set_fd
#define SSL_get_fd tabbyssl_SSL_get_fd

#define SSL_do_handshake tabbyssl_SSL_do_handshake

#define SSL_connect tabbyssl_SSL_connect
#define SSL_connect0 tabbyssl_SSL_connect0
#define SSL_accept tabbyssl_SSL_accept

#define SSL_write tabbyssl_SSL_write
#define SSL_read tabbyssl_SSL_read
#define SSL_write_early_data tabbyssl_SSL_write_early_data
#define SSL_get_early_data_status tabbyssl_SSL_get_early_data_status
#define SSL_flush tabbyssl_SSL_flush
#define SSL_shutdown tabbyssl_SSL_shutdown
#define SSL_get_version tabbyssl_SSL_get_version
#define SSL_free tabbyssl_SSL_free

#define SSL_get_error tabbyssl_SSL_get_error

#define SSL_set_connect_state tabbyssl_SSL_set_connect_state
#define SSL_set_accept_state tabbyssl_SSL_set_accept_state
#define SSL_is_server tabbyssl_SSL_is_server

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_SSL_H */
