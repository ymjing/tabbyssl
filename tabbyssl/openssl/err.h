/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_OPENSSL_ERR_H
#define TABBYSSL_OPENSSL_ERR_H

#include <tabbyssl/ssl.h>
#include <tabbyssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SSL_ERROR_WANT_READ TABBYSSL_ERROR_WANT_READ
#define SSL_ERROR_WANT_WRITE TABBYSSL_ERROR_WANT_WRITE
#define SSL_ERROR_WANT_CONNECT TABBYSSL_ERROR_WANT_CONNECT
#define SSL_ERROR_WANT_ACCEPT TABBYSSL_ERROR_WANT_ACCEPT
#define SSL_ERROR_ZERO_RETURN TABBYSSL_ERROR_ZERO_RETURN
#define SSL_ERROR_SYSCALL TABBYSSL_ERROR_SYSCALL
#define SSL_ERROR_SSL TABBYSSL_ERROR_SSL

#define ERR_load_crypto_strings tabbyssl_ERR_load_error_strings
#define ERR_free_strings tabbyssl_ERR_free_error_strings

#define ERR_error_string_n tabbyssl_ERR_error_string_n
#define ERR_reason_error_string tabbyssl_ERR_reason_error_string

#define ERR_get_error tabbyssl_ERR_get_error
#define ERR_peek_last_error tabbyssl_ERR_peek_last_error
#define ERR_clear_error tabbyssl_ERR_clear_error

#define ERR_print_errors_fp tabbyssl_ERR_print_errors_fp

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_ERR_H */
