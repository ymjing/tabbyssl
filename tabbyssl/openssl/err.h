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

#define SSL_ERROR_WANT_READ TABBY_ERROR_WANT_READ
#define SSL_ERROR_WANT_WRITE TABBY_ERROR_WANT_WRITE
#define SSL_ERROR_WANT_CONNECT TABBY_ERROR_WANT_CONNECT
#define SSL_ERROR_WANT_ACCEPT TABBY_ERROR_WANT_ACCEPT
#define SSL_ERROR_ZERO_RETURN TABBY_ERROR_ZERO_RETURN
#define SSL_ERROR_SYSCALL TABBY_ERROR_SYSCALL
#define SSL_ERROR_SSL TABBY_ERROR_SSL

#define ERR_load_crypto_strings tabby_ERR_load_error_strings
#define ERR_free_strings tabby_ERR_free_error_strings

#define ERR_error_string_n tabby_ERR_error_string_n
#define ERR_reason_error_string tabby_ERR_reason_error_string

#define ERR_get_error tabby_ERR_get_error
#define ERR_peek_last_error tabby_ERR_peek_last_error
#define ERR_clear_error tabby_ERR_clear_error

#define ERR_print_errors_fp tabby_ERR_print_errors_fp

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_ERR_H */
