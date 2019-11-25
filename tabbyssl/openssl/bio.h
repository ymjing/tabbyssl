/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_OPENSSL_BIO_H
#define TABBYSSL_OPENSSL_BIO_H

#include <tabbyssl/bio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIO_METHOD TABBYSSL_BIO_METHOD
#define BIO TABBYSSL_BIO

#define BIO_new tabbyssl_BIO_new
#define BIO_free tabbyssl_BIO_free

#define BIO_read tabbyssl_BIO_read
#define BIO_gets tabbyssl_BIO_gets
#define BIO_write tabbyssl_BIO_write
#define BIO_puts tabbyssl_BIO_puts

#define BIO_s_file tabbyssl_BIO_s_file
#define BIO_new_fp tabbyssl_BIO_new_fp
#define BIO_set_fp tabbyssl_BIO_set_fp
#define BIO_get_close tabbyssl_BIO_get_close
#define BIO_set_close tabbyssl_BIO_set_close

#define BIO_new_file tabbyssl_BIO_new_file
#define BIO_read_filename tabbyssl_BIO_read_filename
#define BIO_write_filename tabbyssl_BIO_write_filename
#define BIO_append_filename tabbyssl_BIO_append_filename
#define BIO_rw_filename tabbyssl_BIO_rw_filename

#define BIO_s_mem tabbyssl_BIO_s_mem
#define BIO_new_mem_buf tabbyssl_BIO_new_mem_buf

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_BIO_H */