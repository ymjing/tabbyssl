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

#define BIO_METHOD TABBY_BIO_METHOD
#define BIO TABBY_BIO

#define BIO_new tabby_BIO_new
#define BIO_free tabby_BIO_free

#define BIO_read tabby_BIO_read
#define BIO_gets tabby_BIO_gets
#define BIO_write tabby_BIO_write
#define BIO_puts tabby_BIO_puts

#define BIO_s_file tabby_BIO_s_file
#define BIO_new_fp tabby_BIO_new_fp
#define BIO_set_fp tabby_BIO_set_fp
#define BIO_get_close tabby_BIO_get_close
#define BIO_set_close tabby_BIO_set_close

#define BIO_new_file tabby_BIO_new_file
#define BIO_read_filename tabby_BIO_read_filename
#define BIO_write_filename tabby_BIO_write_filename
#define BIO_append_filename tabby_BIO_append_filename
#define BIO_rw_filename tabby_BIO_rw_filename

#define BIO_s_mem tabby_BIO_s_mem
#define BIO_new_mem_buf tabby_BIO_new_mem_buf

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_BIO_H */