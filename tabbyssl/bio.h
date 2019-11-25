/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_BIO_H
#define TABBYSSL_BIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <tabbyssl/options.h>
#include <tabbyssl/version.h>
#include <tabbyssl/visibility.h>
#include <stdio.h>

typedef struct TABBY_BIO_METHOD TABBY_BIO_METHOD;
typedef struct TABBY_BIO TABBY_BIO;

#define BIO_NOCLOSE         0x00
#define BIO_CLOSE           0x01

TABBY_API TABBY_BIO *tabby_BIO_new(const TABBY_BIO_METHOD *);
TABBY_API void tabby_BIO_free(TABBY_BIO *);

TABBY_API int tabby_BIO_read(TABBY_BIO *, void *, int);
TABBY_API int tabby_BIO_gets(TABBY_BIO *, char *, int);
TABBY_API int tabby_BIO_write(TABBY_BIO *, const void *, int);
TABBY_API int tabby_BIO_puts(TABBY_BIO *, const char *);

TABBY_API TABBY_BIO_METHOD *tabby_BIO_s_file(void);
TABBY_API TABBY_BIO *tabby_BIO_new_fp(FILE *, int);
TABBY_API void tabby_BIO_set_fp(TABBY_BIO *, FILE *, int);
TABBY_API int tabby_BIO_get_close(TABBY_BIO *);
TABBY_API int tabby_BIO_set_close(TABBY_BIO *, long);

TABBY_API TABBY_BIO *tabby_BIO_new_file(const char *, const char *);
TABBY_API int tabby_BIO_read_filename(TABBY_BIO *, const char *);
TABBY_API int tabby_BIO_write_filename(TABBY_BIO *, const char *);
TABBY_API int tabby_BIO_append_filename(TABBY_BIO *, const char *);
TABBY_API int tabby_BIO_rw_filename(TABBY_BIO *, const char *);

TABBY_API TABBY_BIO_METHOD *tabby_BIO_s_mem(void);
TABBY_API TABBY_BIO *tabby_BIO_new_mem_buf(const void *, int);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_BIO_H */
