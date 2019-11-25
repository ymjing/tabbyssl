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

typedef struct TABBYSSL_BIO_METHOD TABBYSSL_BIO_METHOD;
typedef struct TABBYSSL_BIO TABBYSSL_BIO;

#define BIO_NOCLOSE         0x00
#define BIO_CLOSE           0x01

TABBYSSL_API TABBYSSL_BIO *tabbyssl_BIO_new(const TABBYSSL_BIO_METHOD *);
TABBYSSL_API void tabbyssl_BIO_free(TABBYSSL_BIO *);

TABBYSSL_API int tabbyssl_BIO_read(TABBYSSL_BIO *, void *, int);
TABBYSSL_API int tabbyssl_BIO_gets(TABBYSSL_BIO *, char *, int);
TABBYSSL_API int tabbyssl_BIO_write(TABBYSSL_BIO *, const void *, int);
TABBYSSL_API int tabbyssl_BIO_puts(TABBYSSL_BIO *, const char *);

TABBYSSL_API TABBYSSL_BIO_METHOD *tabbyssl_BIO_s_file(void);
TABBYSSL_API TABBYSSL_BIO *tabbyssl_BIO_new_fp(FILE *, int);
TABBYSSL_API void tabbyssl_BIO_set_fp(TABBYSSL_BIO *, FILE *, int);
TABBYSSL_API int tabbyssl_BIO_get_close(TABBYSSL_BIO *);
TABBYSSL_API int tabbyssl_BIO_set_close(TABBYSSL_BIO *, long);

TABBYSSL_API TABBYSSL_BIO *tabbyssl_BIO_new_file(const char *, const char *);
TABBYSSL_API int tabbyssl_BIO_read_filename(TABBYSSL_BIO *, const char *);
TABBYSSL_API int tabbyssl_BIO_write_filename(TABBYSSL_BIO *, const char *);
TABBYSSL_API int tabbyssl_BIO_append_filename(TABBYSSL_BIO *, const char *);
TABBYSSL_API int tabbyssl_BIO_rw_filename(TABBYSSL_BIO *, const char *);

TABBYSSL_API TABBYSSL_BIO_METHOD *tabbyssl_BIO_s_mem(void);
TABBYSSL_API TABBYSSL_BIO *tabbyssl_BIO_new_mem_buf(const void *, int);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_BIO_H */
