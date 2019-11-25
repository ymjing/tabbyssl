/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_EVP_H
#define TABBYSSL_EVP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <tabbyssl/options.h>
#include <tabbyssl/version.h>
#include <tabbyssl/visibility.h>

typedef struct TABBY_EVP_PKEY TABBY_EVP_PKEY;

TABBY_API void tabby_EVP_PKEY_free(TABBY_EVP_PKEY *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_EVP_H */