/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_OPENSSL_EVP_H
#define TABBYSSL_OPENSSL_EVP_H

#include <tabbyssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EVP_PKEY TABBYSSL_EVP_PKEY

#define EVP_PKEY_free tabbyssl_EVP_PKEY_free

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_EVP_H */
