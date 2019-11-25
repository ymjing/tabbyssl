/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_OPENSSL_PEM_H
#define TABBYSSL_OPENSSL_PEM_H

#include <tabbyssl/pem.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PEM_read_bio_PrivateKey tabby_PEM_read_bio_PrivateKey
#define PEM_read_PrivateKey tabby_PEM_read_PrivateKey
#define PEM_read_bio_X509 tabby_PEM_read_bio_X509
#define PEM_read_X509 tabby_PEM_read_X509

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_PEM_H */