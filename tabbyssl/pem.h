/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_PEM_H
#define TABBYSSL_PEM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <tabbyssl/options.h>
#include <tabbyssl/version.h>
#include <tabbyssl/visibility.h>
#include <tabbyssl/bio.h>
#include <tabbyssl/evp.h>
#include <tabbyssl/x509.h>
#include <stdio.h>

typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

TABBYSSL_API TABBYSSL_EVP_PKEY *tabbyssl_PEM_read_bio_PrivateKey(
  TABBYSSL_BIO *, TABBYSSL_EVP_PKEY **, pem_password_cb *cb, void *u);
TABBYSSL_API TABBYSSL_EVP_PKEY *tabbyssl_PEM_read_PrivateKey(
  FILE *fp, TABBYSSL_EVP_PKEY **x, pem_password_cb *cb, void *u);
TABBYSSL_API TABBYSSL_X509 *tabbyssl_PEM_read_bio_X509(TABBYSSL_BIO *,
                                                       TABBYSSL_X509 **,
                                                       pem_password_cb *cb,
                                                       void *u);
TABBYSSL_API TABBYSSL_X509 *tabbyssl_PEM_read_X509(FILE *fp, TABBYSSL_X509 **x,
                                                   pem_password_cb *cb,
                                                   void *u);
#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_PEM_H */