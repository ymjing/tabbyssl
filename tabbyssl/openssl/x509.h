/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

/* x509.h defines the compatibility layer for OpenSSL */

#ifndef TABBYSSL_OPENSSL_X509_H
#define TABBYSSL_OPENSSL_X509_H

#include <tabbyssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X509 TABBYSSL_X509
#define X509_NAME TABBYSSL_X509_NAME

#define STACK_OF(NAME) TABBYSSL_STACK_OF(TABBYSSL_##NAME)

#define X509_free tabbyssl_X509_free
#define X509_NAME_free tabbyssl_X509_NAME_free
#define X509_get_subject tabbyssl_X509_get_subject
#define X509_get_subject_name tabbyssl_X509_get_subject_name
#define X509_get_alt_subject_names tabbyssl_X509_get_alt_subject_names
#define X509_NAME_oneline tabbyssl_X509_NAME_oneline

#define sk_X509_new_null tabbyssl_sk_X509_new_null
#define sk_X509_num tabbyssl_sk_X509_num
#define sk_X509_value tabbyssl_sk_X509_value
#define sk_X509_push tabbyssl_sk_X509_push
#define sk_X509_free tabbyssl_sk_X509_free

#define sk_X509_NAME_new_null tabbyssl_sk_X509_NAME_new_null
#define sk_X509_NAME_num tabbyssl_sk_X509_NAME_num
#define sk_X509_NAME_value tabbyssl_sk_X509_NAME_value
#define sk_X509_NAME_push tabbyssl_sk_X509_NAME_push
#define sk_X509_NAME_free tabbyssl_sk_X509_NAME_free

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_X509_H */
