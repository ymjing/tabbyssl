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

#define X509 TABBY_X509
#define X509_NAME TABBY_X509_NAME

#define STACK_OF(NAME) TABBY_STACK_OF(TABBY_##NAME)

#define X509_free tabby_X509_free
#define X509_NAME_free tabby_X509_NAME_free
#define X509_get_subject tabby_X509_get_subject
#define X509_get_subject_name tabby_X509_get_subject_name
#define X509_get_alt_subject_names tabby_X509_get_alt_subject_names
#define X509_NAME_oneline tabby_X509_NAME_oneline

#define sk_X509_new_null tabby_sk_X509_new_null
#define sk_X509_num tabby_sk_X509_num
#define sk_X509_value tabby_sk_X509_value
#define sk_X509_push tabby_sk_X509_push
#define sk_X509_free tabby_sk_X509_free

#define sk_X509_NAME_new_null tabby_sk_X509_NAME_new_null
#define sk_X509_NAME_num tabby_sk_X509_NAME_num
#define sk_X509_NAME_value tabby_sk_X509_NAME_value
#define sk_X509_NAME_push tabby_sk_X509_NAME_push
#define sk_X509_NAME_free tabby_sk_X509_NAME_free

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_OPENSSL_X509_H */
