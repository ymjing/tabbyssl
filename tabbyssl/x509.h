/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_X509_H
#define TABBYSSL_X509_H

#ifdef __cplusplus
extern "C" {
#endif

#include <tabbyssl/options.h>
#include <tabbyssl/version.h>
#include <tabbyssl/visibility.h>

typedef struct TABBYSSL_X509 TABBYSSL_X509;
typedef struct TABBYSSL_X509_NAME TABBYSSL_X509_NAME;

#define TABBYSSL_STACK_OF(NAME) TABBYSSL_STACK_##NAME
typedef struct TABBYSSL_STACK_OF(TABBYSSL_X509)
  TABBYSSL_STACK_OF(TABBYSSL_X509);
typedef struct TABBYSSL_STACK_OF(TABBYSSL_X509_NAME)
  TABBYSSL_STACK_OF(TABBYSSL_X509_NAME);

TABBYSSL_API void tabbyssl_X509_free(const TABBYSSL_X509 *);
TABBYSSL_API void tabbyssl_X509_NAME_free(const TABBYSSL_X509_NAME *);

TABBYSSL_API TABBYSSL_X509_NAME *tabbyssl_X509_get_subject(
  const TABBYSSL_X509 *);
TABBYSSL_API TABBYSSL_X509_NAME *tabbyssl_X509_get_subject_name(
  const TABBYSSL_X509 *);
TABBYSSL_API TABBYSSL_STACK_OF(TABBYSSL_X509_NAME) *
  tabbyssl_X509_get_alt_subject_names(const TABBYSSL_X509 *);
TABBYSSL_API char *tabbyssl_X509_NAME_oneline(const TABBYSSL_X509_NAME *,
                                              char *buf, int size);

TABBYSSL_API TABBYSSL_STACK_OF(TABBYSSL_X509) *
  tabbyssl_sk_X509_new_null(void);
TABBYSSL_API int tabbyssl_sk_X509_num(const TABBYSSL_STACK_TABBYSSL_X509 *);
TABBYSSL_API TABBYSSL_X509_NAME *tabbyssl_sk_X509_value(
  const TABBYSSL_STACK_TABBYSSL_X509 *, int);
TABBYSSL_API int tabbyssl_sk_X509_push(TABBYSSL_STACK_TABBYSSL_X509 *,
                                       const TABBYSSL_X509 *);
TABBYSSL_API void tabbyssl_sk_X509_free(const TABBYSSL_STACK_TABBYSSL_X509 *);

TABBYSSL_API TABBYSSL_STACK_OF(TABBYSSL_X509_NAME) *
  tabbyssl_sk_X509_NAME_new_null(void);
TABBYSSL_API int tabbyssl_sk_X509_NAME_num(
  const TABBYSSL_STACK_TABBYSSL_X509_NAME *);
TABBYSSL_API TABBYSSL_X509_NAME *tabbyssl_sk_X509_NAME_value(
  const TABBYSSL_STACK_TABBYSSL_X509_NAME *, int);
TABBYSSL_API void tabbyssl_sk_X509_NAME_free(
  const TABBYSSL_STACK_TABBYSSL_X509_NAME *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_X509_H */
