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

typedef struct TABBY_X509 TABBY_X509;
typedef struct TABBY_X509_NAME TABBY_X509_NAME;

#define TABBY_STACK_OF(NAME) TABBY_STACK_##NAME
typedef struct TABBY_STACK_OF(TABBY_X509)
  TABBY_STACK_OF(TABBY_X509);
typedef struct TABBY_STACK_OF(TABBY_X509_NAME)
  TABBY_STACK_OF(TABBY_X509_NAME);

TABBY_API void tabby_X509_free(const TABBY_X509 *);
TABBY_API void tabby_X509_NAME_free(const TABBY_X509_NAME *);

TABBY_API TABBY_X509_NAME *tabby_X509_get_subject(
  const TABBY_X509 *);
TABBY_API TABBY_X509_NAME *tabby_X509_get_subject_name(
  const TABBY_X509 *);
TABBY_API TABBY_STACK_OF(TABBY_X509_NAME) *
  tabby_X509_get_alt_subject_names(const TABBY_X509 *);
TABBY_API char *tabby_X509_NAME_oneline(const TABBY_X509_NAME *,
                                              char *buf, int size);

TABBY_API TABBY_STACK_OF(TABBY_X509) *
  tabby_sk_X509_new_null(void);
TABBY_API int tabby_sk_X509_num(const TABBY_STACK_TABBY_X509 *);
TABBY_API TABBY_X509_NAME *tabby_sk_X509_value(
  const TABBY_STACK_TABBY_X509 *, int);
TABBY_API int tabby_sk_X509_push(TABBY_STACK_TABBY_X509 *,
                                       const TABBY_X509 *);
TABBY_API void tabby_sk_X509_free(const TABBY_STACK_TABBY_X509 *);

TABBY_API TABBY_STACK_OF(TABBY_X509_NAME) *
  tabby_sk_X509_NAME_new_null(void);
TABBY_API int tabby_sk_X509_NAME_num(
  const TABBY_STACK_TABBY_X509_NAME *);
TABBY_API TABBY_X509_NAME *tabby_sk_X509_NAME_value(
  const TABBY_STACK_TABBY_X509_NAME *, int);
TABBY_API void tabby_sk_X509_NAME_free(
  const TABBY_STACK_TABBY_X509_NAME *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_X509_H */
