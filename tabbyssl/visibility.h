/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

/* Visibility control macros */

#ifndef TABBYSSL_VISIBILITY_H
#define TABBYSSL_VISIBILITY_H

#ifdef HAVE_UNIX
#define TABBY_API __attribute__((visibility("default")))
#define TABBY_LOCAL __attribute__((visiblity("hidden")))
#else
#define TABBY_API
#define TABBY_LOCAL
#endif

#endif /* TABBYSSL_VISIBILITY_H */