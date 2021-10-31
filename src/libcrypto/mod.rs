/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 */

/// Implementations of OpenSSL BIO APIs.
/// Please also refer to the header file at tabbyssl/openssl/bio.h
pub mod bio;

/// Implementations of OpenSSL EVP APIs.
/// Please also refer to the header file at tabbyssl/openssl/evp.h
pub mod evp;

/// Implementations of OpenSSL PEM APIs.
/// Please also refer to the header file at tabbyssl/openssl/evp.h
pub mod pem;

use libc::c_int;
pub const CRYPTO_FAILURE: c_int = 0;
pub const CRYPTO_SUCCESS: c_int = 1;
