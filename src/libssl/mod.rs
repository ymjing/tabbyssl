/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 */

/// Implementations of OpenSSL ERR APIs.
/// Please also refer to the header file at tabbyssl/openssl/err.h
#[macro_use]
pub mod err;

/// Implementations of OpenSSL SSL APIs.
/// Please also refer to the header file at tabbyssl/openssl/ssl.h
pub mod ssl;

/// Implementations of OpenSSL X509 APIs.
/// Please also refer to the header file at tabbyssl/openssl/x509.h
pub mod x509;

/// Implementations of OpenSSL STACK APIs.
/// Please also refer to the header file at tabbyssl/openssl/safestack.h
pub mod safestack;

#[doc(hidden)]
#[repr(C)]
pub(self) enum SslConstants {
    Error = -1,
    Failure = 0,
    Success = 1,
}

#[doc(hidden)]
#[repr(C)]
#[derive(Clone)]
pub(self) enum SslSessionCacheModes {
    Off = 0x0,
    Client = 0x1,
    Server = 0x2,
    Both = 0x3,
}

use libc::c_int;
pub(self) const SSL_ERROR: c_int = SslConstants::Error as c_int;
pub(self) const SSL_FAILURE: c_int = SslConstants::Failure as c_int;
pub(self) const SSL_SUCCESS: c_int = SslConstants::Success as c_int;
