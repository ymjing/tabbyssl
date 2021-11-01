/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
pub enum SslConstants {
    Error = -1,
    Failure = 0,
    Success = 1,
}

use libc::c_int;
pub const SSL_ERROR: c_int = -1;
pub const SSL_FAILURE: c_int = 0;
pub const SSL_SUCCESS: c_int = 1;

#[doc(hidden)]
#[repr(C)]
#[derive(Clone)]
pub(self) enum SslSessionCacheModes {
    Off = 0x0,
    Client = 0x1,
    Server = 0x2,
    Both = 0x3,
}
