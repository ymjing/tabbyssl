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

//! # TabbySSL - OpenSSL compatibility layer for the Rust SSL/TLS stack
//!
//! Previously [MesaLink](https://mesalink.io), TabbySSL is an OpenSSL
//! compatibility layer for the Rust SSL/TLS stack.
//!
//! TabbySSL depends on [rustls](https://github.com/ctz/rustls) and provides the
//! following features through OpenSSL compatible C APIs.
//!
//! * TLS 1.2 and 1.3
//! * ECDSA or RSA server authentication
//! * Forward secrecy using ECDHE; with curve25519, nistp256 or nistp384 curves.
//! * Safe and fast crypto primitives from ring/BoringSSL
//! * AES-128-GCM, AES-256-GCM and Chacha20-Poly1305 bulk encryption
//! * Built-in Mozilla's CA root certificates
//!

#![deny(trivial_numeric_casts, unused_qualifications)]
#![deny(anonymous_parameters, unused_import_braces, unused_results, warnings)]

extern crate ring;
extern crate rustls;
extern crate rustls_pemfile;
extern crate sct;
extern crate untrusted;
extern crate webpki;
extern crate webpki_roots;

extern crate base64;
extern crate bitflags;
extern crate env_logger;
extern crate lazy_static;
extern crate libc;
extern crate thiserror;

use ring::rand;
use ring::rand::SecureRandom;

#[doc(hidden)]
pub(self) const MAGIC_SIZE: usize = 4;

use lazy_static::lazy_static;
lazy_static! {
    #[doc(hidden)]
    pub(self) static ref MAGIC: [u8; MAGIC_SIZE] = {
        let mut number = [0u8; MAGIC_SIZE];
        if rand::SystemRandom::new().fill(&mut number).is_ok() {
            number
        } else {
            panic!("Getrandom error");
        }
    };
}

#[doc(hidden)]
pub(crate) trait OpaquePointerGuard {
    fn check_magic(&self) -> bool;
}

#[macro_use]
mod macros;

#[macro_use]
mod error_san;

/// The ssl module is the counterpart of the OpenSSL ssl library.
pub mod libssl;

/// The crypo module is the counterpart of the OpenSSL crypto library.
pub mod libcrypto;
