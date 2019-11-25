/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
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
#![forbid(anonymous_parameters, unused_import_braces, unused_results, warnings)]

#[cfg(feature = "jemalloc_allocator")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

// enum_to_str_derive for human-readable error numbers
#[cfg(feature = "error_strings")]
#[macro_use]
extern crate enum_to_u8_slice_derive;

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
#[allow(improper_ctypes)]
pub mod libssl;

/// The crypo module is the counterpart of the OpenSSL crypto library.
#[allow(improper_ctypes)]
pub mod libcrypto;
