/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

use crate::error_san::*;
use crate::libcrypto::{CRYPTO_FAILURE, CRYPTO_SUCCESS};
use crate::libssl::err::MesalinkInnerResult;
use crate::{OpaquePointerGuard, MAGIC, MAGIC_SIZE};
use libc::c_int;
use rustls;

/// A structure for storing keys. Currently only RSA/ECC private keys are
/// supported.
#[allow(non_camel_case_types)]
pub struct MESALINK_EVP_PKEY {
    magic: [u8; MAGIC_SIZE],
    pub inner: rustls::PrivateKey,
}

impl OpaquePointerGuard for MESALINK_EVP_PKEY {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl MESALINK_EVP_PKEY {
    pub(crate) fn new(pkey: rustls::PrivateKey) -> Self {
        MESALINK_EVP_PKEY {
            magic: *MAGIC,
            inner: pkey,
        }
    }
}

/// `EVP_PKEY_free()` frees a EVP_PKEY
///
/// ```c
/// #include <mesalink/openssl/evp.h>
///
/// int EVP_PKEY_free(EVP_PKEY *p);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_EVP_PKEY_free(pkey_ptr: *mut MESALINK_EVP_PKEY) {
    let _ = check_inner_result!(inner_mesalink_evp_pkey_free(pkey_ptr), CRYPTO_FAILURE);
}

fn inner_mesalink_evp_pkey_free(pkey_ptr: *mut MESALINK_EVP_PKEY) -> MesalinkInnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(pkey_ptr)?;
    let _ = unsafe { Box::from_raw(pkey_ptr) };
    Ok(CRYPTO_SUCCESS)
}
