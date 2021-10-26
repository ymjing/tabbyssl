/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 */

use crate::error_san::*;
use crate::libcrypto::{CRYPTO_FAILURE, CRYPTO_SUCCESS};
use crate::libssl::err::InnerResult;
use crate::{OpaquePointerGuard, MAGIC, MAGIC_SIZE};
use libc::c_int;
use rustls;

/// A structure for storing keys. Currently only RSA/ECC private keys are
/// supported.
#[allow(non_camel_case_types)]
pub struct EVP_PKEY {
    magic: [u8; MAGIC_SIZE],
    pub inner: rustls::PrivateKey,
}

impl OpaquePointerGuard for EVP_PKEY {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl EVP_PKEY {
    pub(crate) fn new(pkey: rustls::PrivateKey) -> Self {
        EVP_PKEY {
            magic: *MAGIC,
            inner: pkey,
        }
    }
}

/// `EVP_PKEY_free()` frees a EVP_PKEY
///
/// ```c
/// #include <tabbyssl/openssl/evp.h>
///
/// int EVP_PKEY_free(EVP_PKEY *p);
/// ```
#[no_mangle]
pub extern "C" fn EVP_PKEY_free(pkey_ptr: *mut EVP_PKEY) {
    let _ = check_inner_result!(inner_evp_pkey_free(pkey_ptr), CRYPTO_FAILURE);
}

fn inner_evp_pkey_free(pkey_ptr: *mut EVP_PKEY) -> InnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(pkey_ptr)?;
    let _ = unsafe { Box::from_raw(pkey_ptr) };
    Ok(CRYPTO_SUCCESS)
}
