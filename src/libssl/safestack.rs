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

use super::err::{Error, InnerResult};
use super::x509::{X509, X509_NAME};
use super::{SSL_FAILURE, SSL_SUCCESS};
use crate::error_san::*;
use crate::{OpaquePointerGuard, MAGIC, MAGIC_SIZE};
use libc::c_int;
use std::ptr;

// ---------------------------------------
// STACK for X509
// ---------------------------------------

/// An OpenSSL STACK_OF(X509) object
#[allow(non_camel_case_types)]
pub struct STACK_X509 {
    magic: [u8; MAGIC_SIZE],
    pub(crate) stack: Vec<X509>,
}

impl OpaquePointerGuard for STACK_X509 {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl STACK_X509 {
    pub(crate) fn new(names: Vec<X509>) -> STACK_X509 {
        STACK_X509 {
            magic: *MAGIC,
            stack: names,
        }
    }
}

/// `sk_X509_new_null` - allocates a new stack of X509.
///
/// ```c
/// #include <tabbyssl/openssl/x509.h>
///
/// STACK_OF(X509) *sk_X509_new_null(void);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_new_null() -> *mut STACK_X509 {
    let stack = STACK_X509::new(vec![]);
    Box::into_raw(Box::new(stack)) as *mut STACK_X509
}

/// `sk_X509_num` - returns the number of elements in sk or -1 if sk is NULL.
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// int sk_X509_num(const STACK_OF(X509) *sk);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_num(stack_ptr: *const STACK_X509) -> c_int {
    check_inner_result!(inner_sk_X509_num(stack_ptr), SSL_FAILURE)
}

#[allow(non_snake_case)]
fn inner_sk_X509_num(stack_ptr: *const STACK_X509) -> InnerResult<c_int> {
    let stack = sanitize_const_ptr_for_ref(stack_ptr)?;
    Ok(stack.stack.len() as c_int)
}

/// `sk_X509_value` - returns element idx in sk, where idx starts at zero. If
/// idx is out of range then NULL is returned.
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// X509 *sk_X509_value(const STACK_OF(X509) *sk, int idx);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_value(stack_ptr: *const STACK_X509, index: c_int) -> *const X509 {
    check_inner_result!(inner_sk_X509_value(stack_ptr, index), ptr::null())
}

#[allow(non_snake_case)]
fn inner_sk_X509_value(stack_ptr: *const STACK_X509, index: c_int) -> InnerResult<*const X509> {
    let stack = sanitize_const_ptr_for_ref(stack_ptr)?;
    let item = stack.stack.get(index as usize).ok_or(Error::BadFuncArg)?;
    Ok(item as *const X509)
}

/// `sk_X509_push` - appends ptr to sk.
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// int sk_X509_push(STACK_OF(X509) *sk, const X509 *ptr);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_push(stack_ptr: *mut STACK_X509, item_ptr: *const X509) -> c_int {
    check_inner_result!(inner_sk_X509_push(stack_ptr, item_ptr), SSL_FAILURE)
}

#[allow(non_snake_case)]
fn inner_sk_X509_push(stack_ptr: *mut STACK_X509, item_ptr: *const X509) -> InnerResult<c_int> {
    let stack = sanitize_ptr_for_mut_ref(stack_ptr)?;
    let item = sanitize_const_ptr_for_ref(item_ptr)?;
    stack.stack.push(item.clone());
    Ok(SSL_SUCCESS)
}

/// `sk_X509_free` - frees up the sk structure. After this call sk is no longer
/// valid.
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// void sk_X509_free(const STACK_OF(X509) *sk);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_free(stack_ptr: *mut STACK_X509) {
    let _ = check_inner_result!(inner_sk_X509_free(stack_ptr), SSL_FAILURE);
}

#[allow(non_snake_case)]
fn inner_sk_X509_free(stack_ptr: *mut STACK_X509) -> InnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(stack_ptr)?;
    let _ = unsafe { Box::from_raw(stack_ptr) };
    Ok(SSL_SUCCESS)
}

// ---------------------------------------
// STACK for X509_NAME
// ---------------------------------------

/// An OpenSSL STACK_OF(X509_NAME) object
#[allow(non_camel_case_types)]
pub struct STACK_X509_NAME {
    magic: [u8; MAGIC_SIZE],
    pub(crate) stack: Vec<X509_NAME>,
}

impl OpaquePointerGuard for STACK_X509_NAME {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl STACK_X509_NAME {
    pub fn new(names: Vec<X509_NAME>) -> STACK_X509_NAME {
        STACK_X509_NAME {
            magic: *MAGIC,
            stack: names,
        }
    }
}

/// `sk_X509_NAME_new_null` - allocates a new stack of X509_NAME.
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// STACK_OF(X509_NAME) *sk_X509_NAME_new_null(void);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_NAME_new_null() -> *mut STACK_X509_NAME {
    let stack = STACK_X509_NAME::new(vec![]);
    Box::into_raw(Box::new(stack)) as *mut STACK_X509_NAME
}

/// `sk_X509_NAME_num` - returns the number of elements in sk or -1 if sk is NULL..
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// int sk_X509_NAME_num(const STACK_OF(X509_NAME) *sk);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_NAME_num(stack_ptr: *const STACK_X509_NAME) -> c_int {
    check_inner_result!(inner_sk_X509_NAME_num(stack_ptr), SSL_FAILURE)
}

#[allow(non_snake_case)]
fn inner_sk_X509_NAME_num(stack_ptr: *const STACK_X509_NAME) -> InnerResult<c_int> {
    let stack = sanitize_const_ptr_for_ref(stack_ptr)?;
    Ok(stack.stack.len() as c_int)
}

/// `sk_X509_NAME_value` - returns element idx in sk, where idx starts at zero.
/// If idx is out of range then NULL is returned.
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// X509_NAME *sk_X509_NAME_value(const STACK_OF(X509_NAME) *sk, int idx);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_NAME_value(
    stack_ptr: *const STACK_X509_NAME,
    index: c_int,
) -> *const X509_NAME {
    check_inner_result!(inner_sk_X509_NAME_value(stack_ptr, index), ptr::null())
}

#[allow(non_snake_case)]
fn inner_sk_X509_NAME_value(
    stack_ptr: *const STACK_X509_NAME,
    index: c_int,
) -> InnerResult<*const X509_NAME> {
    let stack = sanitize_const_ptr_for_ref(stack_ptr)?;
    let item = stack.stack.get(index as usize).ok_or(Error::BadFuncArg)?;
    Ok(item as *const X509_NAME)
}

/// `sk_X509_NAME_push` - appends ptr to sk.
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// int sk_X509_NAME_push(STACK_OF(X509_NAME) *sk, const X509_NAME *ptr);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_NAME_push(
    stack_ptr: *mut STACK_X509_NAME,
    item_ptr: *const X509_NAME,
) -> c_int {
    check_inner_result!(inner_sk_X509_NAME_push(stack_ptr, item_ptr), SSL_FAILURE)
}

#[allow(non_snake_case)]
fn inner_sk_X509_NAME_push(
    stack_ptr: *mut STACK_X509_NAME,
    item_ptr: *const X509_NAME,
) -> InnerResult<c_int> {
    let stack = sanitize_ptr_for_mut_ref(stack_ptr)?;
    let item = sanitize_const_ptr_for_ref(item_ptr)?;
    stack.stack.push(item.clone());
    Ok(SSL_SUCCESS)
}

/// `sk_X509_NAME_free` - frees up the sk structure. After this call sk is no longer
/// valid.
///
/// ```c
/// #include <tabbyssl/openssl/safestack.h>
///
/// void sk_X509_NAME_free(const STACK_OF(X509_NAME) *sk);
/// ```
#[no_mangle]
pub extern "C" fn sk_X509_NAME_free(stack_ptr: *mut STACK_X509_NAME) {
    let _ = check_inner_result!(inner_sk_X509_NAME_free(stack_ptr), SSL_FAILURE);
}

#[allow(non_snake_case)]
fn inner_sk_X509_NAME_free(stack_ptr: *mut STACK_X509_NAME) -> InnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(stack_ptr)?;
    let _ = unsafe { Box::from_raw(stack_ptr) };
    Ok(SSL_SUCCESS)
}
