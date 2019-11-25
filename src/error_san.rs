/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

use crate::libssl::err::{MesalinkBuiltinError, MesalinkInnerResult};
use crate::OpaquePointerGuard;

pub(crate) fn sanitize_const_ptr_for_ref<'a, T>(ptr: *const T) -> MesalinkInnerResult<&'a T>
where
    T: OpaquePointerGuard,
{
    let ptr = ptr as *mut T;
    sanitize_ptr_for_mut_ref(ptr).map(|r| r as &'a T)
}
pub(crate) fn sanitize_ptr_for_ref<'a, T>(ptr: *mut T) -> MesalinkInnerResult<&'a T>
where
    T: OpaquePointerGuard,
{
    sanitize_ptr_for_mut_ref(ptr).map(|r| r as &'a T)
}
pub(crate) fn sanitize_ptr_for_mut_ref<'a, T>(ptr: *mut T) -> MesalinkInnerResult<&'a mut T>
where
    T: OpaquePointerGuard,
{
    if ptr.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    let obj_ref: &mut T = unsafe { &mut *ptr };
    if obj_ref.check_magic() {
        Ok(obj_ref)
    } else {
        Err(error!(MesalinkBuiltinError::MalformedObject.into()))
    }
}
