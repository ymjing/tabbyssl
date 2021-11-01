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

use crate::libssl::err::{Error, InnerResult};
use crate::OpaquePointerGuard;

pub(crate) fn sanitize_const_ptr_for_ref<'a, T>(ptr: *const T) -> InnerResult<&'a T>
where
    T: OpaquePointerGuard,
{
    let ptr = ptr as *mut T;
    sanitize_ptr_for_mut_ref(ptr).map(|r| r as &'a T)
}

pub(crate) fn sanitize_ptr_for_ref<'a, T>(ptr: *mut T) -> InnerResult<&'a T>
where
    T: OpaquePointerGuard,
{
    sanitize_ptr_for_mut_ref(ptr).map(|r| r as &'a T)
}

pub(crate) fn sanitize_ptr_for_mut_ref<'a, T>(ptr: *mut T) -> InnerResult<&'a mut T>
where
    T: OpaquePointerGuard,
{
    if ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let obj_ref: &mut T = unsafe { &mut *ptr };
    if obj_ref.check_magic() {
        Ok(obj_ref)
    } else {
        Err(Error::MalformedObject)
    }
}
