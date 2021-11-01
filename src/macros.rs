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

// A utility macro that wraps each inner API implementation and checks its
// returned value. This macro also catches panics and prevents unwinding across
// FFI boundaries. Note that the panic mode must be set to `unwind` in
// Cargo.toml.
#[doc(hidden)]
#[macro_export]
macro_rules! check_inner_result {
    ($inner:expr, $err_ret:expr) => {{
        use crate::libssl::err::{Error, ErrorQueue};
        use std::panic;
        match panic::catch_unwind(panic::AssertUnwindSafe(|| $inner))
            .unwrap_or_else(|_| Err(Error::Panic))
        {
            Ok(r) => r,
            Err(e) => {
                ErrorQueue::push_error(e);
                $err_ret
            }
        }
    }};
}
