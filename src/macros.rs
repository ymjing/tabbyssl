/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
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
