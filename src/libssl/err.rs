/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 */

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use thiserror::Error as ThisError;

thread_local! {
    static ERROR_QUEUE: RefCell<VecDeque<Error>> = RefCell::new(VecDeque::new());
}

#[derive(ThisError, Clone, Debug)]
pub enum Error {
    #[error("No error")]
    None,
    #[error("NULL pointer")]
    NullPointer,
    #[error("Malformed objects")]
    MalformedObject,
    #[error("Invalid function arguments")]
    BadFuncArg,
    #[error("Paniked at FFI boundary")]
    Panic,
    #[error("I/O error: {0:?}")]
    Io(io::ErrorKind),
    #[error("TLS error: {0:?}")]
    Tls(#[from] rustls::Error),
}

#[doc(hidden)]
#[repr(C)]
#[derive(PartialEq, Clone)]
#[allow(dead_code)]
pub enum ErrorCode {
    None = 0,
    Ssl = 1,
    WantRead = 2,
    WantWrite = 3,
    X509Lookup = 4,
    Syscall = 5,
    ZeroReturn = 6,
    WantConnect = 7,
    WantAccept = 8,
    InvalidInput = 9,
}

#[doc(hidden)]
pub(crate) type InnerResult<T> = Result<T, Error>;

/// `ERR_load_error_strings` - compatibility only
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void ERR_load_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn ERR_load_error_strings() {
    // compatibility only
}

/// `ERR_free_error_strings` - compatibility only
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void SSL_free_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn ERR_free_error_strings() {
    // compatibility only
}

#[doc(hidden)]
pub(crate) struct ErrorQueue {}

impl ErrorQueue {
    pub fn push_error(e: Error) {
        ERROR_QUEUE.with(|q| {
            q.borrow_mut().push_back(e);
        });
    }
}

/// `ERR_clear_error` - empty the current thread's error queue.
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void ERR_clear_error(void);
/// ```
#[no_mangle]
pub extern "C" fn ERR_clear_error() {
    ERROR_QUEUE.with(|q| {
        q.borrow_mut().clear();
    });
}

/// `ERR_print_errors_fp` - a convenience function that prints the error
/// strings for all errors that OpenSSL has recorded to `fp`, thus emptying the
/// error queue.
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void ERR_print_errors_fp(FILE *fp);
/// ```
///
/// # Safety
/// This API is Rust-unsafe because it dereferences a pointer provided by users
/// Use with caution!
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors_fp(fp: *mut libc::FILE) {
    use crate::libcrypto::bio::FromFileStream;
    use std::fs;
    use std::io::Write;
    if fp.is_null() {
        return;
    }
    let fd = libc::fileno(fp);
    if fd < 0 {
        return;
    }
    let mut file = fs::File::from_file_stream(fp);
    ERROR_QUEUE.with(|q| {
        let mut queue = q.borrow_mut();
        for e in queue.drain(0..) {
            let error_string = format!("error:[tabbyssl]:[{:?}]\n", e);
            let _ = file.write(error_string.as_bytes());
        }
    });
}

#[cfg(test)]
mod tests {}
