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
use crate::libssl::err::{MesalinkBuiltinError, MesalinkInnerResult};
use crate::{MesalinkOpaquePointerType, MAGIC, MAGIC_SIZE};
use libc::{c_char, c_int, c_long, c_void};
use std::{ffi, fs, io, mem, ptr, slice};

// Trait imports
use std::io::{Read, Seek, Write};
use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle};

#[doc(hidden)]
pub trait BioRW: Read + Write + Seek {}
impl<T> BioRW for T where T: Read + Write + Seek + ?Sized {}

////////////////////////////////////////////////////
///
/// BIO inner for file BIO and MEM bio
///
/// ////////////////////////////////////////////////

#[doc(hidden)]
pub enum MesalinkBioInner<'a> {
    File(fs::File),
    Mem(io::Cursor<&'a mut [u8]>),
    Unspecified,
}

impl<'a> Deref for MesalinkBioInner<'a> {
    type Target = dyn BioRW + 'a;

    fn deref(&self) -> &Self::Target {
        unreachable!()
    }
}

impl<'a> DerefMut for MesalinkBioInner<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            MesalinkBioInner::File(ref mut f) => f,
            MesalinkBioInner::Mem(ref mut m) => m,
            _ => unimplemented!(),
        }
    }
}

/// A structure used for the implementation of new BIO types
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(PartialEq)]
pub enum MESALINK_BIO_METHOD {
    File,
    Mem,
    Unspecified,
}

static MESALINK_BIO_METHOD_FILE: MESALINK_BIO_METHOD = MESALINK_BIO_METHOD::File;
static MESALINK_BIO_METHOD_MEM: MESALINK_BIO_METHOD = MESALINK_BIO_METHOD::Mem;

#[doc(hidden)]
#[allow(non_camel_case_types)]
pub struct MesalinkBioFunctions<'a> {
    pub read: Box<dyn Fn(&mut MesalinkBioInner<'a>, &mut [u8]) -> io::Result<usize>>,
    pub write: Box<dyn Fn(&mut MesalinkBioInner<'a>, &[u8]) -> io::Result<usize>>,
    pub gets: Box<dyn Fn(&mut MesalinkBioInner<'a>, &mut [u8]) -> io::Result<usize>>,
    pub puts: Box<dyn Fn(&mut MesalinkBioInner<'a>, &[u8]) -> io::Result<usize>>,
}

fn generic_read<'a>(b: &mut MesalinkBioInner<'a>, buf: &mut [u8]) -> io::Result<usize> {
    b.read(buf)
}

fn generic_write<'a>(b: &mut MesalinkBioInner<'a>, buf: &[u8]) -> io::Result<usize> {
    b.write(buf)
}

fn file_gets<'a>(inner: &mut MesalinkBioInner<'a>, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let file_bytes = if let MesalinkBioInner::File(ref mut f) = inner {
        f.bytes()
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, "BIO not supported"));
    };
    let mut pos = 0usize;
    for byte in file_bytes.take(buf.len() - 1) {
        let b = byte?;
        if b == b'\0' || b == b'\n' {
            break;
        }
        buf[pos] = b;
        pos += 1;
    }
    buf[pos] = b'\0';
    Ok(pos + 1) // include '\0' at the end
}

fn mem_gets<'a>(inner: &mut MesalinkBioInner<'a>, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let mem_bytes = if let MesalinkBioInner::Mem(ref mut m) = inner {
        m.bytes()
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, "BIO not supported"));
    };
    let mut pos = 0usize;
    for byte in mem_bytes.take(buf.len() - 1) {
        let b = byte?;
        if b == b'\0' || b == b'\n' {
            break;
        }
        buf[pos] = b;
        pos += 1;
    }
    buf[pos] = b'\0';
    Ok(pos + 1) // include '\0' at the end
}

impl<'a> From<&MESALINK_BIO_METHOD> for MesalinkBioFunctions<'a> {
    fn from(m: &MESALINK_BIO_METHOD) -> MesalinkBioFunctions<'a> {
        let gets = match *m {
            MESALINK_BIO_METHOD::File => file_gets,
            MESALINK_BIO_METHOD::Mem => mem_gets,
            _ => unimplemented!(),
        };
        MesalinkBioFunctions {
            read: Box::new(generic_read),
            write: Box::new(generic_write),
            gets: Box::new(gets),
            puts: Box::new(generic_write),
        }
    }
}

////////////////////////////////////////////////////
///
/// BIO
///
/// ////////////////////////////////////////////////
use bitflags::bitflags;
bitflags! {
    #[derive(Default)]
    struct BioFlags: u32 {
        const BIO_NOCLOSE = 0x00;
        const BIO_CLOSE   = 0x01;
        const BIO_FLAGS_MEM_RDONLY = 0x200;
        const BIO_FLAGS_NONCLEAR_RST = 0x400;
    }
}

/// An I/O abstraction, it hides many of the underlying I/O details from an
/// application.
#[allow(non_camel_case_types)]
pub struct MESALINK_BIO<'a> {
    magic: [u8; MAGIC_SIZE],
    inner: MesalinkBioInner<'a>,
    method: MesalinkBioFunctions<'a>,
    flags: BioFlags,
}

impl<'a> MesalinkOpaquePointerType for MESALINK_BIO<'a> {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl<'a> MESALINK_BIO<'a> {
    fn is_initialized(&self) -> bool {
        match self.inner {
            MesalinkBioInner::File(_) | MesalinkBioInner::Mem(_) => true,
            _ => false,
        }
    }
}

impl<'a> Read for MESALINK_BIO<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a> Write for MESALINK_BIO<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> Seek for MESALINK_BIO<'a> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// `BIO_new()` returns a new BIO using method `type`
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO *BIO_new(BIO_METHOD *type);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_new<'a>(
    method_ptr: *const MESALINK_BIO_METHOD,
) -> *mut MESALINK_BIO<'a> {
    check_inner_result!(inner_mesalink_bio_new(method_ptr), ptr::null_mut())
}

fn inner_mesalink_bio_new<'a>(
    method_ptr: *const MESALINK_BIO_METHOD,
) -> MesalinkInnerResult<*mut MESALINK_BIO<'a>> {
    if method_ptr.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    if method_ptr != (&MESALINK_BIO_METHOD_FILE as *const MESALINK_BIO_METHOD)
        && method_ptr != (&MESALINK_BIO_METHOD_MEM as *const MESALINK_BIO_METHOD)
    {
        return Err(error!(MesalinkBuiltinError::BadFuncArg.into()));
    }
    let method = unsafe { &*method_ptr };
    let bio = MESALINK_BIO {
        magic: *MAGIC,
        inner: MesalinkBioInner::Unspecified,
        method: method.into(),
        flags: BioFlags::BIO_CLOSE,
    };
    let bio_ptr = Box::into_raw(Box::new(bio)) as *mut MESALINK_BIO<'_>;
    Ok(bio_ptr)
}

/// `BIO_free()` frees a BIO
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// int BIO_free(BIO *a);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_free(bio_ptr: *mut MESALINK_BIO<'_>) {
    let _ = check_inner_result!(inner_mesalink_bio_free(bio_ptr), CRYPTO_FAILURE);
}

fn inner_mesalink_bio_free(bio_ptr: *mut MESALINK_BIO<'_>) -> MesalinkInnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(bio_ptr)?;
    let mut bio = unsafe { Box::from_raw(bio_ptr) };
    let inner = mem::replace(&mut bio.inner, MesalinkBioInner::Unspecified);
    if BioFlags::BIO_NOCLOSE == bio.flags & BioFlags::BIO_NOCLOSE {
        if let MesalinkBioInner::File(f) = inner {
            #[cfg(unix)]
            let _ = f.into_raw_fd();
            #[cfg(windows)]
            let _ = f.into_raw_handle();
        }
    }
    Ok(CRYPTO_SUCCESS)
}

/// `BIO_read` attempts to read *len* bytes from BIO *b* and places the data in
/// *buf*。
///
/// ```c
/// #include <openssl/bio.h>
///
/// int BIO_read(BIO *b, void *buf, int len);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_read(
    bio_ptr: *mut MESALINK_BIO<'_>,
    buf_ptr: *mut c_void,
    len: c_int,
) -> c_int {
    check_inner_result!(inner_mesalink_bio_read(bio_ptr, buf_ptr, len), -1)
}

fn inner_mesalink_bio_read(
    bio_ptr: *mut MESALINK_BIO<'_>,
    buf_ptr: *mut c_void,
    len: c_int,
) -> MesalinkInnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    if !bio.is_initialized() {
        // Mem or file not assigned yet
        return Err(error!(MesalinkBuiltinError::BadFuncArg.into()));
    }
    if buf_ptr.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    let buf_ptr = buf_ptr as *mut u8;
    let mut buf = unsafe { slice::from_raw_parts_mut(buf_ptr, len as usize) };
    let read_fn = &bio.method.read;
    let ret = read_fn(&mut bio.inner, &mut buf).map_err(|e| error!(e.into()))?;
    Ok(ret as c_int)
}

/// `BIO_gets` attempts to read a line of data from the BIO *b* of maximum
/// length *len* and places teh data in *buf*.
/// ```c
/// #include <openssl/bio.h>
///
/// int BIO_gets(BIO *b, char *buf, int size);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_gets(
    bio_ptr: *mut MESALINK_BIO<'_>,
    buf_ptr: *mut c_char,
    size: c_int,
) -> c_int {
    check_inner_result!(inner_mesalink_bio_gets(bio_ptr, buf_ptr, size), -1)
}

fn inner_mesalink_bio_gets(
    bio_ptr: *mut MESALINK_BIO<'_>,
    buf_ptr: *mut c_char,
    size: c_int,
) -> MesalinkInnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    if !bio.is_initialized() {
        // Mem or file not assigned yet
        return Err(error!(MesalinkBuiltinError::BadFuncArg.into()));
    }
    if buf_ptr.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    let buf_ptr = buf_ptr as *mut u8;
    let mut buf = unsafe { slice::from_raw_parts_mut(buf_ptr, size as usize) };
    let gets_fn = &bio.method.gets;
    let ret = gets_fn(&mut bio.inner, &mut buf).map_err(|e| error!(e.into()))?;
    Ok(ret as c_int)
}

/// `BIO_write` attempts to write *len* bytes from *buf* to BIO *b*.
///
/// ```c
/// #include <openssl/bio.h>
///
/// int BIO_write(BIO *b, void *buf, int len);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_write(
    bio_ptr: *mut MESALINK_BIO<'_>,
    buf_ptr: *const c_void,
    len: c_int,
) -> c_int {
    check_inner_result!(inner_mesalink_bio_write(bio_ptr, buf_ptr, len), -1)
}

fn inner_mesalink_bio_write(
    bio_ptr: *mut MESALINK_BIO<'_>,
    buf_ptr: *const c_void,
    len: c_int,
) -> MesalinkInnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    if !bio.is_initialized() {
        // Mem or file not assigned yet
        return Err(error!(MesalinkBuiltinError::BadFuncArg.into()));
    }
    if buf_ptr.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    let buf_ptr = buf_ptr as *const u8;
    let buf = unsafe { slice::from_raw_parts(buf_ptr, len as usize) };
    let write_fn = &bio.method.write;
    let ret = write_fn(&mut bio.inner, &buf).map_err(|e| error!(e.into()))?;
    Ok(ret as c_int)
}

/// `BIO_puts` attempts to write a null terminated string *buf* to BIO *b*.
///
/// ```c
/// #include <openssl/bio.h>
///
/// int BIO_puts(BIO *b, const char *buf);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_puts(
    bio_ptr: *mut MESALINK_BIO<'_>,
    buf_ptr: *const c_char,
) -> c_int {
    check_inner_result!(inner_mesalink_bio_puts(bio_ptr, buf_ptr), -1)
}

fn inner_mesalink_bio_puts(
    bio_ptr: *mut MESALINK_BIO<'_>,
    buf_ptr: *const c_char,
) -> MesalinkInnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    if !bio.is_initialized() {
        // Mem or file not assigned yet
        return Err(error!(MesalinkBuiltinError::BadFuncArg.into()));
    }
    if buf_ptr.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    let strlen = unsafe { libc::strlen(buf_ptr) };
    let buf_ptr = buf_ptr as *const u8;
    let buf = unsafe { slice::from_raw_parts(buf_ptr, strlen + 1) };
    let puts_fn = &bio.method.puts;
    let ret = puts_fn(&mut bio.inner, &buf).map_err(|e| error!(e.into()))?;
    Ok(ret as c_int)
}

/// `BIO_s_file()` returns the BIO file method.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO_METHOD *BIO_s_file(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_s_file() -> *const MESALINK_BIO_METHOD {
    &MESALINK_BIO_METHOD_FILE as *const MESALINK_BIO_METHOD
}

/// `BIO_new_file()` creates a new file BIO with mode mode the meaning of mode
/// is the same as the stdio function fopen(). The BIO_CLOSE flag is set on the
/// returned BIO.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO *BIO_new_file(const char *filename, const char *mode);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_new_file<'a>(
    filename_ptr: *const c_char,
    mode_ptr: *const c_char,
) -> *mut MESALINK_BIO<'a> {
    check_inner_result!(
        inner_mesalink_bio_new_filename(filename_ptr, mode_ptr),
        ptr::null_mut()
    )
}

fn inner_mesalink_bio_new_filename<'a>(
    filename_ptr: *const c_char,
    mode_ptr: *const c_char,
) -> MesalinkInnerResult<*mut MESALINK_BIO<'a>> {
    let file = open_file_from_filename_and_mode(filename_ptr, mode_ptr)?;
    let bio = MESALINK_BIO {
        magic: *MAGIC,
        inner: MesalinkBioInner::File(file),
        method: (&MESALINK_BIO_METHOD_FILE).into(),
        flags: BioFlags::BIO_CLOSE,
    };
    Ok(Box::into_raw(Box::new(bio)) as *mut MESALINK_BIO<'_>)
}

fn open_file_from_filename_and_mode(
    filename_ptr: *const c_char,
    mode_ptr: *const c_char,
) -> MesalinkInnerResult<fs::File> {
    if filename_ptr.is_null() || mode_ptr.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    let mode = unsafe {
        ffi::CStr::from_ptr(mode_ptr)
            .to_str()
            .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?
    };
    let mut open_mode = fs::OpenOptions::new();
    let open_mode = match mode {
        "r" | "rb" => open_mode.read(true),
        "w" | "wb" => open_mode.write(true).create(true).truncate(true),
        "a" | "ab" => open_mode.write(true).create(true).append(true),
        "r+" | "r+b" | "rb+" => open_mode.read(true).write(true),
        "w+" | "w+b" | "wb+" => open_mode.read(true).write(true).create(true).truncate(true),
        "a+" | "a+b" | "ab+" => open_mode.read(true).write(true).create(true).append(true),
        _ => return Err(error!(MesalinkBuiltinError::BadFuncArg.into())),
    };
    let filename = unsafe {
        ffi::CStr::from_ptr(filename_ptr)
            .to_str()
            .map_err(|_| error!(MesalinkBuiltinError::BadFuncArg.into()))?
    };
    open_mode.open(filename).map_err(|e| error!(e.into()))
}

/// `BIO_read_filename()` sets the file BIO b to use file name for reading.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO *BIO_read_file(const char *filename);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_read_filename(
    bio_ptr: *mut MESALINK_BIO<'_>,
    filename_ptr: *const c_char,
) -> c_int {
    check_inner_result!(
        inner_mesalink_bio_set_filename(bio_ptr, filename_ptr, b"r\0".as_ptr() as *const c_char),
        CRYPTO_FAILURE
    )
}

fn inner_mesalink_bio_set_filename(
    bio_ptr: *mut MESALINK_BIO<'_>,
    filename_ptr: *const c_char,
    mode_ptr: *const c_char,
) -> MesalinkInnerResult<c_int> {
    let file = open_file_from_filename_and_mode(filename_ptr, mode_ptr)?;
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    bio.inner = MesalinkBioInner::File(file);
    Ok(CRYPTO_SUCCESS)
}

/// `BIO_write_filename()` sets the file BIO b to use file name for writing.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO *BIO_write_file(const char *filename);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_write_filename(
    bio_ptr: *mut MESALINK_BIO<'_>,
    filename_ptr: *const c_char,
) -> c_int {
    check_inner_result!(
        inner_mesalink_bio_set_filename(bio_ptr, filename_ptr, b"w\0".as_ptr() as *const c_char),
        CRYPTO_FAILURE
    )
}

/// `BIO_append_filename()` sets the file BIO b to use file name for appending.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO *BIO_append_filename(const char *filename);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_append_filename(
    bio_ptr: *mut MESALINK_BIO<'_>,
    filename_ptr: *const c_char,
) -> c_int {
    check_inner_result!(
        inner_mesalink_bio_set_filename(bio_ptr, filename_ptr, b"a\0".as_ptr() as *const c_char),
        CRYPTO_FAILURE
    )
}

/// `BIO_rw_filename()` sets the file BIO b to use file name for reading and
/// writing.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO *BIO_rw_file(const char *filename);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_rw_filename(
    bio_ptr: *mut MESALINK_BIO<'_>,
    filename_ptr: *const c_char,
) -> c_int {
    check_inner_result!(
        inner_mesalink_bio_set_filename(bio_ptr, filename_ptr, b"r+\0".as_ptr() as *const c_char),
        CRYPTO_FAILURE
    )
}

/// `BIO_new_fp()` screates a file BIO wrapping `stream`
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO *BIO_new_fp(FILE *stream, int flags);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_new_fp<'a>(
    stream: *mut libc::FILE,
    flags: c_int,
) -> *mut MESALINK_BIO<'a> {
    check_inner_result!(inner_mesalink_bio_new_fp(stream, flags), ptr::null_mut())
}

fn inner_mesalink_bio_new_fp<'a>(
    stream: *mut libc::FILE,
    flags: c_int,
) -> MesalinkInnerResult<*mut MESALINK_BIO<'a>> {
    if stream.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    let file = unsafe { fs::File::from_file_stream(stream) };
    let flags =
        BioFlags::from_bits(flags as u32).ok_or(error!(MesalinkBuiltinError::BadFuncArg.into()))?;
    let bio = MESALINK_BIO {
        magic: *MAGIC,
        inner: MesalinkBioInner::File(file),
        method: (&MESALINK_BIO_METHOD_FILE).into(),
        flags,
    };
    Ok(Box::into_raw(Box::new(bio)) as *mut MESALINK_BIO<'_>)
}

/// `BIO_set_fp()` sets the fp of a file BIO to `fp`.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO_set_fp(BIO *b,FILE *fp, int flags);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_set_fp(
    bio_ptr: *mut MESALINK_BIO<'_>,
    fp: *mut libc::FILE,
    flags: c_int,
) {
    let _ = check_inner_result!(
        inner_mesalink_bio_set_fp(bio_ptr, fp, flags),
        CRYPTO_FAILURE
    );
}

fn inner_mesalink_bio_set_fp(
    bio_ptr: *mut MESALINK_BIO<'_>,
    fp: *mut libc::FILE,
    flags: c_int,
) -> MesalinkInnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    let file = unsafe { fs::File::from_file_stream(fp) };
    let flags =
        BioFlags::from_bits(flags as u32).ok_or(error!(MesalinkBuiltinError::BadFuncArg.into()))?;
    bio.inner = MesalinkBioInner::File(file);
    bio.flags = flags;
    Ok(CRYPTO_SUCCESS)
}

/// `BIO_get_close()` returns the BIOs close flag.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// int BIO_get_close(BIO *b);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_get_close(bio_ptr: *mut MESALINK_BIO<'_>) -> c_int {
    check_inner_result!(
        inner_mesalink_bio_get_close(bio_ptr),
        BioFlags::default().bits() as c_int
    )
}

fn inner_mesalink_bio_get_close(bio_ptr: *mut MESALINK_BIO<'_>) -> MesalinkInnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    Ok(bio.flags.bits() as c_int)
}

/// `BIO_set_close()` sets the BIO *b* close flag to *flag*
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// int BIO_set_close(BIO *b, long flag);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_set_close(bio_ptr: *mut MESALINK_BIO<'_>, flag: c_long) -> c_int {
    let _ = check_inner_result!(
        inner_mesalink_bio_set_close(bio_ptr, flag),
        BioFlags::default().bits() as c_int
    );
    CRYPTO_SUCCESS
}

fn inner_mesalink_bio_set_close(
    bio_ptr: *mut MESALINK_BIO<'_>,
    flag: c_long,
) -> MesalinkInnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    let flag =
        BioFlags::from_bits(flag as u32).ok_or(error!(MesalinkBuiltinError::BadFuncArg.into()))?;
    bio.flags = flag;
    Ok(CRYPTO_SUCCESS)
}

/// `BIO_s_file()` returns the BIO memory method.
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO_METHOD *BIO_s_mem(void);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_s_mem() -> *const MESALINK_BIO_METHOD {
    &MESALINK_BIO_METHOD_MEM as *const MESALINK_BIO_METHOD
}

/// `BIO_new_mem_buf()` creates a memory BIO using `len` bytes of data at `buf`
///
/// ```c
/// #include <mesalink/openssl/bio.h>
///
/// BIO *BIO_new_mem_buf(const void *buf, int len);
/// ```
#[no_mangle]
pub extern "C" fn mesalink_BIO_new_mem_buf<'a>(
    buf_ptr: *mut c_void,
    len: c_int,
) -> *mut MESALINK_BIO<'a> {
    if buf_ptr.is_null() {
        return ptr::null_mut();
    }
    let buflen = if len < 0 {
        unsafe { libc::strlen(buf_ptr as *const c_char) }
    } else {
        len as usize
    };
    let buf_ptr = buf_ptr as *mut u8;
    let buf = unsafe { slice::from_raw_parts_mut(buf_ptr, buflen) };
    let bio = MESALINK_BIO {
        magic: *MAGIC,
        inner: MesalinkBioInner::Mem(io::Cursor::new(buf)),
        method: (&MESALINK_BIO_METHOD_MEM).into(),
        flags: BioFlags::default(), // TODO: support BIO_FLAGS_MEM_RDONLY
    };
    Box::into_raw(Box::new(bio)) as *mut MESALINK_BIO<'_>
}

/// Helper trait for converting from FILE* in libc.
pub(crate) trait FromFileStream {
    unsafe fn from_file_stream(stream: *mut libc::FILE) -> Self;
}

#[cfg(unix)]
impl<T: FromRawFd> FromFileStream for T {
    unsafe fn from_file_stream(stream: *mut libc::FILE) -> Self {
        Self::from_raw_fd(libc::fileno(stream))
    }
}

#[cfg(windows)]
impl<T: FromRawHandle> FromFileStream for T {
    unsafe fn from_file_stream(stream: *mut libc::FILE) -> Self {
        let fd = libc::fileno(stream);
        let osf_handle = libc::get_osfhandle(fd);
        Self::from_raw_handle(osf_handle as *mut _)
    }
}

/// Helper trait for converting to FILE* in libc.
pub(crate) trait OpenFileStream {
    unsafe fn open_file_stream_r(&self) -> *mut libc::FILE;

    unsafe fn open_file_stream_w(&self) -> *mut libc::FILE;
}

#[cfg(unix)]
impl<T: AsRawFd> OpenFileStream for T {
    unsafe fn open_file_stream_r(&self) -> *mut libc::FILE {
        libc::fdopen(self.as_raw_fd(), b"r\0".as_ptr() as *const c_char)
    }

    unsafe fn open_file_stream_w(&self) -> *mut libc::FILE {
        libc::fdopen(self.as_raw_fd(), b"w\0".as_ptr() as *const c_char)
    }
}

#[cfg(windows)]
impl<T: AsRawHandle> OpenFileStream for T {
    unsafe fn open_file_stream_r(&self) -> *mut libc::FILE {
        let handle = self.as_raw_handle();
        match libc::open_osfhandle(handle as libc::intptr_t, 0) {
            -1 => ptr::null_mut(),
            fd => libc::fdopen(fd, b"r\0".as_ptr() as *const c_char),
        }
    }

    unsafe fn open_file_stream_w(&self) -> *mut libc::FILE {
        let handle = self.as_raw_handle();
        match libc::open_osfhandle(handle as libc::intptr_t, 0) {
            -1 => ptr::null_mut(),
            fd => libc::fdopen(fd, b"w\0".as_ptr() as *const c_char),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::{self, c_char, c_void};
    use std::fs;

    #[test]
    fn bio_methods() {
        assert_ne!(mesalink_BIO_s_file(), ptr::null());
        assert_ne!(mesalink_BIO_s_mem(), ptr::null());
    }

    #[test]
    fn bio_create_from_method() {
        let bio_ptr_f = mesalink_BIO_new(mesalink_BIO_s_mem());
        assert_ne!(bio_ptr_f, ptr::null_mut());
        mesalink_BIO_free(bio_ptr_f);
        let bio_ptr_m = mesalink_BIO_new(mesalink_BIO_s_file());
        assert_ne!(bio_ptr_m, ptr::null_mut());
        mesalink_BIO_free(bio_ptr_m);
    }

    #[test]
    fn bio_null_ptr() {
        let bio_ptr = mesalink_BIO_new(ptr::null());
        assert_eq!(bio_ptr, ptr::null_mut());

        let invalid_method_ptr = "hello".as_ptr() as *const MESALINK_BIO_METHOD;
        let bio_ptr = mesalink_BIO_new(invalid_method_ptr);
        assert_eq!(bio_ptr, ptr::null_mut());
    }

    #[test]
    fn bio_uninitialized() {
        let bio_ptr = mesalink_BIO_new(mesalink_BIO_s_mem());
        let buf_ptr = [0u8; 32].as_ptr() as *mut c_void;
        let len = mesalink_BIO_read(bio_ptr, buf_ptr, 32);
        assert_eq!(-1, len);
        let len = mesalink_BIO_write(bio_ptr, buf_ptr, 32);
        assert_eq!(-1, len);
        let buf_ptr = buf_ptr as *mut c_char;
        let len = mesalink_BIO_gets(bio_ptr, buf_ptr, 32);
        assert_eq!(-1, len);
        let len = mesalink_BIO_puts(bio_ptr, buf_ptr);
        assert_eq!(-1, len);
        mesalink_BIO_free(bio_ptr);
    }

    #[test]
    fn bio_null_buf() {
        let bio_ptr = mesalink_BIO_new_mem_buf(ptr::null_mut(), 10);
        assert_eq!(bio_ptr, ptr::null_mut());
        let bio_ptr = mesalink_BIO_new_mem_buf(b"hello\0".as_ptr() as *mut c_void, -1);
        let buf_ptr = ptr::null_mut() as *mut c_void;
        let len = mesalink_BIO_read(bio_ptr, buf_ptr, 5);
        assert_eq!(-1, len);
        let len = mesalink_BIO_write(bio_ptr, buf_ptr, 5);
        assert_eq!(-1, len);
        let buf_ptr = buf_ptr as *mut c_char;
        let len = mesalink_BIO_gets(bio_ptr, buf_ptr, 5);
        assert_eq!(-1, len);
        let len = mesalink_BIO_puts(bio_ptr, buf_ptr);
        assert_eq!(-1, len);
        mesalink_BIO_free(bio_ptr);
    }

    #[test]
    fn bio_mem() {
        let buf = [0u8; 10];
        let bio_ptr_m = mesalink_BIO_new_mem_buf(buf.as_ptr() as *mut c_void, 10);
        assert_ne!(bio_ptr_m, ptr::null_mut());
        let src = [1u8, 2, 3, 4, 5];
        let ret = mesalink_BIO_write(bio_ptr_m, src.as_ptr() as *const c_void, 5);
        assert_eq!(ret, 5);
        mesalink_BIO_free(bio_ptr_m);

        let buf = [1u8, 2, 3, 4, 5];
        let bio_ptr_m = mesalink_BIO_new_mem_buf(buf.as_ptr() as *mut c_void, 5);
        let dst = [0u8; 10];
        let ret = mesalink_BIO_read(bio_ptr_m, dst.as_ptr() as *mut c_void, 5);
        assert_eq!(ret, 5);
        assert_eq!(dst, [1u8, 2, 3, 4, 5, 0, 0, 0, 0, 0]);
        mesalink_BIO_free(bio_ptr_m);

        let buf = [0u8; 10];
        let bio_ptr_m = mesalink_BIO_new_mem_buf(buf.as_ptr() as *mut c_void, 10);
        assert_ne!(bio_ptr_m, ptr::null_mut());
        let src = b"hello\0";
        let ret = mesalink_BIO_puts(bio_ptr_m, src.as_ptr() as *const c_char);
        assert_eq!(ret, 6);
        mesalink_BIO_free(bio_ptr_m);

        let buf = [1u8, 2, 0, 4, 5];
        let bio_ptr_m = mesalink_BIO_new_mem_buf(buf.as_ptr() as *mut c_void, 5);
        assert_ne!(bio_ptr_m, ptr::null_mut());
        let dst = [0u8; 5];
        let ret = mesalink_BIO_gets(bio_ptr_m, dst.as_ptr() as *mut c_char, 5);
        assert_eq!(ret, 3);
        assert_eq!(dst, [1u8, 2, 0, 0, 0]);
        mesalink_BIO_free(bio_ptr_m);
    }

    #[test]
    fn bio_file_new_fp() {
        let bio_ptr_f = mesalink_BIO_new_fp(ptr::null_mut(), 0);
        assert_eq!(bio_ptr_f, ptr::null_mut());

        let file = fs::File::open("tests/ca.cert").unwrap(); // Read-only, "r"
        let fp = unsafe { file.open_file_stream_r() };
        assert_ne!(fp, ptr::null_mut());

        let bio_ptr_f = mesalink_BIO_new_fp(fp, 0);
        assert_ne!(bio_ptr_f, ptr::null_mut());
        mesalink_BIO_free(bio_ptr_f);
    }

    #[test]
    fn bio_file_set_fp() {
        let file = fs::File::open("tests/ca.cert").unwrap(); // Read-only, "r"
        let fp = unsafe { file.open_file_stream_r() };
        assert_ne!(fp, ptr::null_mut());

        let bio_ptr_f = mesalink_BIO_new(mesalink_BIO_s_file());
        assert_ne!(bio_ptr_f, ptr::null_mut());
        assert_eq!(0x1, mesalink_BIO_get_close(bio_ptr_f)); // BIO_CLOSE by default
        mesalink_BIO_set_fp(bio_ptr_f, fp, 0);
        assert_eq!(0x0, mesalink_BIO_get_close(bio_ptr_f)); // BIO_NOCLOSE after set_fp
        assert_eq!(CRYPTO_SUCCESS, mesalink_BIO_set_close(bio_ptr_f, 0x0));
        let buf = [0u8; 1024];
        let ret = mesalink_BIO_gets(bio_ptr_f, buf.as_ptr() as *mut c_char, 1024);
        assert_eq!(ret, 28); // gets returns the first line
        mesalink_BIO_free(bio_ptr_f);
    }

    #[test]
    fn bio_file_new_from_path() {
        let path_ptr = b"tests/deleteme\0".as_ptr() as *const c_char;

        let bio_ptr_f = mesalink_BIO_new(mesalink_BIO_s_file());
        assert_ne!(bio_ptr_f, ptr::null_mut());

        let ret = mesalink_BIO_write_filename(bio_ptr_f, path_ptr);
        assert_eq!(ret, CRYPTO_SUCCESS);

        let ret = mesalink_BIO_rw_filename(bio_ptr_f, path_ptr);
        assert_eq!(ret, CRYPTO_SUCCESS);

        let ret = mesalink_BIO_read_filename(bio_ptr_f, path_ptr);
        assert_eq!(ret, CRYPTO_SUCCESS);

        let ret = mesalink_BIO_append_filename(bio_ptr_f, path_ptr);
        assert_eq!(ret, CRYPTO_SUCCESS);

        mesalink_BIO_free(bio_ptr_f);
        let _ = fs::remove_file("tests/deleteme");
    }
}
