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

use crate::error_san::*;
use crate::libcrypto::{CRYPTO_FAILURE, CRYPTO_SUCCESS};
use crate::libssl::err::{Error, InnerResult};
use crate::{OpaquePointerGuard, MAGIC, MAGIC_SIZE};
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
pub enum BIO_METHOD {
    File,
    Mem,
    Unspecified,
}

static BIO_METHOD_FILE: BIO_METHOD = BIO_METHOD::File;
static BIO_METHOD_MEM: BIO_METHOD = BIO_METHOD::Mem;

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

impl<'a> From<&BIO_METHOD> for MesalinkBioFunctions<'a> {
    fn from(m: &BIO_METHOD) -> MesalinkBioFunctions<'a> {
        let gets = match *m {
            BIO_METHOD::File => file_gets,
            BIO_METHOD::Mem => mem_gets,
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
pub struct BIO<'a> {
    magic: [u8; MAGIC_SIZE],
    inner: MesalinkBioInner<'a>,
    method: MesalinkBioFunctions<'a>,
    flags: BioFlags,
}

impl<'a> OpaquePointerGuard for BIO<'a> {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl<'a> BIO<'a> {
    fn is_initialized(&self) -> bool {
        matches!(
            self.inner,
            MesalinkBioInner::File(_) | MesalinkBioInner::Mem(_)
        )
    }
}

impl<'a> Read for BIO<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a> Write for BIO<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> Seek for BIO<'a> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// `BIO_new()` returns a new BIO using method `type`
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO *BIO_new(BIO_METHOD *type);
/// ```
#[no_mangle]
pub extern "C" fn BIO_new<'a>(method_ptr: *const BIO_METHOD) -> *mut BIO<'a> {
    check_inner_result!(inner_bio_new(method_ptr), ptr::null_mut())
}

fn inner_bio_new<'a>(method_ptr: *const BIO_METHOD) -> InnerResult<*mut BIO<'a>> {
    if method_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    if method_ptr != (&BIO_METHOD_FILE as *const BIO_METHOD)
        && method_ptr != (&BIO_METHOD_MEM as *const BIO_METHOD)
    {
        return Err(Error::BadFuncArg);
    }
    let method = unsafe { &*method_ptr };
    let bio = BIO {
        magic: *MAGIC,
        inner: MesalinkBioInner::Unspecified,
        method: method.into(),
        flags: BioFlags::BIO_CLOSE,
    };
    let bio_ptr = Box::into_raw(Box::new(bio)) as *mut BIO<'_>;
    Ok(bio_ptr)
}

/// `BIO_free()` frees a BIO
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// int BIO_free(BIO *a);
/// ```
#[no_mangle]
pub extern "C" fn BIO_free(bio_ptr: *mut BIO<'_>) {
    let _ = check_inner_result!(inner_bio_free(bio_ptr), CRYPTO_FAILURE);
}

fn inner_bio_free(bio_ptr: *mut BIO<'_>) -> InnerResult<c_int> {
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
pub extern "C" fn BIO_read(bio_ptr: *mut BIO<'_>, buf_ptr: *mut c_void, len: c_int) -> c_int {
    check_inner_result!(inner_bio_read(bio_ptr, buf_ptr, len), -1)
}

fn inner_bio_read(bio_ptr: *mut BIO<'_>, buf_ptr: *mut c_void, len: c_int) -> InnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    if !bio.is_initialized() {
        // Mem or file not assigned yet
        return Err(Error::BadFuncArg);
    }
    if buf_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let buf_ptr = buf_ptr as *mut u8;
    let buf = unsafe { slice::from_raw_parts_mut(buf_ptr, len as usize) };
    let read_fn = &bio.method.read;
    let ret = read_fn(&mut bio.inner, buf).map_err(|e| Error::Io(e.kind()))?;
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
pub extern "C" fn BIO_gets(bio_ptr: *mut BIO<'_>, buf_ptr: *mut c_char, size: c_int) -> c_int {
    check_inner_result!(inner_bio_gets(bio_ptr, buf_ptr, size), -1)
}

fn inner_bio_gets(bio_ptr: *mut BIO<'_>, buf_ptr: *mut c_char, size: c_int) -> InnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    if !bio.is_initialized() {
        // Mem or file not assigned yet
        return Err(Error::BadFuncArg);
    }
    if buf_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let buf_ptr = buf_ptr as *mut u8;
    let buf = unsafe { slice::from_raw_parts_mut(buf_ptr, size as usize) };
    let gets_fn = &bio.method.gets;
    let ret = gets_fn(&mut bio.inner, buf).map_err(|e| Error::Io(e.kind()))?;
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
pub extern "C" fn BIO_write(bio_ptr: *mut BIO<'_>, buf_ptr: *const c_void, len: c_int) -> c_int {
    check_inner_result!(inner_bio_write(bio_ptr, buf_ptr, len), -1)
}

fn inner_bio_write(
    bio_ptr: *mut BIO<'_>,
    buf_ptr: *const c_void,
    len: c_int,
) -> InnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    if !bio.is_initialized() {
        // Mem or file not assigned yet
        return Err(Error::BadFuncArg);
    }
    if buf_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let buf_ptr = buf_ptr as *const u8;
    let buf = unsafe { slice::from_raw_parts(buf_ptr, len as usize) };
    let write_fn = &bio.method.write;
    let ret = write_fn(&mut bio.inner, buf).map_err(|e| Error::Io(e.kind()))?;
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
pub extern "C" fn BIO_puts(bio_ptr: *mut BIO<'_>, buf_ptr: *const c_char) -> c_int {
    check_inner_result!(inner_bio_puts(bio_ptr, buf_ptr), -1)
}

fn inner_bio_puts(bio_ptr: *mut BIO<'_>, buf_ptr: *const c_char) -> InnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    if !bio.is_initialized() {
        // Mem or file not assigned yet
        return Err(Error::BadFuncArg);
    }
    if buf_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let strlen = unsafe { libc::strlen(buf_ptr) };
    let buf_ptr = buf_ptr as *const u8;
    let buf = unsafe { slice::from_raw_parts(buf_ptr, strlen + 1) };
    let puts_fn = &bio.method.puts;
    let ret = puts_fn(&mut bio.inner, buf).map_err(|e| Error::Io(e.kind()))?;
    Ok(ret as c_int)
}

/// `BIO_s_file()` returns the BIO file method.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO_METHOD *BIO_s_file(void);
/// ```
#[no_mangle]
pub extern "C" fn BIO_s_file() -> *const BIO_METHOD {
    &BIO_METHOD_FILE as *const BIO_METHOD
}

/// `BIO_new_file()` creates a new file BIO with mode mode the meaning of mode
/// is the same as the stdio function fopen(). The BIO_CLOSE flag is set on the
/// returned BIO.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO *BIO_new_file(const char *filename, const char *mode);
/// ```
#[no_mangle]
pub extern "C" fn BIO_new_file<'a>(
    filename_ptr: *const c_char,
    mode_ptr: *const c_char,
) -> *mut BIO<'a> {
    check_inner_result!(
        inner_bio_new_filename(filename_ptr, mode_ptr),
        ptr::null_mut()
    )
}

fn inner_bio_new_filename<'a>(
    filename_ptr: *const c_char,
    mode_ptr: *const c_char,
) -> InnerResult<*mut BIO<'a>> {
    let file = open_file_from_filename_and_mode(filename_ptr, mode_ptr)?;
    let bio = BIO {
        magic: *MAGIC,
        inner: MesalinkBioInner::File(file),
        method: (&BIO_METHOD_FILE).into(),
        flags: BioFlags::BIO_CLOSE,
    };
    Ok(Box::into_raw(Box::new(bio)) as *mut BIO<'_>)
}

fn open_file_from_filename_and_mode(
    filename_ptr: *const c_char,
    mode_ptr: *const c_char,
) -> InnerResult<fs::File> {
    if filename_ptr.is_null() || mode_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let mode = unsafe {
        ffi::CStr::from_ptr(mode_ptr)
            .to_str()
            .map_err(|_| Error::BadFuncArg)?
    };
    let mut open_mode = fs::OpenOptions::new();
    let open_mode = match mode {
        "r" | "rb" => open_mode.read(true),
        "w" | "wb" => open_mode.write(true).create(true).truncate(true),
        "a" | "ab" => open_mode.write(true).create(true).append(true),
        "r+" | "r+b" | "rb+" => open_mode.read(true).write(true),
        "w+" | "w+b" | "wb+" => open_mode.read(true).write(true).create(true).truncate(true),
        "a+" | "a+b" | "ab+" => open_mode.read(true).write(true).create(true).append(true),
        _ => return Err(Error::BadFuncArg),
    };
    let filename = unsafe {
        ffi::CStr::from_ptr(filename_ptr)
            .to_str()
            .map_err(|_| Error::BadFuncArg)?
    };
    open_mode.open(filename).map_err(|e| Error::Io(e.kind()))
}

/// `BIO_read_filename()` sets the file BIO b to use file name for reading.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO *BIO_read_file(const char *filename);
/// ```
#[no_mangle]
pub extern "C" fn BIO_read_filename(bio_ptr: *mut BIO<'_>, filename_ptr: *const c_char) -> c_int {
    check_inner_result!(
        inner_bio_set_filename(bio_ptr, filename_ptr, b"r\0".as_ptr() as *const c_char),
        CRYPTO_FAILURE
    )
}

fn inner_bio_set_filename(
    bio_ptr: *mut BIO<'_>,
    filename_ptr: *const c_char,
    mode_ptr: *const c_char,
) -> InnerResult<c_int> {
    let file = open_file_from_filename_and_mode(filename_ptr, mode_ptr)?;
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    bio.inner = MesalinkBioInner::File(file);
    Ok(CRYPTO_SUCCESS)
}

/// `BIO_write_filename()` sets the file BIO b to use file name for writing.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO *BIO_write_file(const char *filename);
/// ```
#[no_mangle]
pub extern "C" fn BIO_write_filename(bio_ptr: *mut BIO<'_>, filename_ptr: *const c_char) -> c_int {
    check_inner_result!(
        inner_bio_set_filename(bio_ptr, filename_ptr, b"w\0".as_ptr() as *const c_char),
        CRYPTO_FAILURE
    )
}

/// `BIO_append_filename()` sets the file BIO b to use file name for appending.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO *BIO_append_filename(const char *filename);
/// ```
#[no_mangle]
pub extern "C" fn BIO_append_filename(bio_ptr: *mut BIO<'_>, filename_ptr: *const c_char) -> c_int {
    check_inner_result!(
        inner_bio_set_filename(bio_ptr, filename_ptr, b"a\0".as_ptr() as *const c_char),
        CRYPTO_FAILURE
    )
}

/// `BIO_rw_filename()` sets the file BIO b to use file name for reading and
/// writing.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO *BIO_rw_file(const char *filename);
/// ```
#[no_mangle]
pub extern "C" fn BIO_rw_filename(bio_ptr: *mut BIO<'_>, filename_ptr: *const c_char) -> c_int {
    check_inner_result!(
        inner_bio_set_filename(bio_ptr, filename_ptr, b"r+\0".as_ptr() as *const c_char),
        CRYPTO_FAILURE
    )
}

/// `BIO_new_fp()` screates a file BIO wrapping `stream`
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO *BIO_new_fp(FILE *stream, int flags);
/// ```
#[no_mangle]
pub extern "C" fn BIO_new_fp<'a>(stream: *mut libc::FILE, flags: c_int) -> *mut BIO<'a> {
    check_inner_result!(inner_bio_new_fp(stream, flags), ptr::null_mut())
}

fn inner_bio_new_fp<'a>(stream: *mut libc::FILE, flags: c_int) -> InnerResult<*mut BIO<'a>> {
    if stream.is_null() {
        return Err(Error::NullPointer);
    }
    let file = unsafe { fs::File::from_file_stream(stream) };
    let flags = BioFlags::from_bits(flags as u32).ok_or(Error::BadFuncArg)?;
    let bio = BIO {
        magic: *MAGIC,
        inner: MesalinkBioInner::File(file),
        method: (&BIO_METHOD_FILE).into(),
        flags,
    };
    Ok(Box::into_raw(Box::new(bio)) as *mut BIO<'_>)
}

/// `BIO_set_fp()` sets the fp of a file BIO to `fp`.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO_set_fp(BIO *b,FILE *fp, int flags);
/// ```
#[no_mangle]
pub extern "C" fn BIO_set_fp(bio_ptr: *mut BIO<'_>, fp: *mut libc::FILE, flags: c_int) {
    let _ = check_inner_result!(inner_bio_set_fp(bio_ptr, fp, flags), CRYPTO_FAILURE);
}

fn inner_bio_set_fp(
    bio_ptr: *mut BIO<'_>,
    fp: *mut libc::FILE,
    flags: c_int,
) -> InnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    let file = unsafe { fs::File::from_file_stream(fp) };
    let flags = BioFlags::from_bits(flags as u32).ok_or(Error::BadFuncArg)?;
    bio.inner = MesalinkBioInner::File(file);
    bio.flags = flags;
    Ok(CRYPTO_SUCCESS)
}

/// `BIO_get_close()` returns the BIOs close flag.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// int BIO_get_close(BIO *b);
/// ```
#[no_mangle]
pub extern "C" fn BIO_get_close(bio_ptr: *mut BIO<'_>) -> c_int {
    check_inner_result!(
        inner_bio_get_close(bio_ptr),
        BioFlags::default().bits() as c_int
    )
}

fn inner_bio_get_close(bio_ptr: *mut BIO<'_>) -> InnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    Ok(bio.flags.bits() as c_int)
}

/// `BIO_set_close()` sets the BIO *b* close flag to *flag*
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// int BIO_set_close(BIO *b, long flag);
/// ```
#[no_mangle]
pub extern "C" fn BIO_set_close(bio_ptr: *mut BIO<'_>, flag: c_long) -> c_int {
    let _ = check_inner_result!(
        inner_bio_set_close(bio_ptr, flag),
        BioFlags::default().bits() as c_int
    );
    CRYPTO_SUCCESS
}

fn inner_bio_set_close(bio_ptr: *mut BIO<'_>, flag: c_long) -> InnerResult<c_int> {
    let bio = sanitize_ptr_for_mut_ref(bio_ptr)?;
    let flag = BioFlags::from_bits(flag as u32).ok_or(Error::BadFuncArg)?;
    bio.flags = flag;
    Ok(CRYPTO_SUCCESS)
}

/// `BIO_s_file()` returns the BIO memory method.
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO_METHOD *BIO_s_mem(void);
/// ```
#[no_mangle]
pub extern "C" fn BIO_s_mem() -> *const BIO_METHOD {
    &BIO_METHOD_MEM as *const BIO_METHOD
}

/// `BIO_new_mem_buf()` creates a memory BIO using `len` bytes of data at `buf`
///
/// ```c
/// #include <tabbyssl/openssl/bio.h>
///
/// BIO *BIO_new_mem_buf(const void *buf, int len);
/// ```
#[no_mangle]
pub extern "C" fn BIO_new_mem_buf<'a>(buf_ptr: *mut c_void, len: c_int) -> *mut BIO<'a> {
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
    let bio = BIO {
        magic: *MAGIC,
        inner: MesalinkBioInner::Mem(io::Cursor::new(buf)),
        method: (&BIO_METHOD_MEM).into(),
        flags: BioFlags::default(), // TODO: support BIO_FLAGS_MEM_RDONLY
    };
    Box::into_raw(Box::new(bio)) as *mut BIO<'_>
}

/// Helper trait for converting from FILE* in libc.
#[doc(hidden)]
pub trait FromFileStream {
    #[allow(clippy::missing_safety_doc)]
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
#[doc(hidden)]
pub trait OpenFileStream {
    #[allow(clippy::missing_safety_doc)]
    unsafe fn open_file_stream_r(&self) -> *mut libc::FILE;
    #[allow(clippy::missing_safety_doc)]
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
