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
use super::safestack::STACK_X509_NAME;
use super::{SSL_FAILURE, SSL_SUCCESS};
use crate::error_san::*;
use crate::{OpaquePointerGuard, MAGIC, MAGIC_SIZE};
use libc::{c_char, c_int};
use ring::io::der;
use rustls;
use std::convert::TryFrom;
use std::{ptr, slice, str};
use untrusted;
use webpki;

/// An OpenSSL X509 object
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct X509 {
    magic: [u8; MAGIC_SIZE],
    pub inner: rustls::Certificate,
}

impl OpaquePointerGuard for X509 {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

#[allow(unused)]
enum EndEntityOrCA<'a> {
    CA(&'a Cert<'a>),
}

#[allow(unused)]
struct SignedData<'a> {
    data: untrusted::Input<'a>,
    algorithm: untrusted::Input<'a>,
    signature: untrusted::Input<'a>,
}

#[allow(unused)]
struct Cert<'a> {
    pub ee_or_ca: EndEntityOrCA<'a>,
    pub signed_data: SignedData<'a>,
    pub issuer: untrusted::Input<'a>,
    pub validity: untrusted::Input<'a>,
    pub subject: untrusted::Input<'a>,
    pub spki: untrusted::Input<'a>,
    pub basic_constraints: Option<untrusted::Input<'a>>,
    pub eku: Option<untrusted::Input<'a>>,
    pub name_constraints: Option<untrusted::Input<'a>>,
    pub subject_alt_name: Option<untrusted::Input<'a>>,
}

#[doc(hidden)]
impl X509 {
    pub fn new(cert: rustls::Certificate) -> X509 {
        X509 {
            magic: *MAGIC,
            inner: cert,
        }
    }
}

/// `X509_free` - free up a X509 structure. If a is NULL nothing is done.
///
/// ```c
/// #include <tabbyssl/openssl/x509.h>
///
/// void X509_free(X509 *a);
/// ```
#[no_mangle]
pub extern "C" fn X509_free(x509_ptr: *mut X509) {
    let _ = check_inner_result!(inner_x509_free(x509_ptr), SSL_FAILURE);
}

fn inner_x509_free(x509_ptr: *mut X509) -> InnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(x509_ptr)?;
    let _ = unsafe { Box::from_raw(x509_ptr) };
    Ok(SSL_SUCCESS)
}

/// An OpenSSL X509_NAME object
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct X509_NAME {
    magic: [u8; MAGIC_SIZE],
    name: Vec<u8>,
}

impl<'a> OpaquePointerGuard for X509_NAME {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl<'a> X509_NAME {
    pub fn new(name: &[u8]) -> X509_NAME {
        X509_NAME {
            magic: *MAGIC,
            name: name.to_vec(),
        }
    }
}

/// `X509_NAME_free` - free up a X509_NAME structure. If a is NULL nothing is
/// done.
///
/// ```c
/// #include <tabbyssl/openssl/x509.h>
///
/// void X509_free(X509 *a);
/// ```
#[no_mangle]
pub extern "C" fn X509_NAME_free(x509_name_ptr: *mut X509_NAME) {
    let _ = check_inner_result!(inner_x509_name_free(x509_name_ptr), SSL_FAILURE);
}

fn inner_x509_name_free(x509_name_ptr: *mut X509_NAME) -> InnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(x509_name_ptr)?;
    let _ = unsafe { Box::from_raw(x509_name_ptr) };
    Ok(SSL_SUCCESS)
}

/// `X509_get_alt_subject_names` - returns the alternative subject names of
/// certificate x. The returned value is a STACK pointer which MUST be freed by
/// `sk_X509_NAME_free`.
///
/// ```c
/// #include <tabbyssl/openssl/x509.h>
///
/// STACK_OF(X509_NAME) *X509_get_alt_subject_names(const X509 *x);;
/// ```
#[no_mangle]
pub extern "C" fn X509_get_alt_subject_names(x509_ptr: *mut X509) -> *mut STACK_X509_NAME {
    check_inner_result!(inner_x509_get_alt_subject_names(x509_ptr), ptr::null_mut())
}

fn inner_x509_get_alt_subject_names(x509_ptr: *mut X509) -> InnerResult<*mut STACK_X509_NAME> {
    let cert = sanitize_ptr_for_ref(x509_ptr)?;
    let x509 = webpki::EndEntityCert::try_from(cert.inner.0.as_slice())
        .map_err(|e| rustls::Error::InvalidCertificateData(e.to_string()))?;

    let cert: Cert = unsafe { std::mem::transmute(x509) };
    let subject_alt_name = cert.subject_alt_name.ok_or(Error::BadFuncArg)?;
    let mut reader = untrusted::Reader::new(subject_alt_name);
    let mut stack = STACK_X509_NAME::new(Vec::new());
    while !reader.at_end() {
        let (tag, value) =
            der::read_tag_and_get_value(&mut reader).map_err(|_| Error::BadFuncArg)?;
        if tag == 0x82 {
            let x509_name = X509_NAME::new(value.as_slice_less_safe());
            stack.stack.push(x509_name);
        }
    }
    Ok(Box::into_raw(Box::new(stack)) as *mut STACK_X509_NAME)
}

/// `X509_get_subject` - returns the DER bytes of the subject of x as a
/// `X509_NAME`. The returned value is a X509_NAME pointer which MUST be freed
/// by `X509_NAME_free`.
///
/// ```c
/// #include <tabbyssl/openssl/x509.h>
///
/// X509_NAME *X509_get_subject(const X509 *x);;
/// ```
#[no_mangle]
pub extern "C" fn X509_get_subject(x509_ptr: *mut X509) -> *mut X509_NAME {
    check_inner_result!(inner_x509_get_subject(x509_ptr), ptr::null_mut())
}

fn inner_x509_get_subject(x509_ptr: *mut X509) -> InnerResult<*mut X509_NAME> {
    let cert = sanitize_ptr_for_ref(x509_ptr)?;
    let x509 = webpki::EndEntityCert::try_from(cert.inner.0.as_slice())
        .map_err(|e| rustls::Error::InvalidCertificateData(e.to_string()))?;

    let cert: Cert = unsafe { std::mem::transmute(x509) };
    let subject = cert.subject.as_slice_less_safe();
    let subject_len = subject.len();
    let mut value = Vec::new();
    if subject_len <= 127 {
        value.extend_from_slice(&[0x30, subject.len() as u8]);
    } else {
        let mut size_of_length: usize = 0;
        let mut subject_len_tmp = subject_len;
        while subject_len_tmp != 0 {
            size_of_length += 1;
            subject_len_tmp /= 256;
        }
        let mut subject_len_tmp = subject_len;
        value.extend_from_slice(&[0x30, 128 + size_of_length as u8]);
        let mut length_bytes = vec![0; size_of_length];
        for i in 0..size_of_length {
            length_bytes[size_of_length - i - 1] = (subject_len_tmp & 0xff) as u8;
            subject_len_tmp >>= 8;
        }
        value.extend_from_slice(length_bytes.as_slice());
    }
    value.extend_from_slice(subject);
    value.shrink_to_fit();
    let x509_name = X509_NAME::new(&value);
    Ok(Box::into_raw(Box::new(x509_name)) as *mut X509_NAME)
}

/// `X509_get_subject_name` - returns the subject of x as a human readable
/// `X509_NAME`. The returned value is a X509_NAME pointer which MUST be freed
/// by `X509_NAME_free`.
///
/// ```c
/// #include <tabbyssl/openssl/x509.h>
///
/// X509_NAME *X509_get_subject_name(const X509 *x);;
/// ```
#[no_mangle]
pub extern "C" fn X509_get_subject_name(x509_ptr: *mut X509) -> *mut X509_NAME {
    check_inner_result!(inner_x509_get_subject_name(x509_ptr), ptr::null_mut())
}

fn inner_x509_get_subject_name(x509_ptr: *mut X509) -> InnerResult<*mut X509_NAME> {
    let cert = sanitize_ptr_for_ref(x509_ptr)?;
    let x509 = webpki::EndEntityCert::try_from(cert.inner.0.as_slice())
        .map_err(|e| rustls::Error::InvalidCertificateData(e.to_string()))?;

    let mut subject_name = String::new();

    let cert: Cert = unsafe { std::mem::transmute(x509) };
    let _ = cert
        .subject
        .read_all(Error::BadFuncArg, |subject| {
            while !subject.at_end() {
                let (maybe_asn_set_tag, sequence) =
                    der::read_tag_and_get_value(subject).map_err(|_| Error::BadFuncArg)?;
                if (maybe_asn_set_tag as usize) != 0x31 {
                    // Subject should be an ASN.1 SET
                    return Err(Error::BadFuncArg);
                }
                let _ = sequence.read_all(Error::BadFuncArg, |seq| {
                    let oid_and_data = der::expect_tag_and_get_value(seq, der::Tag::Sequence)
                        .map_err(|_| Error::BadFuncArg)?;
                    oid_and_data.read_all(Error::BadFuncArg, |oid_and_data| {
                        let oid = der::expect_tag_and_get_value(oid_and_data, der::Tag::OID)
                            .map_err(|_| Error::BadFuncArg)?;
                        let (_, value) = der::read_tag_and_get_value(oid_and_data)
                            .map_err(|_| Error::BadFuncArg)?;

                        let keyword = match oid.as_slice_less_safe().last().unwrap() {
                            // RFC 1779, X.500 attrinutes, oid 2.5.4
                            3 => "CN",  // CommonName
                            7 => "L",   // LocalityName
                            8 => "ST",  // StateOrProvinceName
                            10 => "O",  // OrganizationName
                            11 => "OU", // OrganizationalUnitName
                            6 => "C",   // CountryName
                            _ => "",
                        };

                        if !keyword.is_empty() {
                            if let Ok(s) = str::from_utf8(value.as_slice_less_safe()) {
                                subject_name.push('/');
                                subject_name.push_str(keyword);
                                subject_name.push('=');
                                subject_name.push_str(s);
                            }
                        }
                        Ok(())
                    })
                });
            }
            Ok(())
        })
        .map_err(|_| Error::BadFuncArg);

    let x509_name = X509_NAME::new(subject_name.as_bytes());
    Ok(Box::into_raw(Box::new(x509_name)) as *mut X509_NAME)
}

/// `X509_NAME_oneline` - prints an ASCII version of a to buf. If buf is NULL
/// then a buffer is dynamically allocated and returned, and size is ignored.
/// Otherwise, at most size bytes will be written, including the ending '\0',
/// and buf is returned.
///
/// ```c
/// #include <tabbyssl/openssl/x509.h>
///
/// char * X509_NAME_oneline(X509_NAME *a,char *buf,int size);
/// ```
#[no_mangle]
pub extern "C" fn X509_NAME_oneline(
    x509_name_ptr: *mut X509_NAME,
    buf_ptr: *mut c_char,
    size: c_int,
) -> *mut c_char {
    check_inner_result!(
        inner_x509_name_oneline(x509_name_ptr, buf_ptr, size),
        ptr::null_mut()
    )
}

fn inner_x509_name_oneline(
    x509_name_ptr: *mut X509_NAME,
    buf_ptr: *mut c_char,
    buf_len: c_int,
) -> InnerResult<*mut c_char> {
    let x509_name = sanitize_ptr_for_ref(x509_name_ptr)?;
    let buf_len: usize = buf_len as usize;
    unsafe {
        let name: &[c_char] = &*(x509_name.name.as_slice() as *const [u8] as *const [c_char]);
        let name_len: usize = name.len();
        if buf_ptr.is_null() {
            return Err(Error::NullPointer);
        }
        let buf = slice::from_raw_parts_mut(buf_ptr, buf_len);
        if name_len + 1 > buf_len {
            buf.copy_from_slice(&name[0..buf_len]);
            buf[buf_len - 1] = 0;
        } else {
            buf[0..name_len].copy_from_slice(name);
            buf[name_len] = 0;
        }
        Ok(buf_ptr)
    }
}
