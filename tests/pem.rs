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

use libc::c_char;
use std::{fs, ptr};
use tabbyssl::libcrypto::bio::OpenFileStream;
use tabbyssl::libcrypto::pem::*;
use tabbyssl::libcrypto::{bio, evp};
use tabbyssl::libssl::x509;

#[test]
fn pem_read_bio_private_key() {
    let bio_ptr = bio::BIO_new_file(
        b"tests/certs/end.key\0".as_ptr() as *const c_char,
        b"r\0".as_ptr() as *const c_char,
    );
    assert_ne!(bio_ptr, ptr::null_mut());
    let pkey_ptr =
        PEM_read_bio_PrivateKey(bio_ptr, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    assert_ne!(pkey_ptr, ptr::null_mut());
    evp::EVP_PKEY_free(pkey_ptr);
    bio::BIO_free(bio_ptr);
}

#[test]
fn pem_read_private_key() {
    let file = fs::File::open("tests/certs/end.key").unwrap();
    let fp = unsafe { file.open_file_stream_r() };
    assert_ne!(fp, ptr::null_mut());
    let pkey_ptr = PEM_read_PrivateKey(fp, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    assert_ne!(pkey_ptr, ptr::null_mut());
    evp::EVP_PKEY_free(pkey_ptr);
}

#[test]
fn pem_read_bio_x509() {
    let bio_ptr = bio::BIO_new_file(
        b"tests/certs/end.fullchain\0".as_ptr() as *const c_char,
        b"r\0".as_ptr() as *const c_char,
    );
    assert_ne!(bio_ptr, ptr::null_mut());
    let x509_ptr = PEM_read_bio_X509(bio_ptr, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    assert_ne!(x509_ptr, ptr::null_mut());
    x509::X509_free(x509_ptr);
    bio::BIO_free(bio_ptr);
}

#[test]
fn pem_read_x509() {
    let file = fs::File::open("tests/certs/end.fullchain").unwrap();
    let fp = unsafe { file.open_file_stream_r() };
    assert_ne!(fp, ptr::null_mut());
    let x509_ptr = PEM_read_X509(fp, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    assert_ne!(x509_ptr, ptr::null_mut());
    x509::X509_free(x509_ptr);
}
