use libc::c_int;
use rustls::Certificate;
use rustls_pemfile as pemfile;
use std::{fs, io, ptr};
use tabbyssl::libssl::safestack::*;
use tabbyssl::libssl::x509::*;
use tabbyssl::libssl::SSL_SUCCESS;

#[test]
fn x509_sk() {
    let stack_ptr: *mut STACK_X509 = sk_X509_new_null();
    let mut certs_io = io::BufReader::new(fs::File::open("tests/certs/end.fullchain").unwrap());
    let certs = pemfile::certs(&mut certs_io).unwrap();
    let certs_count = certs.len();
    assert_eq!(true, certs_count > 0);
    for cert in certs.into_iter() {
        let x509 = X509::new(Certificate(cert));
        let x509_ptr = Box::into_raw(Box::new(x509)) as *mut X509;
        assert_eq!(SSL_SUCCESS, sk_X509_push(stack_ptr, x509_ptr));
        let _ = unsafe { Box::from_raw(x509_ptr) }; // push() clones the X509 object
    }
    assert_eq!(certs_count as c_int, sk_X509_num(stack_ptr));
    for index in 0..certs_count {
        let x509_ptr = sk_X509_value(stack_ptr, index as c_int);
        assert_ne!(x509_ptr, ptr::null_mut());
    }
    sk_X509_free(stack_ptr);
}

#[test]
fn x509_name_sk() {
    let stack_ptr: *mut STACK_X509_NAME = sk_X509_NAME_new_null();
    let names = ["*.google.com", "youtube.com", "map.google.com"];
    for name in names.iter() {
        let x509_name = X509_NAME::new(name.as_bytes());
        let x509_name_ptr = Box::into_raw(Box::new(x509_name)) as *mut X509_NAME;
        assert_eq!(SSL_SUCCESS, sk_X509_NAME_push(stack_ptr, x509_name_ptr));
        let _ = unsafe { Box::from_raw(x509_name_ptr) }; // push() clones the X509_NAME object
    }
    assert_eq!(names.len() as c_int, sk_X509_NAME_num(stack_ptr));
    for index in 0..names.len() {
        let x509_name_ptr = sk_X509_NAME_value(stack_ptr, index as c_int);
        assert_ne!(x509_name_ptr, ptr::null_mut());
    }
    sk_X509_NAME_free(stack_ptr);
}

#[test]
fn sk_free_null_pointer() {
    sk_X509_free(ptr::null_mut());
    sk_X509_NAME_free(ptr::null_mut());
}
