use libc::{c_char, c_int};
use rustls::Certificate;
use rustls_pemfile as pemfile;
use std::{fs, io, ptr};
use tabbyssl::libssl::safestack::*;
use tabbyssl::libssl::x509::*;

#[test]
fn x509_get_subject_name_and_alt_names() {
    let mut certs_io = io::BufReader::new(fs::File::open("tests/certs/end.fullchain").unwrap());
    let certs = pemfile::certs(&mut certs_io).unwrap();
    assert_eq!(true, certs.len() > 0);

    let cert = certs[0].to_owned();
    let x509 = X509::new(Certificate(cert));
    let x509_ptr = Box::into_raw(Box::new(x509)) as *mut X509;

    let buf_1 = [0u8; 255];
    let subject_der_ptr = X509_get_subject(x509_ptr);
    assert_ne!(subject_der_ptr, ptr::null_mut());
    let _ = X509_NAME_oneline(
        subject_der_ptr as *mut X509_NAME,
        buf_1.as_ptr() as *mut c_char,
        255,
    );
    let buf_2 = [0u8; 2];
    let _ = X509_NAME_oneline(
        subject_der_ptr as *mut X509_NAME,
        buf_2.as_ptr() as *mut c_char,
        2,
    );
    X509_NAME_free(subject_der_ptr);

    let subject_name_ptr = X509_get_subject_name(x509_ptr);
    assert_ne!(subject_name_ptr, ptr::null_mut());

    let buf = [0u8; 255];
    let _ = X509_NAME_oneline(
        subject_name_ptr as *mut X509_NAME,
        buf.as_ptr() as *mut c_char,
        255,
    );
    X509_NAME_free(subject_name_ptr);

    let name_stack_ptr = X509_get_alt_subject_names(x509_ptr);

    let name_count = sk_X509_NAME_num(name_stack_ptr) as usize;
    assert_eq!(true, name_count > 0);
    for index in 0..name_count {
        let name_ptr = sk_X509_NAME_value(name_stack_ptr, index as c_int);
        assert_ne!(name_ptr, ptr::null_mut());
        let buf = [0u8; 253];
        let _ = X509_NAME_oneline(name_ptr as *mut X509_NAME, buf.as_ptr() as *mut c_char, 253);
    }
    sk_X509_NAME_free(name_stack_ptr);
    X509_free(x509_ptr);
}

#[test]
fn x509_null_pointer() {
    X509_free(ptr::null_mut());
    X509_NAME_free(ptr::null_mut());
    assert_eq!(
        ptr::null(),
        X509_NAME_oneline(ptr::null_mut(), ptr::null_mut(), 10)
    );
}
