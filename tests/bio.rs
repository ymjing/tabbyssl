use libc::{self, c_char, c_void};
use std::{fs, ptr};
use tabbyssl::libcrypto::bio::OpenFileStream;
use tabbyssl::libcrypto::bio::*;
use tabbyssl::libcrypto::CRYPTO_SUCCESS;

#[test]
fn bio_methods() {
    assert_ne!(BIO_s_file(), ptr::null());
    assert_ne!(BIO_s_mem(), ptr::null());
}

#[test]
fn bio_create_from_method() {
    let bio_ptr_f = BIO_new(BIO_s_mem());
    assert_ne!(bio_ptr_f, ptr::null_mut());
    BIO_free(bio_ptr_f);
    let bio_ptr_m = BIO_new(BIO_s_file());
    assert_ne!(bio_ptr_m, ptr::null_mut());
    BIO_free(bio_ptr_m);
}

#[test]
fn bio_null_ptr() {
    let bio_ptr = BIO_new(ptr::null());
    assert_eq!(bio_ptr, ptr::null_mut());

    let invalid_method_ptr = "hello".as_ptr() as *const BIO_METHOD;
    let bio_ptr = BIO_new(invalid_method_ptr);
    assert_eq!(bio_ptr, ptr::null_mut());
}

#[test]
fn bio_uninitialized() {
    let bio_ptr = BIO_new(BIO_s_mem());
    let buf_ptr = [0u8; 32].as_ptr() as *mut c_void;
    let len = BIO_read(bio_ptr, buf_ptr, 32);
    assert_eq!(-1, len);
    let len = BIO_write(bio_ptr, buf_ptr, 32);
    assert_eq!(-1, len);
    let buf_ptr = buf_ptr as *mut c_char;
    let len = BIO_gets(bio_ptr, buf_ptr, 32);
    assert_eq!(-1, len);
    let len = BIO_puts(bio_ptr, buf_ptr);
    assert_eq!(-1, len);
    BIO_free(bio_ptr);
}

#[test]
fn bio_null_buf() {
    let bio_ptr = BIO_new_mem_buf(ptr::null_mut(), 10);
    assert_eq!(bio_ptr, ptr::null_mut());
    let bio_ptr = BIO_new_mem_buf(b"hello\0".as_ptr() as *mut c_void, -1);
    let buf_ptr = ptr::null_mut() as *mut c_void;
    let len = BIO_read(bio_ptr, buf_ptr, 5);
    assert_eq!(-1, len);
    let len = BIO_write(bio_ptr, buf_ptr, 5);
    assert_eq!(-1, len);
    let buf_ptr = buf_ptr as *mut c_char;
    let len = BIO_gets(bio_ptr, buf_ptr, 5);
    assert_eq!(-1, len);
    let len = BIO_puts(bio_ptr, buf_ptr);
    assert_eq!(-1, len);
    BIO_free(bio_ptr);
}

#[test]
fn bio_mem() {
    let buf = [0u8; 10];
    let bio_ptr_m = BIO_new_mem_buf(buf.as_ptr() as *mut c_void, 10);
    assert_ne!(bio_ptr_m, ptr::null_mut());
    let src = [1u8, 2, 3, 4, 5];
    let ret = BIO_write(bio_ptr_m, src.as_ptr() as *const c_void, 5);
    assert_eq!(ret, 5);
    BIO_free(bio_ptr_m);

    let buf = [1u8, 2, 3, 4, 5];
    let bio_ptr_m = BIO_new_mem_buf(buf.as_ptr() as *mut c_void, 5);
    let dst = [0u8; 10];
    let ret = BIO_read(bio_ptr_m, dst.as_ptr() as *mut c_void, 5);
    assert_eq!(ret, 5);
    assert_eq!(dst, [1u8, 2, 3, 4, 5, 0, 0, 0, 0, 0]);
    BIO_free(bio_ptr_m);

    let buf = [0u8; 10];
    let bio_ptr_m = BIO_new_mem_buf(buf.as_ptr() as *mut c_void, 10);
    assert_ne!(bio_ptr_m, ptr::null_mut());
    let src = b"hello\0";
    let ret = BIO_puts(bio_ptr_m, src.as_ptr() as *const c_char);
    assert_eq!(ret, 6);
    BIO_free(bio_ptr_m);

    let buf = [1u8, 2, 0, 4, 5];
    let bio_ptr_m = BIO_new_mem_buf(buf.as_ptr() as *mut c_void, 5);
    assert_ne!(bio_ptr_m, ptr::null_mut());
    let dst = [0u8; 5];
    let ret = BIO_gets(bio_ptr_m, dst.as_ptr() as *mut c_char, 5);
    assert_eq!(ret, 3);
    assert_eq!(dst, [1u8, 2, 0, 0, 0]);
    BIO_free(bio_ptr_m);
}

#[test]
fn bio_file_new_fp() {
    let bio_ptr_f = BIO_new_fp(ptr::null_mut(), 0);
    assert_eq!(bio_ptr_f, ptr::null_mut());
    let file = fs::File::open("tests/certs/ca.cert").unwrap();
    let fp = unsafe { file.open_file_stream_r() };
    assert_ne!(fp, ptr::null_mut());

    let bio_ptr_f = BIO_new_fp(fp, 0);
    assert_ne!(bio_ptr_f, ptr::null_mut());
    let buf = [0u8; 1024];
    let ret = BIO_gets(bio_ptr_f, buf.as_ptr() as *mut c_char, 1024);
    assert_eq!(ret, 28); // gets returns the first line
    BIO_free(bio_ptr_f);
}

#[test]
fn bio_file_set_fp() {
    let file = fs::File::open("tests/certs/ca.cert").unwrap();
    let fp = unsafe { file.open_file_stream_r() };
    assert_ne!(fp, ptr::null_mut());

    let bio_ptr_f = BIO_new(BIO_s_file());
    assert_ne!(bio_ptr_f, ptr::null_mut());
    assert_eq!(0x1, BIO_get_close(bio_ptr_f)); // BIO_CLOSE by default
    BIO_set_fp(bio_ptr_f, fp, 0);
    assert_eq!(0x0, BIO_get_close(bio_ptr_f)); // BIO_NOCLOSE after set_fp
    assert_eq!(CRYPTO_SUCCESS, BIO_set_close(bio_ptr_f, 0x0));
    let buf = [0u8; 1024];
    let ret = BIO_gets(bio_ptr_f, buf.as_ptr() as *mut c_char, 1024);
    assert_eq!(ret, 28); // gets returns the first line
    BIO_free(bio_ptr_f);
}

#[test]
fn bio_file_new_from_path() {
    let path_ptr = b"tests/certs/deleteme\0".as_ptr() as *const c_char;

    let bio_ptr_f = BIO_new(BIO_s_file());
    assert_ne!(bio_ptr_f, ptr::null_mut());

    let ret = BIO_write_filename(bio_ptr_f, path_ptr);
    assert_eq!(ret, CRYPTO_SUCCESS);

    let ret = BIO_rw_filename(bio_ptr_f, path_ptr);
    assert_eq!(ret, CRYPTO_SUCCESS);

    let ret = BIO_read_filename(bio_ptr_f, path_ptr);
    assert_eq!(ret, CRYPTO_SUCCESS);

    let ret = BIO_append_filename(bio_ptr_f, path_ptr);
    assert_eq!(ret, CRYPTO_SUCCESS);

    BIO_free(bio_ptr_f);
    let _ = fs::remove_file("tests/certs/deleteme");
}
