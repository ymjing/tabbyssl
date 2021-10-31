extern crate tabbyssl;

use libc::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{ffi, net, ptr, str, thread};
use tabbyssl::libssl::err::ERR_clear_error;
use tabbyssl::libssl::ssl::*;
use tabbyssl::libssl::x509::*;
use tabbyssl::libssl::*;

const CONST_CA_FILE: &[u8] = b"tests/certs/ca.cert\0";
const CONST_INTER_CA_FILE: &[u8] = b"tests/certs/inter.cert\0";
const CONST_SERVER_CERT_CHAIN_FILE: &[u8] = b"tests/certs/end.fullchain\0";
const CONST_SERVER_CERT_FILE: &[u8] = b"tests/certs/end.cert\0";
const CONST_SERVER_KEY_FILE: &[u8] = b"tests/certs/end.key\0";
const CONST_CLIENT_CERT_FILE: &[u8] = b"tests/certs/client.fullchain\0";
const CONST_CLIENT_KEY_FILE: &[u8] = b"tests/certs/client.key\0";
const CONST_SERVER_ADDR: &str = "127.0.0.1";

struct TabbyTestSession {
    ctx: *mut SSL_CTX_ARC,
    ssl: *mut SSL,
}

impl TabbyTestSession {
    fn new_client_session(
        method: *const SSL_METHOD,
        sockfd: c_int,
    ) -> Result<TabbyTestSession, ()> {
        let ctx = SSL_CTX_new(method);
        assert_ne!(ctx, ptr::null_mut(), "CTX is null");
        let _ = SSL_CTX_set_session_cache_mode(ctx, 3);
        assert_eq!(
            SSL_SUCCESS,
            SSL_CTX_use_certificate_chain_file(
                ctx,
                CONST_CLIENT_CERT_FILE.as_ptr() as *const c_char,
                0,
            ),
            "Failed to set certificate file"
        );
        assert_eq!(
            SSL_SUCCESS,
            SSL_CTX_use_PrivateKey_file(ctx, CONST_CLIENT_KEY_FILE.as_ptr() as *const c_char, 0,),
            "Failed to set private key"
        );
        assert_eq!(
            SSL_SUCCESS,
            SSL_CTX_load_verify_locations(
                ctx,
                CONST_CA_FILE.as_ptr() as *const c_char,
                ptr::null_mut(),
            ),
            "Failed to load verified locations"
        );

        let ssl = SSL_new(ctx);
        assert_ne!(ssl, ptr::null_mut(), "SSL is null");
        assert_eq!(
            SSL_SUCCESS,
            SSL_set_tlsext_host_name(ssl, b"localhost\0".as_ptr() as *const c_char),
            "Failed to set SNI"
        );
        assert_eq!(SSL_SUCCESS, SSL_set_fd(ssl, sockfd), "Failed to set fd");
        SSL_set_connect_state(ssl);
        assert_eq!(SSL_SUCCESS, SSL_connect(ssl), "Failed to connect");
        if SSL_SUCCESS != SSL_do_handshake(ssl) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return Err(());
        }
        Ok(TabbyTestSession { ctx, ssl })
    }

    fn new_server_session(
        method: *const SSL_METHOD,
        sockfd: c_int,
    ) -> Result<TabbyTestSession, ()> {
        let ctx = SSL_CTX_new(method);
        assert_ne!(ctx, ptr::null_mut(), "CTX is null");
        assert_eq!(
            SSL_SUCCESS,
            SSL_CTX_load_verify_locations(
                ctx,
                CONST_CA_FILE.as_ptr() as *const c_char,
                ptr::null_mut(),
            ),
            "Failed to load verified locations"
        );
        assert_eq!(
            SSL_SUCCESS,
            SSL_CTX_use_certificate_chain_file(
                ctx,
                CONST_SERVER_CERT_CHAIN_FILE.as_ptr() as *const c_char,
                0,
            ),
            "Failed to set certificate file"
        );
        assert_eq!(
            SSL_SUCCESS,
            SSL_CTX_use_PrivateKey_file(ctx, CONST_SERVER_KEY_FILE.as_ptr() as *const c_char, 0,),
            "Failed to set private key"
        );
        assert_eq!(
            SSL_SUCCESS,
            SSL_CTX_set_verify(ctx, 1, None),
            "Failed to set verify mode"
        );
        let ssl = SSL_new(ctx);
        assert_ne!(ssl, ptr::null_mut(), "SSL is null");
        assert_eq!(SSL_SUCCESS, SSL_set_fd(ssl, sockfd), "Faield to set fd");
        SSL_set_accept_state(ssl);
        if SSL_SUCCESS != SSL_accept(ssl) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return Err(());
        }
        Ok(TabbyTestSession { ctx, ssl })
    }

    fn read(&self, buf: &mut [u8]) -> c_int {
        SSL_read(
            self.ssl,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as c_int,
        )
    }

    fn write(&self, buf: &[u8]) -> c_int {
        SSL_write(self.ssl, buf.as_ptr() as *mut c_void, buf.len() as c_int)
    }

    fn shutdown(&self) -> c_int {
        SSL_shutdown(self.ssl)
    }

    fn get_error(&self) -> c_int {
        SSL_get_error(self.ssl, -1)
    }
}

impl Drop for TabbyTestSession {
    fn drop(&mut self) {
        SSL_free(self.ssl);
        SSL_CTX_free(self.ctx);
    }
}

#[allow(dead_code)]
enum TlsVersion {
    Tlsv12,
    Tlsv13,
    Both,
}

fn get_method_by_version(version: &TlsVersion, is_server: bool) -> *const SSL_METHOD {
    match (version, is_server) {
        (TlsVersion::Tlsv12, false) => TLSv1_2_client_method(),
        (TlsVersion::Tlsv13, false) => TLSv1_3_client_method(),
        (&TlsVersion::Both, false) => TLS_client_method(),
        (TlsVersion::Tlsv12, true) => TLSv1_2_server_method(),
        (TlsVersion::Tlsv13, true) => TLSv1_3_server_method(),
        (&TlsVersion::Both, true) => TLS_server_method(),
    }
}

struct TabbyTestDriver {}

impl TabbyTestDriver {
    fn new() -> TabbyTestDriver {
        TabbyTestDriver {}
    }

    fn get_unused_port(&self) -> Option<u16> {
        (50000..60000).find(|port| net::TcpListener::bind((CONST_SERVER_ADDR, *port)).is_ok())
    }

    fn init_server(&self, port: u16) -> net::TcpListener {
        net::TcpListener::bind((CONST_SERVER_ADDR, port)).expect("Bind error")
    }

    fn run_client(&self, port: u16, version: TlsVersion) -> thread::JoinHandle<c_ulong> {
        let sock = net::TcpStream::connect((CONST_SERVER_ADDR, port)).expect("Connect error");
        thread::spawn(move || {
            let method = get_method_by_version(&version, false);
            let session = TabbyTestSession::new_client_session(method, sock.as_raw_fd());
            if session.is_err() {
                return 1; // SSL handshake failed
            }
            let session = session.unwrap();

            let _ = session.write(b"Hello server");

            let mut rd_buf = [0u8; 64];
            let _ = session.read(&mut rd_buf);
            let ssl_error = session.get_error();
            if ssl_error != 0 {
                return ssl_error as u64;
            }
            TabbyTestDriver::test_cipher(session.ssl, &version);
            let _ = session.shutdown();
            0
        })
    }

    fn test_cipher(ssl: *mut SSL, version: &TlsVersion) {
        let cipher_name_ptr = SSL_get_cipher_name(ssl);
        let cipher_name = unsafe { ffi::CStr::from_ptr(cipher_name_ptr).to_str().unwrap() };
        match version {
            TlsVersion::Tlsv12 => {
                assert_eq!(cipher_name, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
            }
            TlsVersion::Tlsv13 => assert_eq!(cipher_name, "TLS13_AES_256_GCM_SHA384"),
            _ => (),
        };

        let cipher_version_ptr = SSL_get_cipher_version(ssl);
        let cipher_version = unsafe { ffi::CStr::from_ptr(cipher_version_ptr).to_str().unwrap() };
        match version {
            TlsVersion::Tlsv12 => assert_eq!(cipher_version, "TLS1.2"),
            TlsVersion::Tlsv13 => assert_eq!(cipher_version, "TLS1.3"),
            _ => (),
        };

        let ssl_version_ptr = SSL_get_version(ssl);
        let ssl_version = unsafe { ffi::CStr::from_ptr(ssl_version_ptr).to_str().unwrap() };
        match version {
            TlsVersion::Tlsv12 => assert_eq!(ssl_version, "TLS1.2"),
            TlsVersion::Tlsv13 => assert_eq!(ssl_version, "TLS1.3"),
            _ => (),
        };
    }

    fn run_server(
        &self,
        server: net::TcpListener,
        version: TlsVersion,
    ) -> thread::JoinHandle<c_ulong> {
        let sock = server.incoming().next().unwrap().expect("Accept error");
        thread::spawn(move || {
            let method = get_method_by_version(&version, true);
            let session = TabbyTestSession::new_server_session(method, sock.as_raw_fd());
            if session.is_err() {
                return 1; // SSL handshake failed
            }
            let session = session.unwrap();
            ERR_clear_error();
            let mut rd_buf = [0u8; 64];
            let _ = session.read(&mut rd_buf);

            TabbyTestDriver::test_cipher(session.ssl, &version);
            ERR_clear_error();
            let _ = session.write(b"Hello client");
            let ssl_error = session.get_error();
            let _ = session.shutdown();
            if ssl_error != 0 {
                return ssl_error as u64;
            }
            0
        })
    }

    fn transfer(&self, client_version: TlsVersion, server_version: TlsVersion, should_fail: bool) {
        let port = self
            .get_unused_port()
            .expect("No port between 50000-60000 is available");
        let server = self.init_server(port);
        let client_thread = self.run_client(port, client_version);
        let server_thread = self.run_server(server, server_version);
        let client_ret = client_thread.join();
        let server_ret = server_thread.join();
        assert_ne!(should_fail, client_ret.is_ok() && client_ret.unwrap() == 0);
        assert_ne!(should_fail, server_ret.is_ok() && server_ret.unwrap() == 0);
    }
}

#[test]
fn supported_tls_versions() {
    let method_ptr = SSLv23_client_method();
    assert_ne!(method_ptr, ptr::null());
    let _ = unsafe { Box::from_raw(method_ptr as *mut SSL_METHOD) };

    let method_ptr = TLSv1_2_client_method();
    assert_ne!(method_ptr, ptr::null());
    let _ = unsafe { Box::from_raw(method_ptr as *mut SSL_METHOD) };

    let method_ptr = TLSv1_2_client_method();
    assert_ne!(method_ptr, ptr::null());
    let _ = unsafe { Box::from_raw(method_ptr as *mut SSL_METHOD) };

    let method_ptr = TLSv1_2_server_method();
    assert_ne!(method_ptr, ptr::null());
    let _ = unsafe { Box::from_raw(method_ptr as *mut SSL_METHOD) };

    let method_ptr = TLS_method();
    assert_ne!(method_ptr, ptr::null());
    let _ = unsafe { Box::from_raw(method_ptr as *mut SSL_METHOD) };

    let method_ptr = TLS_client_method();
    assert_ne!(method_ptr, ptr::null());
    let _ = unsafe { Box::from_raw(method_ptr as *mut SSL_METHOD) };

    let method_ptr = TLS_server_method();
    assert_ne!(method_ptr, ptr::null());
    let _ = unsafe { Box::from_raw(method_ptr as *mut SSL_METHOD) };
}

#[test]
fn legacy_tls_versions_not_supported() {
    assert_eq!(SSLv3_client_method(), ptr::null());
    assert_eq!(TLSv1_client_method(), ptr::null());
    assert_eq!(TLSv1_1_client_method(), ptr::null());
    assert_eq!(SSLv3_server_method(), ptr::null());
    assert_eq!(TLSv1_server_method(), ptr::null());
    assert_eq!(TLSv1_1_server_method(), ptr::null());
}

fn transfer_test(client_version: TlsVersion, server_version: TlsVersion, should_fail: bool) {
    let driver = TabbyTestDriver::new();
    driver.transfer(client_version, server_version, should_fail);
}

#[test]
fn cross_version_tests() {
    //transfer_test(TlsVersion::Both, TlsVersion::Both, false);
    transfer_test(TlsVersion::Tlsv12, TlsVersion::Tlsv12, false);
    transfer_test(TlsVersion::Tlsv13, TlsVersion::Tlsv13, false);
    /*transfer_test(TlsVersion::Both, TlsVersion::Tlsv13, false);
    transfer_test(TlsVersion::Tlsv13, TlsVersion::Both, false);
    transfer_test(TlsVersion::Tlsv12, TlsVersion::Both, false);
    transfer_test(TlsVersion::Both, TlsVersion::Tlsv12, false);
    transfer_test(TlsVersion::Tlsv13, TlsVersion::Tlsv12, true);
    transfer_test(TlsVersion::Tlsv12, TlsVersion::Tlsv13, true);*/
}

#[test]
fn ssl_io_on_bad_file_descriptor() {
    let sock = unsafe { net::TcpStream::from_raw_fd(4526) };
    let ctx = SSL_CTX_new(SSLv23_client_method());
    let ssl = SSL_new(ctx);
    assert_eq!(
        SSL_SUCCESS,
        SSL_set_tlsext_host_name(ssl, b"google.com\0".as_ptr() as *const c_char)
    );
    assert_eq!(SSL_SUCCESS, SSL_set_fd(ssl, sock.as_raw_fd()));
    assert_eq!(SSL_SUCCESS, SSL_connect(ssl));

    let mut buf = [0u8; 64];
    assert_eq!(
        SSL_FAILURE,
        SSL_read(ssl, buf.as_mut_ptr() as *mut c_void, 64)
    );
    assert_eq!(
        SSL_FAILURE,
        SSL_write(ssl, buf.as_ptr() as *const c_void, 64)
    );
    assert_eq!(SSL_FAILURE, SSL_flush(ssl));

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

#[test]
fn ssl_on_nonblocking_socket() {
    let sock = net::TcpStream::connect("google.com:443").expect("Conenction failed");
    assert!(sock.set_nonblocking(true).is_ok());
    let ctx = SSL_CTX_new(SSLv23_client_method());
    let ssl = SSL_new(ctx);
    assert_eq!(
        SSL_SUCCESS,
        SSL_set_tlsext_host_name(ssl, b"google.com\0".as_ptr() as *const c_char)
    );
    assert_eq!(SSL_SUCCESS, SSL_set_fd(ssl, sock.as_raw_fd()));
    assert_eq!(SSL_SUCCESS, SSL_connect(ssl));
    let mut buf = [0u8; 64];
    assert_eq!(
        SSL_ERROR,
        SSL_read(ssl, buf.as_mut_ptr() as *mut c_void, 64)
    );

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

#[test]
fn ssl_ctx_is_not_null() {
    let ctx_ptr = SSL_CTX_new(TLS_client_method());
    assert_ne!(ctx_ptr, ptr::null_mut());
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn ssl_is_not_null() {
    let ctx_ptr = SSL_CTX_new(TLS_client_method());
    let ssl_ptr = SSL_new(ctx_ptr);
    assert_ne!(ctx_ptr, ptr::null_mut());
    SSL_free(ssl_ptr);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn load_verify_locations() {
    let ctx_ptr = SSL_CTX_new(TLS_client_method());
    assert_eq!(
        SSL_FAILURE,
        SSL_CTX_load_verify_locations(ctx_ptr, ptr::null(), ptr::null())
    );
    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_load_verify_locations(
            ctx_ptr,
            b"tests/certs/curl-root-ca.crt\0".as_ptr() as *const c_char,
            ptr::null()
        )
    );
    /*assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_load_verify_locations(
            ctx_ptr,
            ptr::null(),
            b"tests/root_store\0".as_ptr() as *const c_char,
        )
    );*/
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn certificate_not_found() {
    let ctx_ptr = SSL_CTX_new(TLS_server_method());
    assert_ne!(
        SSL_SUCCESS,
        SSL_CTX_use_certificate_chain_file(
            ctx_ptr,
            b"you_do_not_find_me".as_ptr() as *const c_char,
            0
        )
    );
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn private_key_not_found() {
    let ctx_ptr = SSL_CTX_new(TLS_server_method());
    assert_ne!(
        SSL_SUCCESS,
        SSL_CTX_use_PrivateKey_file(
            ctx_ptr,
            b"you_do_not_find_me\0".as_ptr() as *const c_char,
            0
        )
    );
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn invalid_certificate() {
    let ctx_ptr = SSL_CTX_new(TLS_server_method());
    assert_ne!(
        SSL_SUCCESS,
        SSL_CTX_use_certificate_chain_file(
            ctx_ptr,
            b"tests/bad.chain\0".as_ptr() as *const c_char,
            0
        )
    );
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn invalid_private_key() {
    let ctx_ptr = SSL_CTX_new(TLS_server_method());
    assert_ne!(
        SSL_SUCCESS,
        SSL_CTX_use_PrivateKey_file(ctx_ptr, b"tests/bad.certs\0".as_ptr() as *const c_char, 0)
    );
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn verify_certificate_and_key() {
    let ctx_ptr = SSL_CTX_new(TLS_server_method());
    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_use_certificate_chain_file(
            ctx_ptr,
            CONST_SERVER_CERT_CHAIN_FILE.as_ptr() as *const c_char,
            0
        )
    );
    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_use_PrivateKey_file(ctx_ptr, CONST_SERVER_KEY_FILE.as_ptr() as *const c_char, 0)
    );
    assert_eq!(SSL_SUCCESS, SSL_CTX_check_private_key(ctx_ptr));
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn verify_key_and_certificate_1() {
    let ctx_ptr = SSL_CTX_new(TLS_server_method());
    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_use_PrivateKey_file(ctx_ptr, CONST_SERVER_KEY_FILE.as_ptr() as *const c_char, 0)
    );
    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_use_certificate_chain_file(
            ctx_ptr,
            CONST_SERVER_CERT_CHAIN_FILE.as_ptr() as *const c_char,
            0
        )
    );
    assert_eq!(SSL_SUCCESS, SSL_CTX_check_private_key(ctx_ptr));
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn verify_key_and_certificate_2() {
    use tabbyssl::libcrypto::{bio, evp, pem};

    let ctx_ptr = SSL_CTX_new(TLS_server_method());

    // Load the private key
    let bio_pkey_ptr = bio::BIO_new_file(
        CONST_SERVER_KEY_FILE.as_ptr() as *const c_char,
        b"r\0".as_ptr() as *const c_char,
    );
    assert_ne!(bio_pkey_ptr, ptr::null_mut());
    let pkey_ptr = pem::PEM_read_bio_PrivateKey(
        bio_pkey_ptr,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_ne!(pkey_ptr, ptr::null_mut());
    assert_eq!(SSL_SUCCESS, SSL_CTX_use_PrivateKey(ctx_ptr, pkey_ptr));

    // Load the end entity cert
    let bio_x509_cert_ptr = bio::BIO_new_file(
        CONST_SERVER_CERT_FILE.as_ptr() as *const c_char,
        b"r\0".as_ptr() as *const c_char,
    );
    assert_ne!(bio_x509_cert_ptr, ptr::null_mut());
    let x509_cert_ptr = pem::PEM_read_bio_X509(
        bio_x509_cert_ptr,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_ne!(x509_cert_ptr, ptr::null_mut());

    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_use_certificate(ctx_ptr, x509_cert_ptr,)
    );

    // Load the intermediate CA cert
    let bio_x509_inter_ca_ptr = bio::BIO_new_file(
        CONST_INTER_CA_FILE.as_ptr() as *const c_char,
        b"r\0".as_ptr() as *const c_char,
    );
    assert_ne!(bio_x509_inter_ca_ptr, ptr::null_mut());
    let x509_inter_ca_ptr = pem::PEM_read_bio_X509(
        bio_x509_inter_ca_ptr,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_ne!(x509_inter_ca_ptr, ptr::null_mut());

    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_add_extra_chain_cert(ctx_ptr, x509_inter_ca_ptr)
    );

    // Load the CA cert
    let bio_x509_ca_ptr = bio::BIO_new_file(
        CONST_CA_FILE.as_ptr() as *const c_char,
        b"r\0".as_ptr() as *const c_char,
    );
    assert_ne!(bio_x509_ca_ptr, ptr::null_mut());
    let x509_ca_ptr = pem::PEM_read_bio_X509(
        bio_x509_ca_ptr,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_ne!(x509_ca_ptr, ptr::null_mut());

    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_add_extra_chain_cert(ctx_ptr, x509_ca_ptr)
    );

    // Check the private key and certificate
    assert_eq!(SSL_SUCCESS, SSL_CTX_check_private_key(ctx_ptr));

    X509_free(x509_cert_ptr);
    X509_free(x509_inter_ca_ptr);
    X509_free(x509_ca_ptr);
    evp::EVP_PKEY_free(pkey_ptr);
    bio::BIO_free(bio_pkey_ptr);
    bio::BIO_free(bio_x509_cert_ptr);
    bio::BIO_free(bio_x509_inter_ca_ptr);
    bio::BIO_free(bio_x509_ca_ptr);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn ssl_ctx_load_certificate_and_private_key_asn1() {
    let certificate_bytes = include_bytes!("certs/end.cert.der");
    let private_key_bytes = include_bytes!("certs/end.key.der");
    let ctx_ptr = SSL_CTX_new(TLS_server_method());
    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_use_certificate_ASN1(
            ctx_ptr,
            certificate_bytes.len() as c_int,
            certificate_bytes.as_ptr() as *mut c_uchar,
        )
    );
    assert_eq!(
        SSL_SUCCESS,
        SSL_CTX_use_PrivateKey_ASN1(
            0,
            ctx_ptr,
            private_key_bytes.as_ptr() as *mut c_uchar,
            private_key_bytes.len() as c_long,
        )
    );
    assert_eq!(SSL_SUCCESS, SSL_CTX_check_private_key(ctx_ptr));
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn ssl_load_certificate_and_private_key_asn1() {
    let certificate_bytes = include_bytes!("certs/end.cert.der");
    let private_key_bytes = include_bytes!("certs/end.key.der");
    let ctx_ptr = SSL_CTX_new(TLS_server_method());
    let ssl_ptr = SSL_new(ctx_ptr);
    assert_eq!(
        SSL_SUCCESS,
        SSL_use_PrivateKey_ASN1(
            0,
            ssl_ptr,
            private_key_bytes.as_ptr() as *mut c_uchar,
            private_key_bytes.len() as c_long,
        )
    );
    assert_eq!(
        SSL_SUCCESS,
        SSL_use_certificate_ASN1(
            ssl_ptr,
            certificate_bytes.as_ptr() as *mut c_uchar,
            certificate_bytes.len() as c_int,
        )
    );
    assert_eq!(SSL_SUCCESS, SSL_check_private_key(ssl_ptr));
    let new_ctx_ptr = SSL_get_SSL_CTX(ssl_ptr) as *mut SSL_CTX_ARC;
    assert_eq!(SSL_SUCCESS, SSL_CTX_check_private_key(new_ctx_ptr));
    SSL_free(ssl_ptr);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn get_ssl_fd() {
    let ctx_ptr = SSL_CTX_new(TLS_client_method());
    let ssl_ptr = SSL_new(ctx_ptr);
    let sock = net::TcpStream::connect("8.8.8.8:53").expect("Connect error");
    let fd: c_int = sock.as_raw_fd();
    assert_eq!(SSL_SUCCESS, SSL_set_fd(ssl_ptr, fd));
    assert_eq!(fd, SSL_get_fd(ssl_ptr));
    SSL_free(ssl_ptr);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn get_and_set_ssl_ctx() {
    let ctx_ptr = SSL_CTX_new(TLSv1_2_client_method());
    let ssl_ptr = SSL_new(ctx_ptr);
    let ctx_ptr_2 = SSL_CTX_new(TLSv1_3_client_method());
    let ctx_ptr_3 = SSL_set_SSL_CTX(ssl_ptr, ctx_ptr_2);
    let ctx_ptr_4 = SSL_get_SSL_CTX(ssl_ptr);
    assert_eq!(ctx_ptr_3, ctx_ptr_4);
    SSL_free(ssl_ptr);
    SSL_CTX_free(ctx_ptr_2);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn dummy_openssl_compatible_apis_always_return_success() {
    assert_eq!(SSL_SUCCESS, SSL_library_init());
    assert_eq!(SSL_SUCCESS, OpenSSL_add_ssl_algorithms());
}

#[test]
fn ssl_set_null_host_name() {
    let ctx_ptr = SSL_CTX_new(TLSv1_2_client_method());
    let ssl_ptr = SSL_new(ctx_ptr);
    assert_ne!(
        SSL_SUCCESS,
        SSL_set_tlsext_host_name(ssl_ptr, ptr::null() as *const c_char)
    );
    SSL_free(ssl_ptr);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn ssl_set_invalid_host_name() {
    let ctx_ptr = SSL_CTX_new(TLSv1_2_client_method());
    let ssl_ptr = SSL_new(ctx_ptr);
    assert_ne!(
        SSL_SUCCESS,
        SSL_set_tlsext_host_name(ssl_ptr, b"@#$%^&*(\0".as_ptr() as *const c_char)
    );
    SSL_free(ssl_ptr);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn ssl_set_good_host_name() {
    let ctx_ptr = SSL_CTX_new(TLSv1_2_client_method());
    let ssl_ptr = SSL_new(ctx_ptr);
    assert_eq!(
        SSL_SUCCESS,
        SSL_set_tlsext_host_name(ssl_ptr, b"google.com\0".as_ptr() as *const c_char)
    );
    SSL_free(ssl_ptr);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn ssl_ctx_session_cache_mode_and_size() {
    let ctx_ptr = SSL_CTX_new(TLSv1_2_client_method());
    // Default cache mode is Both
    assert_eq!(SSL_CTX_get_session_cache_mode(ctx_ptr), 3);
    // Default cache size is SSL_SESSION_CACHE_MAX_SIZE_DEFAULT
    assert_eq!(SSL_CTX_sess_get_cache_size(ctx_ptr), 256);
    // When cache mode is both, set the cache size to 100
    assert_eq!(SSL_CTX_sess_set_cache_size(ctx_ptr, 100), 256);
    // Turn off session cache
    assert_eq!(SSL_CTX_set_session_cache_mode(ctx_ptr, 0), 3);
    // Now the cache mode is Off
    assert_eq!(SSL_CTX_get_session_cache_mode(ctx_ptr), 0);
    // The cache size to 100
    assert_eq!(SSL_CTX_sess_get_cache_size(ctx_ptr), 100);
    // When cache mode is Off, set the cache size to 200
    assert_eq!(SSL_CTX_sess_set_cache_size(ctx_ptr, 200), 100);
    // Set the cache mode to Client
    assert_eq!(SSL_CTX_set_session_cache_mode(ctx_ptr, 1), 0);
    assert_eq!(SSL_CTX_get_session_cache_mode(ctx_ptr), 1);
    // The cache size to 100
    assert_eq!(SSL_CTX_sess_get_cache_size(ctx_ptr), 200);
    // When cache mode is Client, set the cache size to 300
    assert_eq!(SSL_CTX_sess_set_cache_size(ctx_ptr, 300), 200);
    // Set the cache mode to Server
    assert_eq!(SSL_CTX_set_session_cache_mode(ctx_ptr, 2), 1);
    // Now the cache mode is Server
    assert_eq!(SSL_CTX_get_session_cache_mode(ctx_ptr), 2);
    // The cache size to 300
    assert_eq!(SSL_CTX_sess_get_cache_size(ctx_ptr), 300);
    // When cache mode is Server, set the cache size to 400
    assert_eq!(SSL_CTX_sess_set_cache_size(ctx_ptr, 400), 300);
    assert_eq!(SSL_CTX_set_session_cache_mode(ctx_ptr, 3), 2);
    assert_eq!(SSL_CTX_get_session_cache_mode(ctx_ptr), 3);
    SSL_CTX_free(ctx_ptr);
}

#[test]
fn test_null_pointers_as_arguments() {
    assert_eq!(
        SSL_FAILURE,
        SSL_CTX_use_certificate_chain_file(ptr::null_mut(), ptr::null_mut(), 0)
    );
    assert_eq!(
        SSL_FAILURE,
        SSL_CTX_use_PrivateKey_file(ptr::null_mut(), ptr::null_mut(), 0)
    );
    let version_str_ptr_1 = SSL_CIPHER_get_version(ptr::null_mut());
    let version_str_1 = unsafe { ffi::CStr::from_ptr(version_str_ptr_1).to_str().unwrap() };
    assert_eq!(" NONE ", version_str_1);

    let version_str_ptr_2 = SSL_get_cipher(ptr::null_mut());
    assert_eq!(ptr::null(), version_str_ptr_2);

    assert_eq!(SSL_FAILURE, SSL_read(ptr::null_mut(), ptr::null_mut(), 100));
    assert_eq!(
        SSL_FAILURE,
        SSL_write(ptr::null_mut(), ptr::null_mut(), 100)
    );
    assert_eq!(SSL_FAILURE, SSL_flush(ptr::null_mut()));
    assert_eq!(
        SSL_FAILURE,
        SSL_write_early_data(ptr::null_mut(), ptr::null_mut(), 100, ptr::null_mut())
    );
    let buf = [0u8; 10];
    assert_eq!(
        SSL_FAILURE,
        SSL_write_early_data(
            ptr::null_mut(),
            buf.as_ptr() as *const c_uchar,
            10,
            ptr::null_mut()
        )
    );
}

#[test]
fn test_io_before_full_handshake() {
    let ctx = SSL_CTX_new(TLS_client_method());
    let ssl = SSL_new(ctx);
    let mut buf = [0u8; 10];
    assert_eq!(
        SSL_FAILURE,
        SSL_read(ssl, buf.as_mut_ptr() as *mut c_void, 10)
    );
    assert_eq!(
        SSL_FAILURE,
        SSL_write(ssl, buf.as_ptr() as *const c_void, 10)
    );
    let wr_len_ptr = Box::into_raw(Box::new(0));
    assert_eq!(
        SSL_FAILURE,
        SSL_write_early_data(ssl, buf.as_ptr() as *const c_uchar, 10, wr_len_ptr)
    );
    let _ = unsafe { Box::from_raw(wr_len_ptr) };
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
