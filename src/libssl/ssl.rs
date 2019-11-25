/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

//! # Synopsis
//! This sub-module implements the necessary APIs to establish a TLS session.
//! All the APIs are compatible to their OpenSSL counterparts.
//!
//! # Usage
//! The first step is to create a `SSL_CTX` object with `SSL_CTX_new`.
//!
//! Then `SSL_CTX_use_certificate_chain_file` and `SSL_CTX_use_PrivateKey_file`
//! must be called to set up the certificate and private key if the context is
//! to be used in a TLS server.
//!
//! When a TCP socket has been created, an `SSL` object can be created with
//! `SSL_new`. Afterwards, the socket can be assigned to the `SSL` object with
//! `SSL_set_fd`.
//!
//! Then the TLS handshake is performed using `SSL_connect` or `SSL_accept` for
//! a client or a server respectively. `SSL_read` and `SSL_write` are used to
//! read and write data on the TLS connection. Finally, `SSL_shutdown` can be
//! used to shut down the connection.

// Module imports

use super::cache::{ClientSessionMemoryCache, ServerSessionMemoryCache};
use super::err::{ErrorCode, MesalinkError, MesalinkInnerResult, OpensslError};
use super::safestack::TABBY_STACK_TABBY_X509;
use super::x509::TABBY_X509;
use super::{SslSessionCacheModes, SSL_ERROR, SSL_FAILURE, SSL_SUCCESS};
use crate::error_san::*;
use crate::libcrypto::evp::TABBY_EVP_PKEY;
use crate::{OpaquePointerGuard, MAGIC, MAGIC_SIZE};
use libc::{c_char, c_int, c_long, c_uchar, c_void, size_t};
use parking_lot::RwLock;
use rustls;
use std::sync::Arc;
use std::{ffi, fs, io, net, path, ptr, slice};
use webpki;

// Trait imports
use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};

const SSL_SESSION_CACHE_MAX_SIZE_DEFAULT: usize = 1024 * 20;

#[cfg(not(feature = "error_strings"))]
const CONST_NOTBUILTIN_STR: &'static [u8] = b"(Ciphersuite string not built-in)\0";

/// An OpenSSL Cipher object
#[allow(non_camel_case_types)]
pub struct TABBY_CIPHER {
    magic: [u8; MAGIC_SIZE],
    ciphersuite: &'static rustls::SupportedCipherSuite,
}

impl OpaquePointerGuard for TABBY_CIPHER {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl TABBY_CIPHER {
    fn new(ciphersuite: &'static rustls::SupportedCipherSuite) -> TABBY_CIPHER {
        TABBY_CIPHER {
            magic: *MAGIC,
            ciphersuite,
        }
    }
}

/// A dispatch structure describing the internal ssl library methods/functions
/// which implement the various protocol versions such as TLS v1.2.
///
/// This is a structure describing a specific TLS protocol version. It can be
/// created with a method like `TLSv1_2_client_method`. Then `SSL_CTX_new` can
/// consume it and create a new context. Note that a `SSL_METHOD` object is
/// implicitly freed in `SSL_CTX_new`. To avoid double free, do NOT reuse
/// `SSL_METHOD` objects; always create new ones when needed.
#[allow(non_camel_case_types)]
pub struct TABBY_METHOD {
    magic: [u8; MAGIC_SIZE],
    versions: Vec<rustls::ProtocolVersion>,
    mode: ClientOrServerMode,
}

#[derive(Clone, PartialEq)]
enum ClientOrServerMode {
    Client,
    Server,
    Both,
}

impl OpaquePointerGuard for TABBY_METHOD {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl TABBY_METHOD {
    fn new(versions: Vec<rustls::ProtocolVersion>, mode: ClientOrServerMode) -> TABBY_METHOD {
        TABBY_METHOD {
            magic: *MAGIC,
            versions,
            mode,
        }
    }
}

struct NoServerAuth {}
impl rustls::ServerCertVerifier for NoServerAuth {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef<'_>,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

struct ClientSessionCache {
    cache: Arc<ClientSessionMemoryCache>,
}

impl ClientSessionCache {
    fn with_capacity(cache_size: usize) -> Arc<ClientSessionCache> {
        let session_cache = ClientSessionCache {
            cache: ClientSessionMemoryCache::new(cache_size),
        };
        Arc::new(session_cache)
    }
}

impl rustls::StoresClientSessions for ClientSessionCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        if key.len() > 2 && key[0] == b'k' && key[1] == b'x' {
            true
        } else {
            self.cache.put(key, value)
        }
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.get(key)
    }
}

/// A global context structure which is created by a server or a client once per
/// program. It holds default values for `SSL` objects which are later created
/// for individual connections.
///
/// Pass a valid `SSL_METHOD` object to `SSL_CTX_new` to create a `SSL_CTX`
/// object. Note that only TLS 1.2 and 1.3 (draft 18) are supported.
///
/// For a context to be used in a TLS server, call
/// `SSL_CTX_use_certificate_chain_file` and `SSL_CTX_use_PrivateKey_file` to
/// set the certificates and private key. Otherwise, `SSL_accept` would fail and
/// return an error code `NoCertificatesPresented`. If the context is created
/// for a TLS client, no further action is needed as MesaLink has built-in root
/// CA certificates and default ciphersuites. Support for configurable
/// ciphersuites will be added soon in the next release.
#[allow(non_camel_case_types)]
#[derive(Clone)]
pub struct TABBY_CTX {
    magic: [u8; MAGIC_SIZE],
    client_config: rustls::ClientConfig,
    server_config: rustls::ServerConfig,
    certificates: Option<Vec<rustls::Certificate>>,
    private_key: Option<rustls::PrivateKey>,
    ca_roots: rustls::RootCertStore,
    session_cache_mode: SslSessionCacheModes,
    session_cache_size: usize,
    mode: ClientOrServerMode,
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
pub type TABBY_CTX_ARC = Arc<TABBY_CTX>;

impl OpaquePointerGuard for TABBY_CTX_ARC {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl TABBY_CTX {
    fn new(method: &TABBY_METHOD) -> TABBY_CTX {
        let mut client_config = rustls::ClientConfig::new();
        let mut server_config = rustls::ServerConfig::new(rustls::NoClientAuth::new());

        client_config.versions.clear();
        server_config.versions.clear();

        for v in &method.versions {
            client_config.versions.push(*v);
            server_config.versions.push(*v);
        }

        client_config.set_persistence(ClientSessionCache::with_capacity(
            SSL_SESSION_CACHE_MAX_SIZE_DEFAULT,
        ));
        server_config.set_persistence(ServerSessionMemoryCache::new(
            SSL_SESSION_CACHE_MAX_SIZE_DEFAULT,
        ));

        client_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        client_config.enable_early_data = true;
        server_config.ticketer = rustls::Ticketer::new(); // Enable ticketing for server

        TABBY_CTX {
            magic: *MAGIC,
            client_config,
            server_config,
            certificates: None,
            private_key: None,
            ca_roots: rustls::RootCertStore::empty(),
            session_cache_mode: SslSessionCacheModes::Both,
            session_cache_size: SSL_SESSION_CACHE_MAX_SIZE_DEFAULT,
            mode: method.mode.clone(),
        }
    }
}

enum ClientOrServerSession {
    Client(rustls::ClientSession),
    Server(rustls::ServerSession),
}

impl Deref for ClientOrServerSession {
    type Target = dyn rustls::Session;

    fn deref(&self) -> &Self::Target {
        match &self {
            ClientOrServerSession::Client(ref c) => c,
            ClientOrServerSession::Server(ref s) => s,
        }
    }
}

impl DerefMut for ClientOrServerSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            ClientOrServerSession::Client(ref mut c) => c,
            ClientOrServerSession::Server(ref mut s) => s,
        }
    }
}

impl ClientOrServerSession {
    fn assert_client(&mut self) -> &mut rustls::ClientSession {
        match self {
            ClientOrServerSession::Client(ref mut c) => c,
            ClientOrServerSession::Server(_) => panic!("ClientSession required here"),
        }
    }
}

/// The main TLS structure which is created by a server or client per
/// established connection.
///
/// Pass a valid `SSL_CTX` object to `SSL_new` to create a new `SSL` object.
/// Then associate a valid socket file descriptor with `SSL_set_fd`.
#[allow(non_camel_case_types)]
pub struct TABBY_SSL {
    magic: [u8; MAGIC_SIZE],
    context: Option<TABBY_CTX_ARC>,
    client_config: Arc<rustls::ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
    hostname: Option<String>,
    io: Option<net::TcpStream>,
    session: Option<RwLock<ClientOrServerSession>>,
    error: ErrorCode,
    eof: bool,
    mode: ClientOrServerMode,
}

impl OpaquePointerGuard for TABBY_SSL {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl Drop for TABBY_SSL {
    fn drop(&mut self) {
        if self.io.is_some() {
            let stream_owned = std::mem::replace(&mut self.io, None).unwrap();
            // Leak the file descriptor so that the C caller can close it.
            #[cfg(unix)]
            let _ = stream_owned.into_raw_fd();
            #[cfg(windows)]
            let _ = stream_owned.into_raw_socket();
        }
    }
}

fn complete_io(
    session: &mut ClientOrServerSession,
    io: &mut net::TcpStream,
) -> Result<(usize, usize), MesalinkError> {
    let until_handshaked = session.is_handshaking();
    let mut wrlen = 0;
    let mut rdlen = 0;
    let mut eof = false;
    loop {
        while session.wants_write() {
            match session.write_tls(io) {
                Ok(n) => wrlen += n,
                Err(e) => {
                    return match e.kind() {
                        io::ErrorKind::WouldBlock => Err(error!(OpensslError::WantWrite.into())),
                        _ => Err(error!(e.into())),
                    };
                }
            }
        }
        if !until_handshaked && wrlen > 0 {
            return Ok((wrlen, rdlen));
        }
        if !eof && session.wants_read() {
            match session.read_tls(io) {
                Ok(0) => eof = true,
                Ok(n) => rdlen += n,
                Err(e) => {
                    return match e.kind() {
                        io::ErrorKind::WouldBlock => Err(error!(OpensslError::WantRead.into())),
                        _ => Err(error!(e.into())),
                    };
                }
            }
        }
        if let Err(tls_err) = session.process_new_packets() {
            // flush io to send any unsent alerts
            let _ignored = session.write_tls(io);
            return Err(error!(tls_err.into()));
        }
        match (eof, until_handshaked, session.is_handshaking()) {
            (_, true, false) => return Ok((rdlen, wrlen)),
            (_, false, _) => return Ok((rdlen, wrlen)),
            (true, true, true) => {
                return Err(error!(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF"
                )
                .into()));
            }
            (..) => (),
        }
    }
}

impl TABBY_SSL {
    fn new(ctx: &TABBY_CTX_ARC) -> TABBY_SSL {
        TABBY_SSL {
            magic: *MAGIC,
            context: Some(ctx.clone()), // reference count +1
            client_config: Arc::new(ctx.client_config.clone()),
            server_config: Arc::new(ctx.server_config.clone()),
            hostname: None,
            io: None,
            session: None,
            error: ErrorCode::default(),
            eof: false,
            mode: ctx.mode.clone(),
        }
    }

    pub(crate) fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, MesalinkError> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => loop {
                let mut session = session.write(); // Lock read
                match session.read(buf) {
                    Ok(0) => match complete_io(&mut session, io) {
                        Err(e) => return Err(e),
                        Ok((rdlen, wrlen)) => {
                            if rdlen == 0 && wrlen == 0 {
                                self.eof = true;
                                return Ok(0);
                            }
                        }
                    },
                    Ok(n) => {
                        self.error = ErrorCode::default();
                        return Ok(n);
                    }
                    Err(e) => {
                        let error = error!(e.into());
                        self.error = ErrorCode::from(&error);
                        return Err(error);
                    }
                }
            },
            _ => Err(error!(OpensslError::BadFuncArg.into())),
        }
    }

    pub(crate) fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, MesalinkError> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => {
                let mut session = session.write();
                let len = session.write(buf).map_err(|e| error!(e.into()))?;
                match session.write_tls(io) {
                    Ok(_) => Ok(len),
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock => Err(error!(OpensslError::WantWrite.into())),
                        _ => Err(error!(e.into())),
                    },
                }
            }
            _ => Err(error!(OpensslError::BadFuncArg.into())),
        }
    }

    pub(crate) fn ssl_flush(&mut self) -> Result<(), MesalinkError> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => {
                let mut session = session.write();
                session.flush().map_err(|e| error!(e.into()))?;
                match session.write_tls(io) {
                    Ok(_) => Ok(()),
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock => Err(error!(OpensslError::WantWrite.into())),
                        _ => Err(error!(e.into())),
                    },
                }
            }
            _ => Err(error!(OpensslError::BadFuncArg.into())),
        }
    }

    pub(crate) fn ssl_write_early_data(&mut self, buf: &[u8]) -> Result<usize, MesalinkError> {
        use std::io::Write;
        match self.session.as_mut() {
            Some(session) => {
                let mut session = session.write();
                let client_session = session.deref_mut().assert_client();
                let mut early_writer = client_session.early_data().ok_or(error!(
                    io::Error::new(io::ErrorKind::InvalidData, "Early data not supported").into()
                ))?;
                // WriteEarlyData::write() does not really write I/O.
                // It is still necessary to call complete_io to drive handshaking.
                match early_writer.write(buf) {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        // EarlyData::check_write() returns io::ErrorKind::InvalidIput if
                        let error = error!(e.into());
                        self.error = ErrorCode::from(&error);
                        Err(error)
                    }
                }
            }
            _ => Err(error!(OpensslError::BadFuncArg.into())),
        }
    }
}

use bitflags::bitflags;
bitflags! {
    #[derive(Default)]
    struct VerifyModes: i32 {
        const VERIFY_NONE = 0x00;
        const VERIFY_PEER   = 0x01;
        const VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
    }
}

/// For OpenSSL compatibility only. Always returns 1.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_library_init(void);
/// int OpenSSL_add_ssl_algorithms(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_library_init() -> c_int {
    /* compatibility only */
    SSL_SUCCESS
}

#[cfg(feature = "error_strings")]
fn init_logger() {
    env_logger::init();
}

#[cfg(not(feature = "error_strings"))]
fn init_logger() {}

/// For OpenSSL compatibility only. Always returns 1.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_library_init(void);
/// int OpenSSL_add_ssl_algorithms(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_add_ssl_algorithms() -> c_int {
    /* compatibility only */
    SSL_SUCCESS
}

/// For OpenSSL compatibility only.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_load_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_load_error_strings() {
    /* compatibility only */
}

/// `SSL_init_logger` turns on debugging output
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_load_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_init_logger() {
    init_logger();
}

fn tabby_not_available_method() -> *const TABBY_METHOD {
    let p: *const TABBY_METHOD = ptr::null();
    p
}

/// A general-purpose version-flexible SSL/TLS method. The supported protocols
/// are TLSv1.2 and TLSv1.3.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLS_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLS_method() -> *const TABBY_METHOD {
    let method = TABBY_METHOD::new(
        vec![
            rustls::ProtocolVersion::TLSv1_3,
            rustls::ProtocolVersion::TLSv1_2,
        ],
        ClientOrServerMode::Both,
    );
    Box::into_raw(Box::new(method))
}

/// A general-purpose version-flexible SSL/TLS method. The supported protocols
/// are TLSv1.2 and TLSv1.3.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLS_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLS_client_method() -> *const TABBY_METHOD {
    let method = TABBY_METHOD::new(
        vec![
            rustls::ProtocolVersion::TLSv1_3,
            rustls::ProtocolVersion::TLSv1_2,
        ],
        ClientOrServerMode::Client,
    );
    Box::into_raw(Box::new(method))
}

/// A general-purpose version-flexible SSL/TLS method. The supported protocols
/// are TLSv1.2 and TLSv1.3.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv23_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_SSLv23_client_method() -> *const TABBY_METHOD {
    tabby_TLS_client_method()
}

/// This SSL/TLS version is not supported. Always return NULL.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv3_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_SSLv3_client_method() -> *const TABBY_METHOD {
    tabby_not_available_method()
}

/// This SSL/TLS version is not supported. Always return NULL.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLSv1_client_method() -> *const TABBY_METHOD {
    tabby_not_available_method()
}

/// This SSL/TLS version is not supported. Always return NULL.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_1_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLSv1_1_client_method() -> *const TABBY_METHOD {
    tabby_not_available_method()
}

/// Version-specific method APIs. A TLS/SSL connection established with these
/// methods will only understand the TLSv1.2 protocol.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_2_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLSv1_2_client_method() -> *const TABBY_METHOD {
    let method = TABBY_METHOD::new(
        vec![rustls::ProtocolVersion::TLSv1_2],
        ClientOrServerMode::Client,
    );
    Box::into_raw(Box::new(method))
}

/// Version-specific method APIs. A TLS/SSL connection established with these
/// methods will only understand the TLSv1.3 protocol.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_3_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLSv1_3_client_method() -> *const TABBY_METHOD {
    let method = TABBY_METHOD::new(
        vec![rustls::ProtocolVersion::TLSv1_3],
        ClientOrServerMode::Client,
    );
    Box::into_raw(Box::new(method))
}

/// A general-purpose version-flexible SSL/TLS method. The supported protocols
/// are TLSv1.2 and TLSv1.3.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLS_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLS_server_method() -> *const TABBY_METHOD {
    let method = TABBY_METHOD::new(
        vec![
            rustls::ProtocolVersion::TLSv1_3,
            rustls::ProtocolVersion::TLSv1_2,
        ],
        ClientOrServerMode::Server,
    );
    Box::into_raw(Box::new(method))
}

/// A general-purpose version-flexible SSL/TLS method. The supported protocols
/// are TLSv1.2 and TLSv1.3.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv23_client_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_SSLv23_server_method() -> *const TABBY_METHOD {
    tabby_TLS_server_method()
}

/// This SSL/TLS version is not supported. Always return NULL.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *SSLv3_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_SSLv3_server_method() -> *const TABBY_METHOD {
    tabby_not_available_method()
}

/// This SSL/TLS version is not supported. Always return NULL.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLSv1_server_method() -> *const TABBY_METHOD {
    tabby_not_available_method()
}

/// This SSL/TLS version is not supported. Always return NULL.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_1_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLSv1_1_server_method() -> *const TABBY_METHOD {
    tabby_not_available_method()
}

/// Version-specific method APIs. A TLS/SSL connection established with these
/// methods will only understand the TLSv1.2 protocol.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_2_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLSv1_2_server_method() -> *const TABBY_METHOD {
    let method = TABBY_METHOD::new(
        vec![rustls::ProtocolVersion::TLSv1_2],
        ClientOrServerMode::Server,
    );
    Box::into_raw(Box::new(method))
}

/// Version-specific method APIs. A TLS/SSL connection established with these
/// methods will only understand the TLSv1.3 protocol.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const SSL_METHOD *TLSv1_3_server_method(void);
/// ```
///
#[no_mangle]
pub extern "C" fn tabby_TLSv1_3_server_method() -> *const TABBY_METHOD {
    let method = TABBY_METHOD::new(
        vec![rustls::ProtocolVersion::TLSv1_3],
        ClientOrServerMode::Server,
    );
    Box::into_raw(Box::new(method))
}

/// `SSL_CTX_new` - create a new SSL_CTX object as framework to establish TLS/SSL
/// enabled connections.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_new(method_ptr: *const TABBY_METHOD) -> *mut TABBY_CTX_ARC {
    check_inner_result!(inner_tabby_ssl_ctx_new(method_ptr), ptr::null_mut())
}

fn inner_tabby_ssl_ctx_new(
    method_ptr: *const TABBY_METHOD,
) -> MesalinkInnerResult<*mut TABBY_CTX_ARC> {
    let method = sanitize_const_ptr_for_ref(method_ptr)?;
    let context = TABBY_CTX::new(method);
    let _ = unsafe { Box::from_raw(method_ptr as *mut TABBY_METHOD) };
    Ok(Box::into_raw(Box::new(Arc::new(context)))) // initialize the referece counter
}

/// `SSL_CTX_load_verify_locations` - specifies the locations for ctx, at which
/// CA certificates for verification purposes are located. The certificates
/// available via CAfile and CApath are trusted.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
///                                   const char *CApath);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_load_verify_locations(
    ctx_ptr: *mut TABBY_CTX_ARC,
    cafile_ptr: *const c_char,
    capath_ptr: *const c_char,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_ctx_load_verify_locations(ctx_ptr, cafile_ptr, capath_ptr),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_ctx_load_verify_locations(
    ctx_ptr: *mut TABBY_CTX_ARC,
    cafile_ptr: *const c_char,
    capath_ptr: *const c_char,
) -> MesalinkInnerResult<c_int> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    if cafile_ptr.is_null() && capath_ptr.is_null() {
        return Err(error!(OpensslError::NullPointer.into()));
    }
    let ctx = util::get_context_mut(ctx);
    if !cafile_ptr.is_null() {
        let cafile = unsafe {
            ffi::CStr::from_ptr(cafile_ptr)
                .to_str()
                .map_err(|_| error!(OpensslError::BadFuncArg.into()))?
        };
        load_cert_into_root_store(ctx, path::Path::new(cafile))?;
    }
    if !capath_ptr.is_null() {
        let capath = unsafe {
            ffi::CStr::from_ptr(capath_ptr)
                .to_str()
                .map_err(|_| error!(OpensslError::BadFuncArg.into()))?
        };
        let dir = fs::read_dir(path::Path::new(capath))
            .map_err(|_| error!(OpensslError::BadFuncArg.into()))?;
        for file_path in dir {
            let file_path = file_path.map_err(|_| error!(OpensslError::BadFuncArg.into()))?;
            load_cert_into_root_store(ctx, &file_path.path())?;
        }
    }
    ctx.client_config.root_store = ctx.ca_roots.clone();
    Ok(SSL_SUCCESS)
}

fn load_cert_into_root_store(ctx: &mut TABBY_CTX, path: &path::Path) -> MesalinkInnerResult<()> {
    let file = fs::File::open(path).map_err(|e| error!(e.into()))?;
    let mut reader = io::BufReader::new(file);
    let _ = ctx
        .ca_roots
        .add_pem_file(&mut reader)
        .map_err(|_| error!(OpensslError::BadFuncArg.into()))?;
    Ok(())
}

fn update_ctx_if_both_certs_and_key_set(ctx: &mut Arc<TABBY_CTX>) -> MesalinkInnerResult<c_int> {
    if let Ok((certs, priv_key)) = util::try_get_context_certs_and_key(ctx) {
        util::get_context_mut(ctx)
            .client_config
            .set_single_client_cert(certs.clone(), priv_key.clone());
        util::get_context_mut(ctx)
            .server_config
            .set_single_cert(certs.clone(), priv_key.clone())
            .map_err(|e| error!(e.into()))?;
    }
    Ok(SSL_SUCCESS)
}

/// `SSL_CTX_use_certificate_chain_file` - load a certificate chain from file
/// into ctx. The certificates must be in PEM format and must be sorted starting
/// with the subject's certificate (actual client or server certificate),
/// followed by intermediate CA certificates if applicable, and ending at the
/// highest level (root) CA.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_use_certificate_chain_file(
    ctx_ptr: *mut TABBY_CTX_ARC,
    filename_ptr: *const c_char,
    _format: c_int,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_ctx_use_certificate_chain_file(ctx_ptr, filename_ptr),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_ctx_use_certificate_chain_file(
    ctx_ptr: *mut TABBY_CTX_ARC,
    filename_ptr: *const c_char,
) -> MesalinkInnerResult<c_int> {
    use crate::libcrypto::pem;

    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    if filename_ptr.is_null() {
        return Err(error!(OpensslError::NullPointer.into()));
    }
    let filename = unsafe {
        ffi::CStr::from_ptr(filename_ptr)
            .to_str()
            .map_err(|_| error!(OpensslError::BadFuncArg.into()))?
    };
    let file = fs::File::open(filename).map_err(|e| error!(e.into()))?;
    let mut buf_reader = io::BufReader::new(file);
    let certs = pem::get_certificate_chain(&mut buf_reader);
    if certs.is_empty() {
        return Err(error!(OpensslError::BadFuncArg.into()));
    }
    util::get_context_mut(ctx).certificates = Some(certs);
    Ok(update_ctx_if_both_certs_and_key_set(ctx)?)
}

/// `SSL_CTX_use_certificate` loads the certificate x into ctx. The rest of the
/// certificates needed to form the complete certificate chain can be specified
/// using the `SSL_CTX_add_extra_chain_cert` function.
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_use_certificate(
    ctx_ptr: *mut TABBY_CTX_ARC,
    x509_ptr: *mut TABBY_X509,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_ctx_add_certificate(ctx_ptr, x509_ptr),
        SSL_FAILURE
    )
}

#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_add_extra_chain_cert(
    ctx_ptr: *mut TABBY_CTX_ARC,
    x509_ptr: *mut TABBY_X509,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_ctx_add_certificate(ctx_ptr, x509_ptr),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_ctx_add_certificate(
    ctx_ptr: *mut TABBY_CTX_ARC,
    x509_ptr: *mut TABBY_X509,
) -> MesalinkInnerResult<c_int> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let x509 = sanitize_ptr_for_ref(x509_ptr)?;
    let cert = x509.inner.clone();
    {
        let ctx_mut_ref = util::get_context_mut(ctx);
        if ctx_mut_ref.certificates.is_none() {
            ctx_mut_ref.certificates = Some(vec![]);
        }
        ctx_mut_ref.certificates.as_mut().unwrap().push(cert);
    }
    Ok(update_ctx_if_both_certs_and_key_set(ctx)?)
}

/// `SSL_CTX_use_certificate_ASN1` - load the ASN1 encoded certificate
/// into ssl_ctx.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, unsigned char *d);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_use_certificate_ASN1(
    ctx_ptr: *mut TABBY_CTX_ARC,
    len: c_int,
    d: *mut c_uchar,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_ctx_use_certificate_asn1(ctx_ptr, len, d),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_ctx_use_certificate_asn1(
    ctx_ptr: *mut TABBY_CTX_ARC,
    len: c_int,
    d: *mut c_uchar,
) -> MesalinkInnerResult<c_int> {
    if d.is_null() {
        return Err(error!(OpensslError::NullPointer.into()));
    }
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let buf: &[u8] = unsafe { slice::from_raw_parts_mut(d, len as usize) };
    let cert = rustls::Certificate(buf.to_vec());
    {
        let ctx_mut_ref = util::get_context_mut(ctx);
        if ctx_mut_ref.certificates.is_none() {
            ctx_mut_ref.certificates = Some(vec![]);
        }
        ctx_mut_ref.certificates.as_mut().unwrap().push(cert);
    }
    Ok(update_ctx_if_both_certs_and_key_set(ctx)?)
}

/// `SSL_use_certificate_ASN1` - load the ASN1 encoded certificate
/// into ssl.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_use_certificate_ASN1(SSL *ssl, unsigned char *d, int len);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_use_certificate_ASN1(
    ssl_ptr: *mut TABBY_SSL,
    d: *mut c_uchar,
    len: c_int,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_use_certificate_asn1(ssl_ptr, d, len),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_use_certificate_asn1(
    ssl_ptr: *mut TABBY_SSL,
    d: *mut c_uchar,
    len: c_int,
) -> MesalinkInnerResult<c_int> {
    let ctx_ptr = inner_tabby_ssl_get_ssl_ctx(ssl_ptr)?;
    let _ = inner_tabby_ssl_ctx_use_certificate_asn1(ctx_ptr, len, d)?;
    let _ = inner_tabby_ssl_set_ssl_ctx(ssl_ptr, ctx_ptr)?;
    Ok(SSL_SUCCESS)
}

/// `SSL_CTX_use_PrivateKey` adds *pkey* as private key to *ctx*
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_use_PrivateKey(
    ctx_ptr: *mut TABBY_CTX_ARC,
    pkey_ptr: *mut TABBY_EVP_PKEY,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_ctx_use_privatekey(ctx_ptr, pkey_ptr),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_ctx_use_privatekey(
    ctx_ptr: *mut TABBY_CTX_ARC,
    pkey_ptr: *mut TABBY_EVP_PKEY,
) -> MesalinkInnerResult<c_int> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let pkey = sanitize_ptr_for_mut_ref(pkey_ptr)?;
    let key = pkey.inner.clone();
    util::get_context_mut(ctx).private_key = Some(key);
    Ok(update_ctx_if_both_certs_and_key_set(ctx)?)
}

/// `SSL_CTX_use_PrivateKey_file` - add the first private key found in file to
/// ctx. The formatting type of the certificate must be specified from the known
/// types SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_use_PrivateKey_file(
    ctx_ptr: *mut TABBY_CTX_ARC,
    filename_ptr: *const c_char,
    _format: c_int,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_ctx_use_privatekey_file(ctx_ptr, filename_ptr),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_ctx_use_privatekey_file(
    ctx_ptr: *mut TABBY_CTX_ARC,
    filename_ptr: *const c_char,
) -> MesalinkInnerResult<c_int> {
    use crate::libcrypto::pem;

    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    if filename_ptr.is_null() {
        return Err(error!(OpensslError::NullPointer.into()));
    }
    let filename = unsafe {
        ffi::CStr::from_ptr(filename_ptr)
            .to_str()
            .map_err(|_| error!(OpensslError::BadFuncArg.into()))?
    };
    let file = fs::File::open(filename).map_err(|e| error!(e.into()))?;
    let mut buf_reader = io::BufReader::new(file);
    let key = pem::get_either_rsa_or_ecdsa_private_key(&mut buf_reader)
        .map_err(|_| error!(OpensslError::BadFuncArg.into()))?;
    util::get_context_mut(ctx).private_key = Some(key);
    Ok(update_ctx_if_both_certs_and_key_set(ctx)?)
}

/// `SSL_CTX_use_PrivateKey_ASN1` - load the ASN1 encoded certificate into
/// ssl_ctx.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx, unsigned char *d,
///                               long len);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_use_PrivateKey_ASN1(
    pk_type: c_int,
    ctx_ptr: *mut TABBY_CTX_ARC,
    d: *mut c_uchar,
    len: c_long,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_ctx_use_privatekey_asn1(pk_type, ctx_ptr, d, len),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_ctx_use_privatekey_asn1(
    _pk_type: c_int,
    ctx_ptr: *mut TABBY_CTX_ARC,
    d: *mut c_uchar,
    len: c_long,
) -> MesalinkInnerResult<c_int> {
    if d.is_null() {
        return Err(error!(OpensslError::NullPointer.into()));
    }
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let buf: &[u8] = unsafe { slice::from_raw_parts_mut(d, len as usize) };
    let pkey = rustls::PrivateKey(buf.to_vec());
    util::get_context_mut(ctx).private_key = Some(pkey);
    Ok(update_ctx_if_both_certs_and_key_set(ctx)?)
}

/// `SSL_use_PrivateKey_ASN1` - load the ASN1 encoded certificate into
/// ssl.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx, unsigned char *d,
///                             long len);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_use_PrivateKey_ASN1(
    pk_type: c_int,
    ssl_ptr: *mut TABBY_SSL,
    d: *mut c_uchar,
    len: c_long,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_use_privatekey_asn1(pk_type, ssl_ptr, d, len),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_use_privatekey_asn1(
    pk_type: c_int,
    ssl_ptr: *mut TABBY_SSL,
    d: *mut c_uchar,
    len: c_long,
) -> MesalinkInnerResult<c_int> {
    let ctx_ptr = inner_tabby_ssl_get_ssl_ctx(ssl_ptr)?;
    let _ = inner_tabby_ssl_ctx_use_privatekey_asn1(pk_type, ctx_ptr, d, len)?;
    let _ = inner_tabby_ssl_set_ssl_ctx(ssl_ptr, ctx_ptr)?;
    Ok(SSL_SUCCESS)
}

/// `SSL_CTX_check_private_key` - check the consistency of a private key with the
/// corresponding certificate loaded into ctx
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_check_private_key(const SSL_CTX *ctx);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_check_private_key(ctx_ptr: *mut TABBY_CTX_ARC) -> c_int {
    check_inner_result!(inner_tabby_ssl_ctx_check_private_key(ctx_ptr), SSL_FAILURE)
}

fn inner_tabby_ssl_ctx_check_private_key(
    ctx_ptr: *mut TABBY_CTX_ARC,
) -> MesalinkInnerResult<c_int> {
    use rustls::sign;
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    match (&ctx.certificates, &ctx.private_key) {
        (&Some(ref certs), &Some(ref key)) => {
            let signing_key = sign::any_supported_type(&key)
                .map_err(|_| error!(OpensslError::BadFuncArg.into()))?;
            sign::CertifiedKey::new(certs.clone(), Arc::new(signing_key))
                .cross_check_end_entity_cert(None)
                .map_err(|e| error!(e.into()))?;
            Ok(SSL_SUCCESS)
        }
        _ => Err(error!(OpensslError::BadFuncArg.into())),
    }
}

/// `SSL_check_private_key` - check the consistency of a private key with the
/// corresponding certificate loaded into ssl
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_check_private_key(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_check_private_key(ctx_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_ssl_check_private_key(ctx_ptr), SSL_FAILURE)
}

fn inner_tabby_ssl_check_private_key(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;

    let ctx = ssl
        .context
        .as_ref()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    let ctx_ptr = ctx as *const TABBY_CTX_ARC as *mut TABBY_CTX_ARC;
    inner_tabby_ssl_ctx_check_private_key(ctx_ptr)
}

/// `SSL_CTX_set_verify` sets the verification flags for ctx to be *mode* and
/// The verify_callback function is ignored for now.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CTX_set_verify(const SSL_CTX *ctx, int mode, void *ignored_cb);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_set_verify(
    ctx_ptr: *mut TABBY_CTX_ARC,
    mode: c_int,
    _cb: Option<extern "C" fn(c_int, *mut c_void) -> c_int>,
) -> c_int {
    check_inner_result!(inner_tabby_ssl_ctx_set_verify(ctx_ptr, mode), SSL_FAILURE)
}

fn inner_tabby_ssl_ctx_set_verify(
    ctx_ptr: *mut TABBY_CTX_ARC,
    mode: c_int,
) -> MesalinkInnerResult<c_int> {
    let mode = VerifyModes::from_bits(mode).ok_or(error!(OpensslError::BadFuncArg.into()))?;
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    if mode == VerifyModes::VERIFY_NONE {
        util::get_context_mut(ctx)
            .client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoServerAuth {}));
    } else if mode == VerifyModes::VERIFY_PEER | VerifyModes::VERIFY_FAIL_IF_NO_PEER_CERT {
        let verifier = rustls::AllowAnyAuthenticatedClient::new(ctx.ca_roots.clone());
        util::get_context_mut(ctx)
            .server_config
            .set_client_certificate_verifier(verifier);
    } else if mode == VerifyModes::VERIFY_PEER {
        let verifier = rustls::AllowAnyAnonymousOrAuthenticatedClient::new(ctx.ca_roots.clone());
        util::get_context_mut(ctx)
            .server_config
            .set_client_certificate_verifier(verifier);
    }
    Ok(SSL_SUCCESS)
}

/// `SSL_CTX_set_session_cache_mode` - enable/disable session caching by setting
/// the operational mode for ctx to <mode>
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// long SSL_CTX_set_session_cache_mode(SSL_CTX ctx, long mode);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_set_session_cache_mode(
    ctx_ptr: *mut TABBY_CTX_ARC,
    mode: c_long,
) -> c_long {
    let error_ret: c_long = SSL_ERROR.into();
    check_inner_result!(
        inner_tabby_ssl_ctx_set_session_cache_mode(ctx_ptr, mode),
        error_ret
    )
}

fn inner_tabby_ssl_ctx_set_session_cache_mode(
    ctx_ptr: *mut TABBY_CTX_ARC,
    mode: c_long,
) -> MesalinkInnerResult<c_long> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let prev_mode = ctx.session_cache_mode.clone() as c_long;
    let sess_size = ctx.session_cache_size;
    let ctx_mut = util::get_context_mut(ctx);
    if mode == SslSessionCacheModes::Off as c_long {
        ctx_mut
            .client_config
            .set_persistence(Arc::new(rustls::NoClientSessionStorage {}));
        ctx_mut
            .server_config
            .set_persistence(Arc::new(rustls::NoServerSessionStorage {}));
        ctx_mut.session_cache_mode = SslSessionCacheModes::Off;
    } else if mode == SslSessionCacheModes::Client as c_long {
        ctx_mut
            .client_config
            .set_persistence(ClientSessionCache::with_capacity(sess_size));
        ctx_mut
            .server_config
            .set_persistence(Arc::new(rustls::NoServerSessionStorage {}));
        ctx_mut.session_cache_mode = SslSessionCacheModes::Client;
    } else if mode == SslSessionCacheModes::Server as c_long {
        ctx_mut
            .client_config
            .set_persistence(Arc::new(rustls::NoClientSessionStorage {}));
        ctx_mut
            .server_config
            .set_persistence(ServerSessionMemoryCache::new(sess_size));
        ctx_mut.session_cache_mode = SslSessionCacheModes::Server;
    } else if mode == SslSessionCacheModes::Both as c_long {
        ctx_mut
            .client_config
            .set_persistence(ClientSessionCache::with_capacity(sess_size));
        ctx_mut
            .server_config
            .set_persistence(ServerSessionMemoryCache::new(sess_size));
        ctx_mut.session_cache_mode = SslSessionCacheModes::Both;
    }
    Ok(prev_mode)
}

/// `SSL_CTX_get_session_cache_mode` -  return the currently used cache mode
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// long SSL_CTX_get_session_cache_mode(SSL_CTX ctx);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_get_session_cache_mode(ctx_ptr: *mut TABBY_CTX_ARC) -> c_long {
    let error_ret: c_long = SSL_ERROR.into();
    check_inner_result!(
        inner_tabby_ssl_ctx_get_session_cache_mode(ctx_ptr),
        error_ret
    )
}

fn inner_tabby_ssl_ctx_get_session_cache_mode(
    ctx_ptr: *mut TABBY_CTX_ARC,
) -> MesalinkInnerResult<c_long> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let prev_mode = ctx.session_cache_mode.clone() as c_long;
    Ok(prev_mode)
}

/// `SSL_CTX_sess_set_cache_size` -  return the currently session cache size
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// long SSL_CTX_sess_set_cache_size(SSL_CTX ctx, long t);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_sess_set_cache_size(
    ctx_ptr: *mut TABBY_CTX_ARC,
    t: c_long,
) -> c_long {
    let error_ret: c_long = SSL_ERROR.into();
    check_inner_result!(
        inner_tabby_ssl_ctx_sess_set_cache_size(ctx_ptr, t),
        error_ret
    )
}

fn inner_tabby_ssl_ctx_sess_set_cache_size(
    ctx_ptr: *mut TABBY_CTX_ARC,
    t: c_long,
) -> MesalinkInnerResult<c_long> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let prev_size = ctx.session_cache_size;
    let sess_mode = ctx.session_cache_mode.clone();
    let ctx_mut = util::get_context_mut(ctx);
    ctx_mut.session_cache_size = t as usize;
    match sess_mode {
        SslSessionCacheModes::Client => {
            ctx_mut
                .client_config
                .set_persistence(ClientSessionCache::with_capacity(t as usize));
        }
        SslSessionCacheModes::Server => {
            ctx_mut
                .server_config
                .set_persistence(ServerSessionMemoryCache::new(t as usize));
        }
        SslSessionCacheModes::Both => {
            ctx_mut
                .client_config
                .set_persistence(ClientSessionCache::with_capacity(t as usize));
            ctx_mut
                .server_config
                .set_persistence(ServerSessionMemoryCache::new(t as usize));
        }
        _ => (),
    }
    Ok(prev_size as c_long)
}

/// `SSL_CTX_sess_get_cache_size` -  return the currently session cache size
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// long SSL_CTX_sess_get_cache_size(SSL_CTX ctx);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_sess_get_cache_size(ctx_ptr: *mut TABBY_CTX_ARC) -> c_long {
    let error_ret: c_long = SSL_ERROR.into();
    check_inner_result!(inner_tabby_ssl_ctx_sess_get_cache_size(ctx_ptr), error_ret)
}

fn inner_tabby_ssl_ctx_sess_get_cache_size(
    ctx_ptr: *mut TABBY_CTX_ARC,
) -> MesalinkInnerResult<c_long> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let prev_size = ctx.session_cache_size;
    Ok(prev_size as c_long)
}

/// `SSL_new` - create a new SSL structure which is needed to hold the data for a
/// TLS/SSL connection
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// SSL *SSL_new(SSL_CTX *ctx);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_new(ctx_ptr: *mut TABBY_CTX_ARC) -> *mut TABBY_SSL {
    check_inner_result!(inner_tabby_ssl_new(ctx_ptr), ptr::null_mut())
}

fn inner_tabby_ssl_new(ctx_ptr: *mut TABBY_CTX_ARC) -> MesalinkInnerResult<*mut TABBY_SSL> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    Ok(Box::into_raw(Box::new(TABBY_SSL::new(ctx))))
}

/// `SSL_get_SSL_CTX` - return a pointer to the SSL_CTX object, from which ssl was
/// created with SSL_new.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_SSL_CTX(ssl_ptr: *mut TABBY_SSL) -> *const TABBY_CTX_ARC {
    check_inner_result!(inner_tabby_ssl_get_ssl_ctx(ssl_ptr), ptr::null())
}

fn inner_tabby_ssl_get_ssl_ctx(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<*mut TABBY_CTX_ARC> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;
    let ctx = ssl
        .context
        .as_ref()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    Ok(ctx as *const TABBY_CTX_ARC as *mut TABBY_CTX_ARC)
}

/// `SSL_set_SSL_CTX` - set the SSL_CTX object of an SSL object.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_set_SSL_CTX(
    ssl_ptr: *mut TABBY_SSL,
    ctx_ptr: *mut TABBY_CTX_ARC,
) -> *const TABBY_CTX_ARC {
    check_inner_result!(inner_tabby_ssl_set_ssl_ctx(ssl_ptr, ctx_ptr), ptr::null())
}

fn inner_tabby_ssl_set_ssl_ctx(
    ssl_ptr: *mut TABBY_SSL,
    ctx_ptr: *mut TABBY_CTX_ARC,
) -> MesalinkInnerResult<*const TABBY_CTX_ARC> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    ssl.context = Some(ctx.clone());
    ssl.client_config = Arc::new(ctx.client_config.clone());
    ssl.server_config = Arc::new(ctx.server_config.clone());
    let ctx_ref = ssl
        .context
        .as_ref()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    Ok(ctx_ref as *const TABBY_CTX_ARC)
}

/// `SSL_get_current_cipher` - returns a pointer to an SSL_CIPHER object
/// containing the description of the actually used cipher of a connection
/// established with the ssl object. See SSL_CIPHER_get_name for more details.
/// Note that this API allocates memory and needs to be properly freed. freed.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_current_cipher(ssl_ptr: *mut TABBY_SSL) -> *mut TABBY_CIPHER {
    check_inner_result!(inner_tabby_ssl_get_current_cipher(ssl_ptr), ptr::null_mut())
}

fn inner_tabby_ssl_get_current_cipher(
    ssl_ptr: *mut TABBY_SSL,
) -> MesalinkInnerResult<*mut TABBY_CIPHER> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;
    let session = ssl
        .session
        .as_ref()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    let ciphersuite = session
        .read()
        .get_negotiated_ciphersuite()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    Ok(Box::into_raw(Box::new(TABBY_CIPHER::new(ciphersuite)))) // Allocates memory!
}

/// `SSL_CIPHER_get_name` - return a pointer to the name of cipher. If the
/// argument is the NULL pointer, a pointer to the constant value "NONE" is
/// returned.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher);
/// ```
#[no_mangle]
#[cfg(feature = "error_strings")]
pub extern "C" fn tabby_SSL_CIPHER_get_name(cipher_ptr: *mut TABBY_CIPHER) -> *const c_char {
    check_inner_result!(inner_tabby_ssl_cipher_get_name(cipher_ptr), ptr::null())
}

#[cfg(feature = "error_strings")]
fn inner_tabby_ssl_cipher_get_name(
    cipher_ptr: *mut TABBY_CIPHER,
) -> MesalinkInnerResult<*const c_char> {
    let ciphersuite = sanitize_ptr_for_ref(cipher_ptr)?;
    Ok(util::suite_to_name_str(ciphersuite.ciphersuite.suite.get_u16()).as_ptr() as *const c_char)
}

#[no_mangle]
#[cfg(not(feature = "error_strings"))]
pub extern "C" fn tabby_SSL_CIPHER_get_name(cipher_ptr: *mut TABBY_CIPHER) -> *const c_char {
    check_inner_result!(inner_tabby_ssl_cipher_get_name(cipher_ptr), ptr::null())
}

#[cfg(not(feature = "error_strings"))]
fn inner_tabby_ssl_cipher_get_name(
    cipher_ptr: *mut TABBY_CIPHER,
) -> MesalinkInnerResult<*const c_char> {
    let _ = sanitize_ptr_for_ref(cipher_ptr)?;
    Ok(CONST_NOTBUILTIN_STR.as_ptr() as *const c_char)
}

/// `SSL_CIPHER_get_bits` - return the number of secret bits used for cipher. If
/// alg_bits is not NULL, it contains the number of bits processed by the chosen
/// algorithm. If cipher is NULL, 0 is returned.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_CIPHER_get_bits(const SSL_CIPHER *cipher, int *alg_bits);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CIPHER_get_bits(
    cipher_ptr: *mut TABBY_CIPHER,
    bits_ptr: *mut c_int,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_cipher_get_bits(cipher_ptr, bits_ptr),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_cipher_get_bits(
    cipher_ptr: *mut TABBY_CIPHER,
    bits_ptr: *mut c_int,
) -> MesalinkInnerResult<c_int> {
    let ciphersuite = sanitize_ptr_for_ref(cipher_ptr)?;
    unsafe {
        if bits_ptr.is_null() {
            return Err(error!(OpensslError::NullPointer.into()));
        }
        ptr::write(bits_ptr, ciphersuite.ciphersuite.enc_key_len as c_int);
    }
    Ok(SSL_SUCCESS)
}

/// `SSL_CIPHER_get_version` - returns string which indicates the SSL/TLS protocol
/// version that first defined the cipher. This is currently SSLv2 or
/// TLSv1/SSLv3. In some cases it should possibly return "TLSv1.2" but does not;
/// use SSL_CIPHER_description() instead. If cipher is NULL, "(NONE)" is
/// returned.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// char *SSL_CIPHER_get_version(const SSL_CIPHER *cipher);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_CIPHER_get_version(cipher_ptr: *mut TABBY_CIPHER) -> *const c_char {
    check_inner_result!(inner_tabby_ssl_cipher_get_version(cipher_ptr), ptr::null())
}

fn inner_tabby_ssl_cipher_get_version(
    cipher_ptr: *mut TABBY_CIPHER,
) -> MesalinkInnerResult<*const c_char> {
    match sanitize_ptr_for_ref(cipher_ptr) {
        Ok(ciphersuite) => {
            let version = util::suite_to_version_str(ciphersuite.ciphersuite.suite.get_u16());
            Ok(version.as_ptr() as *const c_char)
        }
        Err(_) => Ok(util::CONST_NONE_STR.as_ptr() as *const c_char),
    }
}

/// `SSL_get_cipher_name` - obtain the name of the currently used cipher.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// char *SSL_get_cipher_name(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_cipher_name(ssl_ptr: *mut TABBY_SSL) -> *const c_char {
    let cipher = tabby_SSL_get_current_cipher(ssl_ptr);
    let ret = tabby_SSL_CIPHER_get_name(cipher);
    if !cipher.is_null() {
        let _ = unsafe { Box::from_raw(cipher) };
    }
    ret
}

/// `SSL_get_cipher` - obtain the name of the currently used cipher.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// char *SSL_get_cipher(const SSL *ssl);
/// ```c
#[no_mangle]
pub extern "C" fn tabby_SSL_get_cipher(ssl_ptr: *mut TABBY_SSL) -> *const c_char {
    tabby_SSL_get_cipher_name(ssl_ptr)
}

/// `SSL_get_cipher_bits` - obtain the number of secret/algorithm bits used.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_cipher_bits(const SSL *ssl, int* np);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_cipher_bits(
    ssl_ptr: *mut TABBY_SSL,
    bits_ptr: *mut c_int,
) -> c_int {
    let cipher = tabby_SSL_get_current_cipher(ssl_ptr);
    let ret = tabby_SSL_CIPHER_get_bits(cipher, bits_ptr);
    if !cipher.is_null() {
        let _ = unsafe { Box::from_raw(cipher) };
    }
    ret
}

/// `SSL_get_cipher_version` - returns the protocol name.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// char* SSL_get_cipher_version(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_cipher_version(ssl_ptr: *mut TABBY_SSL) -> *const c_char {
    let cipher = tabby_SSL_get_current_cipher(ssl_ptr);
    let ret = tabby_SSL_CIPHER_get_version(cipher);
    unsafe {
        if !cipher.is_null() {
            let _ = Box::from_raw(cipher);
        }
    }
    ret
}

/// `SSL_get_peer_certificate` - get the X509 certificate of the peer
///
/// ```c
///  #include <openssl/ssl.h>
///
/// X509 *SSL_get_peer_certificate(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_peer_certificate(ssl_ptr: *mut TABBY_SSL) -> *mut TABBY_X509 {
    check_inner_result!(
        inner_tabby_ssl_get_peer_certificate(ssl_ptr),
        ptr::null_mut()
    )
}

fn inner_tabby_ssl_get_peer_certificate(
    ssl_ptr: *mut TABBY_SSL,
) -> MesalinkInnerResult<*mut TABBY_X509> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let certs = get_peer_certificates(&ssl)?;
    let x509 = TABBY_X509::new(certs[0].clone());
    Ok(Box::into_raw(Box::new(x509)) as *mut TABBY_X509)
}

/// `SSL_get_peer_certificates` - get the X509 certificate chain of the peer
///
/// ```c
///  #include <openssl/ssl.h>
///
/// STACK_OF(X509) *SSL_get_peer_certificates(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_peer_certificates(
    ssl_ptr: *mut TABBY_SSL,
) -> *mut TABBY_STACK_TABBY_X509 {
    check_inner_result!(
        inner_tabby_ssl_get_peer_certificates(ssl_ptr),
        ptr::null_mut()
    )
}

fn inner_tabby_ssl_get_peer_certificates(
    ssl_ptr: *mut TABBY_SSL,
) -> MesalinkInnerResult<*mut TABBY_STACK_TABBY_X509> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;

    let certs = get_peer_certificates(&ssl)?;
    let mut vec: Vec<TABBY_X509> = Vec::new();
    for cert in certs {
        let x509 = TABBY_X509::new(cert.clone());
        vec.push(x509);
    }
    let x509_stack = TABBY_STACK_TABBY_X509::new(vec);
    Ok(Box::into_raw(Box::new(x509_stack)) as *mut TABBY_STACK_TABBY_X509)
}

fn get_peer_certificates(ssl: &TABBY_SSL) -> MesalinkInnerResult<Vec<rustls::Certificate>> {
    let session = ssl
        .session
        .as_ref()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    session
        .read()
        .get_peer_certificates()
        .ok_or(error!(OpensslError::BadFuncArg.into()))
        .and_then(|certs| {
            if certs.is_empty() {
                Err(error!(OpensslError::BadFuncArg.into()))
            } else {
                Ok(certs)
            }
        })
}

/// `SSL_set_tlsext_host_name` - set the server name indication ClientHello
/// extension to contain the value name.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_set_tlsext_host_name(const SSL *s, const char *name);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_set_tlsext_host_name(
    ssl_ptr: *mut TABBY_SSL,
    hostname_ptr: *const c_char,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_set_tlsext_host_name(ssl_ptr, hostname_ptr),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_set_tlsext_host_name(
    ssl_ptr: *mut TABBY_SSL,
    hostname_ptr: *const c_char,
) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    if hostname_ptr.is_null() {
        return Err(error!(OpensslError::NullPointer.into()));
    }
    let hostname = unsafe {
        ffi::CStr::from_ptr(hostname_ptr)
            .to_str()
            .map_err(|_| error!(OpensslError::BadFuncArg.into()))?
    };
    let _ = webpki::DNSNameRef::try_from_ascii_str(hostname)
        .map_err(|_| error!(OpensslError::BadFuncArg.into()))?;
    ssl.hostname = Some(hostname.to_owned());
    Ok(SSL_SUCCESS)
}

/// `SSL_set_fd` - set the file descriptor fd as the input/output facility for the
/// TLS/SSL (encrypted) side of ssl. fd will typically be the socket file
/// descriptor of a network connection.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_set_fd(SSL *ssl, int fd);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_set_fd(ssl_ptr: *mut TABBY_SSL, fd: c_int) -> c_int {
    #[cfg(unix)]
    {
        check_inner_result!(inner_tabby_ssl_set_fd(ssl_ptr, fd), SSL_FAILURE)
    }

    #[cfg(windows)]
    {
        check_inner_result!(
            inner_tabby_ssl_set_socket(ssl_ptr, fd as libc::SOCKET),
            SSL_FAILURE
        )
    }
}

#[cfg(unix)]
fn inner_tabby_ssl_set_fd(ssl_ptr: *mut TABBY_SSL, fd: c_int) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    if fd < 0 {
        return Err(error!(OpensslError::BadFuncArg.into()));
    }
    let socket = unsafe { net::TcpStream::from_raw_fd(fd) };
    ssl.io = Some(socket);
    Ok(SSL_SUCCESS)
}

/// `SSL_get_fd` - return the file descriptor which is linked to ssl.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_fd(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_fd(ssl_ptr: *mut TABBY_SSL) -> c_int {
    #[cfg(unix)]
    {
        check_inner_result!(inner_measlink_ssl_get_fd(ssl_ptr), SSL_FAILURE)
    }

    #[cfg(windows)]
    {
        check_inner_result!(
            inner_measlink_ssl_get_socket(ssl_ptr).map(|socket| socket as c_int),
            SSL_FAILURE
        )
    }
}

#[cfg(unix)]
fn inner_measlink_ssl_get_fd(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;
    let socket = ssl
        .io
        .as_ref()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    Ok(socket.as_raw_fd())
}

/// `SSL_set_socket` - set the Windows raw socket as the input/output facility for the
/// TLS/SSL (encrypted) side of ssl. fd will typically be the socket file
/// descriptor of a network connection.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_set_socket(SSL *ssl, int fd);
/// ```
#[cfg(windows)]
#[no_mangle]
pub extern "C" fn tabby_SSL_set_socket(ssl_ptr: *mut TABBY_SSL, sock: libc::SOCKET) -> c_int {
    check_inner_result!(inner_tabby_ssl_set_socket(ssl_ptr, sock), SSL_FAILURE)
}

#[cfg(windows)]
fn inner_tabby_ssl_set_socket(
    ssl_ptr: *mut TABBY_SSL,
    sock: libc::SOCKET,
) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    if sock == 0 {
        return Err(error!(OpensslError::BadFuncArg.into()));
    }
    let socket = unsafe { net::TcpStream::from_raw_socket(sock as std::os::windows::raw::SOCKET) };
    ssl.io = Some(socket);
    Ok(SSL_SUCCESS)
}

/// `SSL_get_socket` - return the socket which is linked to ssl.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_socket(const SSL *ssl);
/// ```
#[cfg(windows)]
#[no_mangle]
pub extern "C" fn tabby_SSL_get_socket(ssl_ptr: *mut TABBY_SSL) -> libc::SOCKET {
    check_inner_result!(inner_measlink_ssl_get_socket(ssl_ptr), 0)
}

#[cfg(windows)]
fn inner_measlink_ssl_get_socket(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<libc::SOCKET> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;
    let socket = ssl
        .io
        .as_ref()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    Ok(socket.as_raw_socket() as usize)
}

/// `SSL_set_connect_state` sets *ssl* to work in client mode.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_set_connect_state(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_set_connect_state(ssl_ptr: *mut TABBY_SSL) {
    let _ = check_inner_result!(inner_tabby_ssl_set_mode(ssl_ptr, false), SSL_FAILURE);
}

/// `SSL_set_accept_state` sets *ssl* to work in server mode.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_set_accept_state(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_set_accept_state(ssl_ptr: *mut TABBY_SSL) {
    let _ = check_inner_result!(inner_tabby_ssl_set_mode(ssl_ptr, true), SSL_FAILURE);
}

fn inner_tabby_ssl_set_mode(
    ssl_ptr: *mut TABBY_SSL,
    is_server: bool,
) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    ssl.mode = if is_server {
        ClientOrServerMode::Server
    } else {
        ClientOrServerMode::Client
    };
    Ok(SSL_SUCCESS)
}

/// `SSL_is_server` checks if ssl is working in server mode.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_is_server(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_is_server(ssl_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_is_server_mode(ssl_ptr), SSL_FAILURE)
}

fn inner_tabby_is_server_mode(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    match ssl.mode {
        ClientOrServerMode::Client | ClientOrServerMode::Both => Ok(0),
        ClientOrServerMode::Server => Ok(1),
    }
}

/// `SSL_do_handshake` - perform a TLS/SSL handshake
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_do_handshake(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_do_handshake(ssl_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_ssl_do_handshake(ssl_ptr), SSL_FAILURE)
}

fn inner_tabby_ssl_do_handshake(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let mut ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let _ = setup_ssl_if_ready(&mut ssl)?;
    do_handshake(&mut ssl)
}

fn setup_ssl_if_ready(ssl: &mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    match ssl.error {
        ErrorCode::OpensslErrorNone
        | ErrorCode::OpensslErrorWantRead
        | ErrorCode::OpensslErrorWantWrite
        | ErrorCode::OpensslErrorWantConnect
        | ErrorCode::OpensslErrorWantAccept => ssl.error = ErrorCode::default(),
        _ => (),
    };

    if ssl.session.is_none() {
        match ssl.mode {
            ClientOrServerMode::Client | ClientOrServerMode::Both => {
                let hostname = ssl
                    .hostname
                    .as_ref()
                    .ok_or(error!(OpensslError::BadFuncArg.into()))?
                    .clone();
                let dnsname = webpki::DNSNameRef::try_from_ascii_str(&hostname)
                    .map_err(|_| error!(OpensslError::BadFuncArg.into()))?;
                let client_session = rustls::ClientSession::new(&ssl.client_config, dnsname);
                ssl.session = Some(RwLock::new(ClientOrServerSession::Client(client_session)));
            }
            ClientOrServerMode::Server => {
                let server_session = rustls::ServerSession::new(&ssl.server_config);
                ssl.session = Some(RwLock::new(ClientOrServerSession::Server(server_session)));
            }
        }
    }
    Ok(SSL_SUCCESS)
}

fn do_handshake(ssl: &mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    match (ssl.session.as_mut(), ssl.io.as_mut()) {
        (Some(session), Some(io)) => {
            let mut session = session.write();
            if session.is_handshaking() {
                match complete_io(&mut session, io) {
                    Err(e) => {
                        ssl.error = ErrorCode::from(&e);
                        match ssl.error {
                            ErrorCode::OpensslErrorWantRead
                            | ErrorCode::OpensslErrorWantWrite
                            | ErrorCode::IoErrorNotConnected => Ok(SSL_ERROR),
                            _ => Err(e),
                        }
                    }
                    Ok(_) => Ok(SSL_SUCCESS),
                }
            } else {
                Ok(SSL_SUCCESS)
            }
        }
        _ => Err(error!(OpensslError::BadFuncArg.into())),
    }
}

/// `SSL_connect` - initiate the TLS handshake with a server. The communication
/// channel must already have been set and assigned to the ssl with SSL_set_fd.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_connect(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_connect(ssl_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_ssl_connect(ssl_ptr, false), SSL_FAILURE)
}

/// `SSL_connect0` - initiate the TLS handshake lazily with a server. The
/// communication channel must already have been set and assigned to the ssl
/// with SSL_set_fd. You must call `SSL_do_handshake()` to explictly start the
/// handshake.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_connect0(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_connect0(ssl_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_ssl_connect(ssl_ptr, true), SSL_FAILURE)
}

fn inner_tabby_ssl_connect(ssl_ptr: *mut TABBY_SSL, is_lazy: bool) -> MesalinkInnerResult<c_int> {
    let mut ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    ssl.mode = ClientOrServerMode::Client;

    let _ = setup_ssl_if_ready(&mut ssl)?;
    if !is_lazy {
        do_handshake(&mut ssl)
    } else {
        Ok(SSL_SUCCESS)
    }
}

/// `SSL_accept` - wait for a TLS client to initiate the TLS handshake. The
/// communication channel must already have been set and assigned to the ssl by
/// setting SSL_set_fd.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_accept(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_accept(ssl_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_ssl_accept(ssl_ptr), SSL_FAILURE)
}

fn inner_tabby_ssl_accept(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let mut ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    ssl.mode = ClientOrServerMode::Server;
    let _ = setup_ssl_if_ready(&mut ssl)?;
    do_handshake(&mut ssl)
}

/// `SSL_get_error` - obtain result code for TLS/SSL I/O operation
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_error(const SSL *ssl, int ret);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_error(ssl_ptr: *mut TABBY_SSL, ret: c_int) -> c_int {
    check_inner_result!(inner_tabby_ssl_get_error(ssl_ptr, ret), SSL_FAILURE)
}

fn inner_tabby_ssl_get_error(ssl_ptr: *mut TABBY_SSL, ret: c_int) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    if ret > 0 {
        Ok(0)
    } else {
        Ok(ssl.error as c_int)
    }
}

/// `SSL_read` - read `num` bytes from the specified `ssl` into the
/// buffer `buf`.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_read(SSL *ssl, void *buf, int num);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_read(
    ssl_ptr: *mut TABBY_SSL,
    buf_ptr: *mut c_uchar,
    buf_len: c_int,
) -> c_int {
    check_inner_result!(inner_tabby_ssl_read(ssl_ptr, buf_ptr, buf_len), SSL_FAILURE)
}

fn inner_tabby_ssl_read(
    ssl_ptr: *mut TABBY_SSL,
    buf_ptr: *mut c_uchar,
    buf_len: c_int,
) -> MesalinkInnerResult<c_int> {
    if buf_ptr.is_null() || buf_len < 0 {
        return Err(error!(OpensslError::BadFuncArg.into()));
    }
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let buf = unsafe { slice::from_raw_parts_mut(buf_ptr, buf_len as usize) };
    match ssl.ssl_read(buf) {
        Ok(count) => Ok(count as c_int),
        Err(e) => {
            let error_code = ErrorCode::from(&e);
            ssl.error = ErrorCode::from(&e);
            if error_code == ErrorCode::IoErrorWouldBlock {
                ssl.error = ErrorCode::OpensslErrorWantRead;
            } else {
                ssl.error = error_code;
            }
            if ssl.error == ErrorCode::OpensslErrorWantRead
                || ssl.error == ErrorCode::IoErrorNotConnected
            {
                return Ok(SSL_ERROR);
            }
            Err(e)
        }
    }
}

/// `SSL_write` - write `num` bytes from the buffer `buf` into the
/// specified `ssl` connection.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_write(SSL *ssl, const void *buf, int num);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_write(
    ssl_ptr: *mut TABBY_SSL,
    buf_ptr: *const c_uchar,
    buf_len: c_int,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_write(ssl_ptr, buf_ptr, buf_len),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_write(
    ssl_ptr: *mut TABBY_SSL,
    buf_ptr: *const c_uchar,
    buf_len: c_int,
) -> MesalinkInnerResult<c_int> {
    if buf_ptr.is_null() || buf_len < 0 {
        return Err(error!(OpensslError::BadFuncArg.into()));
    }
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let buf = unsafe { slice::from_raw_parts(buf_ptr, buf_len as usize) };
    match ssl.ssl_write(buf) {
        Ok(count) => Ok(count as c_int),
        Err(e) => Err(e),
    }
}

/// `SSL_write` - write `num` bytes from the buffer `buf` into the
/// specified `ssl` connection.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_write(SSL *ssl, const void *buf, int num);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_flush(ssl_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_ssl_flush(ssl_ptr), SSL_FAILURE)
}

fn inner_tabby_ssl_flush(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    match ssl.ssl_flush() {
        Ok(_) => Ok(SSL_SUCCESS),
        Err(e) => Err(e),
    }
}

/// `SSL_write_early_data` - write `num` bytes of TLS 1.3 early data from the
/// buffer `buf` into the specified `ssl` connection.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_write_early_data(SSL *s, const void *buf, size_t num, size_t *written);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_write_early_data(
    ssl_ptr: *mut TABBY_SSL,
    buf_ptr: *const c_uchar,
    buf_len: c_int,
    written_len_ptr: *mut size_t,
) -> c_int {
    check_inner_result!(
        inner_tabby_ssl_write_early_data(ssl_ptr, buf_ptr, buf_len, written_len_ptr),
        SSL_FAILURE
    )
}

fn inner_tabby_ssl_write_early_data(
    ssl_ptr: *mut TABBY_SSL,
    buf_ptr: *const c_uchar,
    buf_len: c_int,
    written_len_ptr: *mut size_t,
) -> MesalinkInnerResult<c_int> {
    if buf_ptr.is_null() || buf_len < 0 {
        return Err(error!(OpensslError::BadFuncArg.into()));
    }
    if written_len_ptr.is_null() {
        return Err(error!(OpensslError::NullPointer.into()));
    }
    let _ = inner_tabby_ssl_connect(ssl_ptr, true)?; // creates a client session
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let buf = unsafe { slice::from_raw_parts(buf_ptr, buf_len as usize) };
    match ssl.ssl_write_early_data(buf) {
        Ok(count) => {
            let written_size: size_t = count;
            unsafe { ptr::write(written_len_ptr, written_size) };
            Ok(SSL_SUCCESS)
        }
        Err(e) => {
            ssl.error = ErrorCode::from(&e);
            Err(e)
        }
    }
}

/// `SSL_get_early_data_status` - returns SSL_EARLY_DATA_ACCEPTED if early data
/// was accepted by the server, SSL_EARLY_DATA_REJECTED if early data was
/// rejected by the server.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_early_data_status(const SSL *s);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_early_data_status(ssl_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_ssl_get_early_data_status(ssl_ptr), SSL_FAILURE)
}

fn inner_tabby_ssl_get_early_data_status(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let session = ssl
        .session
        .as_mut()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    let mut session = session.write();
    if session.deref_mut().assert_client().is_early_data_accepted() {
        Ok(2)
    } else {
        Ok(1)
    }
}

/// `SSL_shutdown` - shut down a TLS connection
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_shutdown(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_shutdown(ssl_ptr: *mut TABBY_SSL) -> c_int {
    check_inner_result!(inner_tabby_ssl_shutdown(ssl_ptr), SSL_FAILURE)
}

fn inner_tabby_ssl_shutdown(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let session = ssl
        .session
        .as_mut()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    session.write().send_close_notify();
    Ok(SSL_SUCCESS)
}

/// `SSL_get_version` - get the protocol information of a connection
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// const char *SSL_get_version(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn tabby_SSL_get_version(ssl_ptr: *mut TABBY_SSL) -> *const c_char {
    check_inner_result!(inner_tabby_ssl_get_version(ssl_ptr), ptr::null())
}

fn inner_tabby_ssl_get_version(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<*const c_char> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let session = ssl
        .session
        .as_ref()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    let version = session
        .read()
        .get_protocol_version()
        .ok_or(error!(OpensslError::BadFuncArg.into()))?;
    match version {
        rustls::ProtocolVersion::TLSv1_2 => Ok(util::CONST_TLS12_STR.as_ptr() as *const c_char),
        rustls::ProtocolVersion::TLSv1_3 => Ok(util::CONST_TLS13_STR.as_ptr() as *const c_char),
        _ => Ok(util::CONST_NONE_STR.as_ptr() as *const c_char),
    }
}

/// `SSL_CTX_free` - free an allocated SSL_CTX object
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_CTX_free(SSL_CTX *ctx);
/// ```c
#[no_mangle]
pub extern "C" fn tabby_SSL_CTX_free(ctx_ptr: *mut TABBY_CTX_ARC) {
    let _ = check_inner_result!(inner_tabby_ssl_ctx_free(ctx_ptr), SSL_FAILURE);
}

fn inner_tabby_ssl_ctx_free(ctx_ptr: *mut TABBY_CTX_ARC) -> MesalinkInnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let _ = unsafe { Box::from_raw(ctx_ptr) };
    Ok(SSL_SUCCESS)
}

/// `SSL_free` - free an allocated SSL object
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_free(SSL *ssl);
/// ```c
#[no_mangle]
pub extern "C" fn tabby_SSL_free(ssl_ptr: *mut TABBY_SSL) {
    let _ = check_inner_result!(inner_tabby_ssl_free(ssl_ptr), SSL_FAILURE);
}

fn inner_tabby_ssl_free(ssl_ptr: *mut TABBY_SSL) -> MesalinkInnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let _ = unsafe { Box::from_raw(ssl_ptr) };
    Ok(SSL_SUCCESS)
}

mod util {
    use crate::libssl::ssl;
    use std::sync::Arc;

    pub(crate) const CONST_NONE_STR: &[u8] = b" NONE \0";
    pub(crate) const CONST_TLS12_STR: &[u8] = b"TLS1.2\0";
    pub const CONST_TLS13_STR: &[u8] = b"TLS1.3\0";

    use rustls;

    pub fn try_get_context_certs_and_key(
        ctx: &mut ssl::TABBY_CTX_ARC,
    ) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), ()> {
        let certs = ctx.certificates.as_ref().ok_or(())?;
        let priv_key = ctx.private_key.as_ref().ok_or(())?;
        Ok((certs.clone(), priv_key.clone()))
    }

    #[cfg(feature = "error_strings")]
    pub fn suite_to_name_str(suite: u16) -> &'static [u8] {
        match suite {
            0x1303 => b"TLS13_CHACHA20_POLY1305_SHA256\0",
            0xcca8 => b"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256\0",
            0xcca9 => b"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\0",
            0x1301 => b"TLS13_AES_128_GCM_SHA256\0",
            0x1302 => b"TLS13_AES_256_GCM_SHA384\0",
            0xc02b => b"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\0",
            0xc02c => b"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\0",
            0xc02f => b"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\0",
            0xc030 => b"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\0",
            _ => b"Unsupported ciphersuite\0",
        }
    }

    pub fn suite_to_version_str(suite: u16) -> &'static [u8] {
        match suite {
            0x1303 => CONST_TLS13_STR,
            0xcca8 | 0xcca9 => CONST_TLS12_STR,
            0x1301 | 0x1302 => CONST_TLS13_STR,
            0xc02b | 0xc02c | 0xc02f | 0xc030 => CONST_TLS12_STR,
            _ => b"Unsupported ciphersuite\0",
        }
    }

    pub fn get_context_mut(ctx: &mut ssl::TABBY_CTX_ARC) -> &mut ssl::TABBY_CTX {
        Arc::make_mut(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libssl::err::{tabby_ERR_clear_error, tabby_ERR_get_error};
    use crate::libssl::safestack::*;
    use crate::libssl::x509::*;
    use libc::{c_long, c_ulong};
    use std::{str, thread};

    const CONST_CA_FILE: &'static [u8] = b"tests/ca.cert\0";
    const CONST_INTER_CA_FILE: &'static [u8] = b"tests/inter.cert\0";
    const CONST_SERVER_CERT_CHAIN_FILE: &'static [u8] = b"tests/end.fullchain\0";
    const CONST_SERVER_CERT_FILE: &'static [u8] = b"tests/end.cert\0";
    const CONST_SERVER_KEY_FILE: &'static [u8] = b"tests/end.key\0";
    const CONST_CLIENT_CERT_FILE: &'static [u8] = b"tests/client.fullchain\0";
    const CONST_CLIENT_KEY_FILE: &'static [u8] = b"tests/client.key\0";
    const CONST_SERVER_ADDR: &'static str = "127.0.0.1";

    struct MesalinkTestSession {
        ctx: *mut TABBY_CTX_ARC,
        ssl: *mut TABBY_SSL,
    }

    impl MesalinkTestSession {
        fn new_client_session(
            method: *const TABBY_METHOD,
            sockfd: c_int,
        ) -> Result<MesalinkTestSession, ()> {
            let ctx = tabby_SSL_CTX_new(method);
            assert_ne!(ctx, ptr::null_mut(), "CTX is null");
            let _ = tabby_SSL_CTX_set_session_cache_mode(ctx, SslSessionCacheModes::Both as c_long);
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_CTX_use_certificate_chain_file(
                    ctx,
                    CONST_CLIENT_CERT_FILE.as_ptr() as *const c_char,
                    0,
                ),
                "Failed to set certificate file"
            );
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_CTX_use_PrivateKey_file(
                    ctx,
                    CONST_CLIENT_KEY_FILE.as_ptr() as *const c_char,
                    0,
                ),
                "Failed to set private key"
            );
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_CTX_load_verify_locations(
                    ctx,
                    CONST_CA_FILE.as_ptr() as *const c_char,
                    ptr::null_mut(),
                ),
                "Failed to load verified locations"
            );

            let ssl = tabby_SSL_new(ctx);
            assert_ne!(ssl, ptr::null_mut(), "SSL is null");
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_set_tlsext_host_name(ssl, b"localhost\0".as_ptr() as *const c_char),
                "Failed to set SNI"
            );
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_set_fd(ssl, sockfd),
                "Failed to set fd"
            );
            tabby_SSL_set_connect_state(ssl);
            assert_eq!(SSL_SUCCESS, tabby_SSL_connect0(ssl), "Failed to connect");
            if SSL_SUCCESS != tabby_SSL_do_handshake(ssl) {
                tabby_SSL_free(ssl);
                tabby_SSL_CTX_free(ctx);
                return Err(());
            }
            let certs = tabby_SSL_get_peer_certificates(ssl);
            let cert = tabby_SSL_get_peer_certificate(ssl);
            assert_ne!(certs, ptr::null_mut(), "Failed to get peer certificates");
            assert_ne!(cert, ptr::null_mut(), "Failed to get peer certificate");
            tabby_sk_X509_free(certs);
            tabby_X509_free(cert);

            Ok(MesalinkTestSession { ctx, ssl })
        }

        fn new_server_session(
            method: *const TABBY_METHOD,
            sockfd: c_int,
        ) -> Result<MesalinkTestSession, ()> {
            let ctx = tabby_SSL_CTX_new(method);
            assert_ne!(ctx, ptr::null_mut(), "CTX is null");
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_CTX_load_verify_locations(
                    ctx,
                    CONST_CA_FILE.as_ptr() as *const c_char,
                    ptr::null_mut(),
                ),
                "Failed to load verified locations"
            );
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_CTX_use_certificate_chain_file(
                    ctx,
                    CONST_SERVER_CERT_CHAIN_FILE.as_ptr() as *const c_char,
                    0,
                ),
                "Failed to set certificate file"
            );
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_CTX_use_PrivateKey_file(
                    ctx,
                    CONST_SERVER_KEY_FILE.as_ptr() as *const c_char,
                    0,
                ),
                "Failed to set private key"
            );
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_CTX_set_verify(ctx, 1, None),
                "Failed to set verify mode"
            );
            let ssl = tabby_SSL_new(ctx);
            assert_ne!(ssl, ptr::null_mut(), "SSL is null");
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_set_fd(ssl, sockfd),
                "Faield to set fd"
            );
            tabby_SSL_set_accept_state(ssl);
            if SSL_SUCCESS != tabby_SSL_accept(ssl) {
                tabby_SSL_free(ssl);
                tabby_SSL_CTX_free(ctx);
                return Err(());
            }
            Ok(MesalinkTestSession { ctx, ssl })
        }

        fn read(&self, buf: &mut [u8]) -> c_int {
            tabby_SSL_read(
                self.ssl,
                buf.as_mut_ptr() as *mut c_uchar,
                buf.len() as c_int,
            )
        }

        fn write(&self, buf: &[u8]) -> c_int {
            tabby_SSL_write(self.ssl, buf.as_ptr() as *mut c_uchar, buf.len() as c_int)
        }

        fn shutdown(&self) -> c_int {
            tabby_SSL_shutdown(self.ssl)
        }

        fn get_error(&self) -> c_int {
            tabby_SSL_get_error(self.ssl, -1)
        }
    }

    impl Drop for MesalinkTestSession {
        fn drop(&mut self) {
            tabby_SSL_free(self.ssl);
            tabby_SSL_CTX_free(self.ctx);
        }
    }

    #[allow(dead_code)]
    enum TlsVersion {
        Tlsv12,
        Tlsv13,
        Both,
    }

    fn get_method_by_version(version: &TlsVersion, is_server: bool) -> *const TABBY_METHOD {
        match (version, is_server) {
            (&TlsVersion::Tlsv12, false) => tabby_TLSv1_2_client_method(),
            (&TlsVersion::Tlsv13, false) => tabby_TLSv1_3_client_method(),
            (&TlsVersion::Both, false) => tabby_TLS_client_method(),
            (&TlsVersion::Tlsv12, true) => tabby_TLSv1_2_server_method(),
            (&TlsVersion::Tlsv13, true) => tabby_TLSv1_3_server_method(),
            (&TlsVersion::Both, true) => tabby_TLS_server_method(),
        }
    }

    struct MesalinkTestDriver {}

    impl MesalinkTestDriver {
        fn new() -> MesalinkTestDriver {
            MesalinkTestDriver {}
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
                let session = MesalinkTestSession::new_client_session(method, sock.as_raw_fd());
                if session.is_err() {
                    return 1; // SSL handshake failed
                }
                let session = session.unwrap();
                tabby_ERR_clear_error();
                let _ = session.write(b"Hello server");
                let error = tabby_ERR_get_error();
                if error != 0 {
                    return error;
                }
                tabby_ERR_clear_error();
                let mut rd_buf = [0u8; 64];
                let _ = session.read(&mut rd_buf);
                let error = tabby_ERR_get_error();
                let ssl_error = session.get_error();
                if error != 0 || ssl_error != 0 {
                    return error;
                }
                MesalinkTestDriver::test_cipher(session.ssl, &version);
                let _ = session.shutdown();
                0
            })
        }

        fn test_cipher(ssl: *mut TABBY_SSL, version: &TlsVersion) {
            let cipher_name_ptr = tabby_SSL_get_cipher_name(ssl);
            let cipher_name = unsafe { ffi::CStr::from_ptr(cipher_name_ptr).to_str().unwrap() };
            match version {
                &TlsVersion::Tlsv12 => {
                    assert_eq!(cipher_name, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
                }
                &TlsVersion::Tlsv13 => assert_eq!(cipher_name, "TLS13_CHACHA20_POLY1305_SHA256"),
                _ => (),
            };

            let cipher_version_ptr = tabby_SSL_get_cipher_version(ssl);
            let cipher_version =
                unsafe { ffi::CStr::from_ptr(cipher_version_ptr).to_str().unwrap() };
            match version {
                &TlsVersion::Tlsv12 => assert_eq!(cipher_version, "TLS1.2"),
                &TlsVersion::Tlsv13 => assert_eq!(cipher_version, "TLS1.3"),
                _ => (),
            };

            let ssl_version_ptr = tabby_SSL_get_version(ssl);
            let ssl_version = unsafe { ffi::CStr::from_ptr(ssl_version_ptr).to_str().unwrap() };
            match version {
                &TlsVersion::Tlsv12 => assert_eq!(ssl_version, "TLS1.2"),
                &TlsVersion::Tlsv13 => assert_eq!(ssl_version, "TLS1.3"),
                _ => (),
            };

            let mut cipher_bits: c_int = 0;
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_get_cipher_bits(ssl, &mut cipher_bits as *mut c_int)
            );
            assert_eq!(32, cipher_bits);
        }

        fn run_server(
            &self,
            server: net::TcpListener,
            version: TlsVersion,
        ) -> thread::JoinHandle<c_ulong> {
            let sock = server.incoming().next().unwrap().expect("Accept error");
            thread::spawn(move || {
                let method = get_method_by_version(&version, true);
                let session = MesalinkTestSession::new_server_session(method, sock.as_raw_fd());
                if session.is_err() {
                    return 1; // SSL handshake failed
                }
                let session = session.unwrap();
                tabby_ERR_clear_error();
                let mut rd_buf = [0u8; 64];
                let _ = session.read(&mut rd_buf);
                let error = tabby_ERR_get_error();
                if error != 0 {
                    return error;
                }
                MesalinkTestDriver::test_cipher(session.ssl, &version);
                tabby_ERR_clear_error();
                let _ = session.write(b"Hello client");
                let error = tabby_ERR_get_error();
                let ssl_error = session.get_error();
                let _ = session.shutdown();
                if error != 0 || ssl_error != 0 {
                    return error;
                }
                0
            })
        }

        fn transfer(
            &self,
            client_version: TlsVersion,
            server_version: TlsVersion,
            should_fail: bool,
        ) {
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
        let method_ptr = tabby_SSLv23_client_method();
        assert_ne!(method_ptr, ptr::null());
        let _ = unsafe { Box::from_raw(method_ptr as *mut TABBY_METHOD) };

        let method_ptr = tabby_TLSv1_2_client_method();
        assert_ne!(method_ptr, ptr::null());
        let _ = unsafe { Box::from_raw(method_ptr as *mut TABBY_METHOD) };

        let method_ptr = tabby_TLSv1_2_client_method();
        assert_ne!(method_ptr, ptr::null());
        let _ = unsafe { Box::from_raw(method_ptr as *mut TABBY_METHOD) };

        let method_ptr = tabby_TLSv1_2_server_method();
        assert_ne!(method_ptr, ptr::null());
        let _ = unsafe { Box::from_raw(method_ptr as *mut TABBY_METHOD) };

        let method_ptr = tabby_TLS_method();
        assert_ne!(method_ptr, ptr::null());
        let _ = unsafe { Box::from_raw(method_ptr as *mut TABBY_METHOD) };

        let method_ptr = tabby_TLS_client_method();
        assert_ne!(method_ptr, ptr::null());
        let _ = unsafe { Box::from_raw(method_ptr as *mut TABBY_METHOD) };

        let method_ptr = tabby_TLS_server_method();
        assert_ne!(method_ptr, ptr::null());
        let _ = unsafe { Box::from_raw(method_ptr as *mut TABBY_METHOD) };
    }

    #[test]
    fn legacy_tls_versions_not_supported() {
        assert_eq!(tabby_SSLv3_client_method(), ptr::null());
        assert_eq!(tabby_TLSv1_client_method(), ptr::null());
        assert_eq!(tabby_TLSv1_1_client_method(), ptr::null());
        assert_eq!(tabby_SSLv3_server_method(), ptr::null());
        assert_eq!(tabby_TLSv1_server_method(), ptr::null());
        assert_eq!(tabby_TLSv1_1_server_method(), ptr::null());
    }

    fn transfer_test(client_version: TlsVersion, server_version: TlsVersion, should_fail: bool) {
        let driver = MesalinkTestDriver::new();
        driver.transfer(client_version, server_version, should_fail);
    }

    #[test]
    fn cross_version_tests() {
        transfer_test(TlsVersion::Both, TlsVersion::Both, false);
        transfer_test(TlsVersion::Tlsv12, TlsVersion::Tlsv12, false);
        transfer_test(TlsVersion::Tlsv13, TlsVersion::Tlsv13, false);
        transfer_test(TlsVersion::Both, TlsVersion::Tlsv13, false);
        transfer_test(TlsVersion::Tlsv13, TlsVersion::Both, false);
        transfer_test(TlsVersion::Tlsv12, TlsVersion::Both, false);
        transfer_test(TlsVersion::Both, TlsVersion::Tlsv12, false);
        transfer_test(TlsVersion::Tlsv13, TlsVersion::Tlsv12, true);
        transfer_test(TlsVersion::Tlsv12, TlsVersion::Tlsv13, true);
    }

    #[test]
    fn ssl_io_on_bad_file_descriptor() {
        let sock = unsafe { net::TcpStream::from_raw_fd(4526) };
        let ctx = tabby_SSL_CTX_new(tabby_SSLv23_client_method());
        let ssl = tabby_SSL_new(ctx);
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_set_tlsext_host_name(ssl, b"google.com\0".as_ptr() as *const c_char)
        );
        assert_eq!(SSL_SUCCESS, tabby_SSL_set_fd(ssl, sock.as_raw_fd()));
        assert_eq!(SSL_SUCCESS, tabby_SSL_connect0(ssl));

        let mut buf = [0u8; 64];
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_read(ssl, buf.as_mut_ptr() as *mut c_uchar, 64)
        );
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_write(ssl, buf.as_ptr() as *const c_uchar, 64)
        );
        assert_eq!(SSL_FAILURE, tabby_SSL_flush(ssl));

        tabby_SSL_free(ssl);
        tabby_SSL_CTX_free(ctx);
    }

    #[test]
    fn ssl_on_nonblocking_socket() {
        let sock = net::TcpStream::connect("mesalink.io:443").expect("Conenction failed");
        assert_eq!(true, sock.set_nonblocking(true).is_ok());
        let ctx = tabby_SSL_CTX_new(tabby_SSLv23_client_method());
        let ssl = tabby_SSL_new(ctx);
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_set_tlsext_host_name(ssl, b"mesalink.io\0".as_ptr() as *const c_char)
        );
        assert_eq!(SSL_SUCCESS, tabby_SSL_set_fd(ssl, sock.as_raw_fd()));
        assert_eq!(SSL_SUCCESS, tabby_SSL_connect0(ssl));
        let mut buf = [0u8; 64];
        assert_eq!(
            SSL_ERROR,
            tabby_SSL_read(ssl, buf.as_mut_ptr() as *mut c_uchar, 64)
        );
        assert_eq!(64, tabby_SSL_write(ssl, buf.as_ptr() as *const c_uchar, 64));
        assert_eq!(SSL_SUCCESS, tabby_SSL_flush(ssl));

        tabby_SSL_free(ssl);
        tabby_SSL_CTX_free(ctx);
    }

    #[test]
    fn ssl_ctx_is_thread_safe() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_client_method());
        let ctx = sanitize_ptr_for_mut_ref(ctx_ptr);
        let _ = &ctx as &dyn Send;
        let _ = &ctx as &dyn Sync;
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn ssl_is_thread_safe() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_client_method());
        let ssl_ptr = tabby_SSL_new(ctx_ptr);
        let ssl = sanitize_ptr_for_mut_ref(ssl_ptr);
        let _ = &ssl as &dyn Send;
        let _ = &ssl as &dyn Sync;
        tabby_SSL_free(ssl_ptr);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn ssl_ctx_is_not_null() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_client_method());
        assert_ne!(ctx_ptr, ptr::null_mut());
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn ssl_is_not_null() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_client_method());
        let ssl_ptr = tabby_SSL_new(ctx_ptr);
        assert_ne!(ctx_ptr, ptr::null_mut());
        tabby_SSL_free(ssl_ptr);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn load_verify_locations() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_client_method());
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_CTX_load_verify_locations(ctx_ptr, ptr::null(), ptr::null())
        );
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_load_verify_locations(
                ctx_ptr,
                b"tests/root_store/curl-root-ca.crt\0".as_ptr() as *const c_char,
                ptr::null()
            )
        );
        /*assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_load_verify_locations(
                ctx_ptr,
                ptr::null(),
                b"tests/root_store\0".as_ptr() as *const c_char,
            )
        );*/
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn certificate_not_found() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());
        assert_ne!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_certificate_chain_file(
                ctx_ptr,
                b"you_do_not_find_me".as_ptr() as *const c_char,
                0
            )
        );
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn private_key_not_found() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());
        assert_ne!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_PrivateKey_file(
                ctx_ptr,
                b"you_do_not_find_me\0".as_ptr() as *const c_char,
                0
            )
        );
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn invalid_certificate() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());
        assert_ne!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_certificate_chain_file(
                ctx_ptr,
                b"tests/bad.chain\0".as_ptr() as *const c_char,
                0
            )
        );
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn invalid_private_key() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());
        assert_ne!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_PrivateKey_file(
                ctx_ptr,
                b"tests/bad.certs\0".as_ptr() as *const c_char,
                0
            )
        );
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn verify_certificate_and_key() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_certificate_chain_file(
                ctx_ptr,
                CONST_SERVER_CERT_CHAIN_FILE.as_ptr() as *const c_char,
                0
            )
        );
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_PrivateKey_file(
                ctx_ptr,
                CONST_SERVER_KEY_FILE.as_ptr() as *const c_char,
                0
            )
        );
        assert_eq!(SSL_SUCCESS, tabby_SSL_CTX_check_private_key(ctx_ptr));
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn verify_key_and_certificate_1() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_PrivateKey_file(
                ctx_ptr,
                CONST_SERVER_KEY_FILE.as_ptr() as *const c_char,
                0
            )
        );
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_certificate_chain_file(
                ctx_ptr,
                CONST_SERVER_CERT_CHAIN_FILE.as_ptr() as *const c_char,
                0
            )
        );
        assert_eq!(SSL_SUCCESS, tabby_SSL_CTX_check_private_key(ctx_ptr));
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn verify_key_and_certificate_2() {
        use crate::libcrypto::{bio, evp, pem};

        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());

        // Load the private key
        let bio_pkey_ptr = bio::tabby_BIO_new_file(
            CONST_SERVER_KEY_FILE.as_ptr() as *const c_char,
            b"r\0".as_ptr() as *const c_char,
        );
        assert_ne!(bio_pkey_ptr, ptr::null_mut());
        let pkey_ptr = pem::tabby_PEM_read_bio_PrivateKey(
            bio_pkey_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_ne!(pkey_ptr, ptr::null_mut());
        assert_eq!(SSL_SUCCESS, tabby_SSL_CTX_use_PrivateKey(ctx_ptr, pkey_ptr));

        // Load the end entity cert
        let bio_x509_cert_ptr = bio::tabby_BIO_new_file(
            CONST_SERVER_CERT_FILE.as_ptr() as *const c_char,
            b"r\0".as_ptr() as *const c_char,
        );
        assert_ne!(bio_x509_cert_ptr, ptr::null_mut());
        let x509_cert_ptr = pem::tabby_PEM_read_bio_X509(
            bio_x509_cert_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_ne!(x509_cert_ptr, ptr::null_mut());

        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_certificate(ctx_ptr, x509_cert_ptr,)
        );

        // Load the intermediate CA cert
        let bio_x509_inter_ca_ptr = bio::tabby_BIO_new_file(
            CONST_INTER_CA_FILE.as_ptr() as *const c_char,
            b"r\0".as_ptr() as *const c_char,
        );
        assert_ne!(bio_x509_inter_ca_ptr, ptr::null_mut());
        let x509_inter_ca_ptr = pem::tabby_PEM_read_bio_X509(
            bio_x509_inter_ca_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_ne!(x509_inter_ca_ptr, ptr::null_mut());

        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_add_extra_chain_cert(ctx_ptr, x509_inter_ca_ptr)
        );

        // Load the CA cert
        let bio_x509_ca_ptr = bio::tabby_BIO_new_file(
            CONST_CA_FILE.as_ptr() as *const c_char,
            b"r\0".as_ptr() as *const c_char,
        );
        assert_ne!(bio_x509_ca_ptr, ptr::null_mut());
        let x509_ca_ptr = pem::tabby_PEM_read_bio_X509(
            bio_x509_ca_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_ne!(x509_ca_ptr, ptr::null_mut());

        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_add_extra_chain_cert(ctx_ptr, x509_ca_ptr)
        );

        // Check the private key and certificate
        assert_eq!(SSL_SUCCESS, tabby_SSL_CTX_check_private_key(ctx_ptr));

        tabby_X509_free(x509_cert_ptr);
        tabby_X509_free(x509_inter_ca_ptr);
        tabby_X509_free(x509_ca_ptr);
        evp::tabby_EVP_PKEY_free(pkey_ptr);
        bio::tabby_BIO_free(bio_pkey_ptr);
        bio::tabby_BIO_free(bio_x509_cert_ptr);
        bio::tabby_BIO_free(bio_x509_inter_ca_ptr);
        bio::tabby_BIO_free(bio_x509_ca_ptr);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn ssl_ctx_load_certificate_and_private_key_asn1() {
        let certificate_bytes = include_bytes!("../../tests/end.cert.der");
        let private_key_bytes = include_bytes!("../../tests/end.key.der");
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_certificate_ASN1(
                ctx_ptr,
                certificate_bytes.len() as c_int,
                certificate_bytes.as_ptr() as *mut c_uchar,
            )
        );
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_CTX_use_PrivateKey_ASN1(
                0,
                ctx_ptr,
                private_key_bytes.as_ptr() as *mut c_uchar,
                private_key_bytes.len() as c_long,
            )
        );
        assert_eq!(SSL_SUCCESS, tabby_SSL_CTX_check_private_key(ctx_ptr));
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn ssl_load_certificate_and_private_key_asn1() {
        let certificate_bytes = include_bytes!("../../tests/end.cert.der");
        let private_key_bytes = include_bytes!("../../tests/end.key.der");
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_server_method());
        let ssl_ptr = tabby_SSL_new(ctx_ptr);
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_use_PrivateKey_ASN1(
                0,
                ssl_ptr,
                private_key_bytes.as_ptr() as *mut c_uchar,
                private_key_bytes.len() as c_long,
            )
        );
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_use_certificate_ASN1(
                ssl_ptr,
                certificate_bytes.as_ptr() as *mut c_uchar,
                certificate_bytes.len() as c_int,
            )
        );
        assert_eq!(SSL_SUCCESS, tabby_SSL_check_private_key(ssl_ptr));
        let new_ctx_ptr = tabby_SSL_get_SSL_CTX(ssl_ptr) as *mut TABBY_CTX_ARC;
        assert_eq!(SSL_SUCCESS, tabby_SSL_CTX_check_private_key(new_ctx_ptr));
        tabby_SSL_free(ssl_ptr);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn get_ssl_fd() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLS_client_method());
        let ssl_ptr = tabby_SSL_new(ctx_ptr);
        let sock = net::TcpStream::connect("8.8.8.8:53").expect("Connect error");
        let fd: c_int = sock.as_raw_fd();
        assert_eq!(SSL_SUCCESS, tabby_SSL_set_fd(ssl_ptr, fd));
        assert_eq!(fd, tabby_SSL_get_fd(ssl_ptr));
        tabby_SSL_free(ssl_ptr);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn get_and_set_ssl_ctx() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLSv1_2_client_method());
        let ssl_ptr = tabby_SSL_new(ctx_ptr);
        let ctx_ptr_2 = tabby_SSL_CTX_new(tabby_TLSv1_3_client_method());
        let ctx_ptr_3 = tabby_SSL_set_SSL_CTX(ssl_ptr, ctx_ptr_2);
        let ctx_ptr_4 = tabby_SSL_get_SSL_CTX(ssl_ptr);
        let ctx_ref_1 = sanitize_const_ptr_for_ref(ctx_ptr).unwrap();
        let ctx_ref_2 = sanitize_const_ptr_for_ref(ctx_ptr_2).unwrap();
        assert_ne!(
            ctx_ref_1.client_config.versions,
            ctx_ref_2.client_config.versions
        );
        assert_eq!(ctx_ptr_3, ctx_ptr_4);
        tabby_SSL_free(ssl_ptr);
        tabby_SSL_CTX_free(ctx_ptr_2);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn dummy_openssl_compatible_apis_always_return_success() {
        assert_eq!(SSL_SUCCESS, tabby_library_init());
        assert_eq!(SSL_SUCCESS, tabby_add_ssl_algorithms());
        assert_eq!((), tabby_SSL_load_error_strings());
    }

    #[test]
    fn tabby_ssl_set_null_host_name() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLSv1_2_client_method());
        let ssl_ptr = tabby_SSL_new(ctx_ptr);
        assert_ne!(
            SSL_SUCCESS,
            tabby_SSL_set_tlsext_host_name(ssl_ptr, ptr::null() as *const c_char)
        );
        tabby_SSL_free(ssl_ptr);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn tabby_ssl_set_invalid_host_name() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLSv1_2_client_method());
        let ssl_ptr = tabby_SSL_new(ctx_ptr);
        assert_ne!(
            SSL_SUCCESS,
            tabby_SSL_set_tlsext_host_name(ssl_ptr, b"@#$%^&*(\0".as_ptr() as *const c_char)
        );
        tabby_SSL_free(ssl_ptr);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn tabby_ssl_set_good_host_name() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLSv1_2_client_method());
        let ssl_ptr = tabby_SSL_new(ctx_ptr);
        assert_eq!(
            SSL_SUCCESS,
            tabby_SSL_set_tlsext_host_name(ssl_ptr, b"google.com\0".as_ptr() as *const c_char)
        );
        tabby_SSL_free(ssl_ptr);
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn tabby_ssl_ctx_session_cache_mode_and_size() {
        let ctx_ptr = tabby_SSL_CTX_new(tabby_TLSv1_2_client_method());
        // Default cache mode is Both
        assert_eq!(
            tabby_SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Both as c_long
        );
        // Default cache size is SSL_SESSION_CACHE_MAX_SIZE_DEFAULT
        assert_eq!(
            tabby_SSL_CTX_sess_get_cache_size(ctx_ptr),
            SSL_SESSION_CACHE_MAX_SIZE_DEFAULT as c_long
        );
        // When cache mode is both, set the cache size to 100
        assert_eq!(
            tabby_SSL_CTX_sess_set_cache_size(ctx_ptr, 100),
            SSL_SESSION_CACHE_MAX_SIZE_DEFAULT as c_long
        );
        // Turn off session cache
        assert_eq!(
            tabby_SSL_CTX_set_session_cache_mode(ctx_ptr, SslSessionCacheModes::Off as c_long),
            SslSessionCacheModes::Both as c_long
        );
        // Now the cache mode is Off
        assert_eq!(
            tabby_SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Off as c_long
        );
        // The cache size to 100
        assert_eq!(tabby_SSL_CTX_sess_get_cache_size(ctx_ptr), 100);
        // When cache mode is Off, set the cache size to 200
        assert_eq!(tabby_SSL_CTX_sess_set_cache_size(ctx_ptr, 200), 100);
        // Set the cache mode to Client
        assert_eq!(
            tabby_SSL_CTX_set_session_cache_mode(ctx_ptr, SslSessionCacheModes::Client as c_long),
            SslSessionCacheModes::Off as c_long
        );
        assert_eq!(
            tabby_SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Client as c_long
        );
        // The cache size to 100
        assert_eq!(tabby_SSL_CTX_sess_get_cache_size(ctx_ptr), 200);
        // When cache mode is Client, set the cache size to 300
        assert_eq!(tabby_SSL_CTX_sess_set_cache_size(ctx_ptr, 300), 200);
        // Set the cache mode to Server
        assert_eq!(
            tabby_SSL_CTX_set_session_cache_mode(ctx_ptr, SslSessionCacheModes::Server as c_long),
            SslSessionCacheModes::Client as c_long
        );
        // Now the cache mode is Server
        assert_eq!(
            tabby_SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Server as c_long
        );
        // The cache size to 300
        assert_eq!(tabby_SSL_CTX_sess_get_cache_size(ctx_ptr), 300);
        // When cache mode is Server, set the cache size to 400
        assert_eq!(tabby_SSL_CTX_sess_set_cache_size(ctx_ptr, 400), 300);
        assert_eq!(
            tabby_SSL_CTX_set_session_cache_mode(ctx_ptr, SslSessionCacheModes::Both as c_long),
            SslSessionCacheModes::Server as c_long
        );
        assert_eq!(
            tabby_SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Both as c_long
        );
        tabby_SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn early_data_to_yimingjing_com() {
        const HTTP_REQUEST: &[u8; 83] = b"GET / HTTP/1.1\r\n\
            Host: mesalink.io\r\n\
            Connection: close\r\n\
            Accept-Encoding: identity\r\n\
            \r\n";

        let method = tabby_TLSv1_3_client_method();
        let ctx = tabby_SSL_CTX_new(method);
        let _ = tabby_SSL_CTX_set_session_cache_mode(ctx, SslSessionCacheModes::Client as c_long);

        for i in 0..2 {
            tabby_ERR_clear_error();
            let is_resuming = i != 0;
            let ssl = tabby_SSL_new(ctx);
            assert_ne!(ssl, ptr::null_mut(), "SSL is null");
            assert_eq!(
                SSL_SUCCESS,
                tabby_SSL_set_tlsext_host_name(ssl, b"yimingjing.com\0".as_ptr() as *const c_char),
                "Failed to set SNI"
            );
            let sock = net::TcpStream::connect("yimingjing.com:443").expect("Failed to connect");
            assert_eq!(SSL_SUCCESS, tabby_SSL_set_fd(ssl, sock.as_raw_fd()),);

            let early_written_len_ptr = Box::into_raw(Box::new(0));
            let ret = tabby_SSL_write_early_data(
                ssl,
                HTTP_REQUEST.as_ptr() as *const c_uchar,
                83,
                early_written_len_ptr,
            );
            if is_resuming {
                assert_eq!(true, ret == SSL_SUCCESS);
            }
            let early_written_len = unsafe { Box::from_raw(early_written_len_ptr) };
            if is_resuming {
                println!(
                    "Resuming session, buffered {} bytes of early data",
                    *early_written_len
                );
                assert_eq!(true, *early_written_len > 0);
            }

            if SSL_SUCCESS != tabby_SSL_connect(ssl) {
                let error = tabby_SSL_get_error(ssl, -1);
                panic!("Connect error: 0x{:X}\n", error);
            }
            if 2 != tabby_SSL_get_early_data_status(ssl) {
                let wr_len = tabby_SSL_write(ssl, HTTP_REQUEST.as_ptr() as *const c_uchar, 83);
                assert_eq!(true, wr_len > 0);
            }
            assert_eq!(SSL_SUCCESS, tabby_SSL_flush(ssl));

            let mut buf = [0u8; 2048];
            loop {
                let rd_len =
                    tabby_SSL_read(ssl, buf.as_mut_ptr() as *mut c_uchar, buf.len() as c_int);
                println!("Read {} bytes", rd_len);
                if rd_len <= 0 {
                    break;
                }
            }

            if is_resuming {
                let error = tabby_ERR_get_error();
                assert_eq!(0, error);
                let ssl_error = tabby_SSL_get_error(ssl, -1);
                assert_eq!(0, ssl_error);
            }

            assert_eq!(SSL_SUCCESS, tabby_SSL_shutdown(ssl));
            tabby_SSL_free(ssl);
        }
        tabby_SSL_CTX_free(ctx);
    }

    #[test]
    fn test_null_pointers_as_arguments() {
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_CTX_use_certificate_chain_file(ptr::null_mut(), ptr::null_mut(), 0)
        );
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_CTX_use_PrivateKey_file(ptr::null_mut(), ptr::null_mut(), 0)
        );
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_CIPHER_get_bits(ptr::null_mut(), ptr::null_mut())
        );
        let version_str_ptr_1 = tabby_SSL_CIPHER_get_version(ptr::null_mut());
        let version_str_1 = unsafe { ffi::CStr::from_ptr(version_str_ptr_1).to_str().unwrap() };
        assert_eq!(" NONE ", version_str_1);

        let version_str_ptr_2 = tabby_SSL_get_cipher(ptr::null_mut());
        assert_eq!(ptr::null(), version_str_ptr_2);

        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_read(ptr::null_mut(), ptr::null_mut(), 100)
        );
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_write(ptr::null_mut(), ptr::null_mut(), 100)
        );
        assert_eq!(SSL_FAILURE, tabby_SSL_flush(ptr::null_mut()));
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_write_early_data(ptr::null_mut(), ptr::null_mut(), 100, ptr::null_mut())
        );
        let buf = [0u8; 10];
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_write_early_data(
                ptr::null_mut(),
                buf.as_ptr() as *const c_uchar,
                10,
                ptr::null_mut()
            )
        );
    }

    #[test]
    fn test_io_before_full_handshake() {
        let ctx = tabby_SSL_CTX_new(tabby_TLS_client_method());
        let ssl = tabby_SSL_new(ctx);
        let mut buf = [0u8; 10];
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_read(ssl, buf.as_mut_ptr() as *mut c_uchar, 10)
        );
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_write(ssl, buf.as_ptr() as *const c_uchar, 10)
        );
        let wr_len_ptr = Box::into_raw(Box::new(0));
        assert_eq!(
            SSL_FAILURE,
            tabby_SSL_write_early_data(ssl, buf.as_ptr() as *const c_uchar, 10, wr_len_ptr)
        );
        let _ = unsafe { Box::from_raw(wr_len_ptr) };
        tabby_SSL_free(ssl);
        tabby_SSL_CTX_free(ctx);
    }
}
