/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
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

use super::err::{Error, ErrorCode, InnerResult};
use super::safestack::STACK_X509;
use super::x509::X509;
use super::{SslSessionCacheModes, SSL_ERROR, SSL_FAILURE, SSL_SUCCESS};
use crate::error_san::*;
use crate::libcrypto::evp::EVP_PKEY;
use crate::{OpaquePointerGuard, MAGIC, MAGIC_SIZE};

use rustls::client::{ClientSessionMemoryCache, NoClientSessionStorage};
use rustls::client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier};
use rustls::server::{AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient};
use rustls::server::{
    NoServerSessionStorage, ResolvesServerCertUsingSni, ServerSessionMemoryCache,
};
use rustls::version::{TLS12, TLS13};
use rustls::{Certificate, PrivateKey, RootCertStore, ServerName};
use rustls::{ClientConfig, OwnedTrustAnchor, ServerConfig};
use rustls::{ClientConnection, Connection, ServerConnection, Stream};
use rustls::{SupportedCipherSuite, SupportedProtocolVersion};

use libc::{c_char, c_int, c_long, c_uchar, c_void, size_t};
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::sync::Arc;
use std::{ffi, fs, io, net, path, ptr, slice};

// Trait imports
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};

const SSL_SESSION_CACHE_MAX_SIZE_DEFAULT: usize = 256; // Default value used by rustls

#[cfg(not(feature = "error_strings"))]
const CONST_NOTBUILTIN_STR: &'static [u8] = b"(Ciphersuite string not built-in)\0";

/// An OpenSSL Cipher object
#[allow(non_camel_case_types)]
pub struct CIPHER {
    magic: [u8; MAGIC_SIZE],
    ciphersuite: SupportedCipherSuite,
}

impl OpaquePointerGuard for CIPHER {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl CIPHER {
    fn new(ciphersuite: SupportedCipherSuite) -> CIPHER {
        CIPHER {
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
pub struct SSL_METHOD {
    magic: [u8; MAGIC_SIZE],
    versions: Vec<&'static SupportedProtocolVersion>,
    mode: ClientOrServerMode,
}

#[derive(Clone, PartialEq)]
enum ClientOrServerMode {
    Client,
    Server,
    Both,
}

impl OpaquePointerGuard for SSL_METHOD {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl SSL_METHOD {
    fn new(
        versions: Vec<&'static SupportedProtocolVersion>,
        mode: ClientOrServerMode,
    ) -> SSL_METHOD {
        SSL_METHOD {
            magic: *MAGIC,
            versions,
            mode,
        }
    }
}

struct NoServerAuth {}
impl ServerCertVerifier for NoServerAuth {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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
pub struct SSL_CTX {
    magic: [u8; MAGIC_SIZE],
    versions: Vec<&'static SupportedProtocolVersion>,
    certificates: Option<Vec<Certificate>>,
    private_key: Option<PrivateKey>,
    ca_roots: RootCertStore,
    session_cache_mode: SslSessionCacheModes,
    session_cache_size: usize,
    verify_modes: VerifyModes,
    mode: ClientOrServerMode,
}

#[allow(non_camel_case_types)]
#[doc(hidden)]
pub type SSL_CTX_ARC = Arc<SSL_CTX>;

impl OpaquePointerGuard for SSL_CTX_ARC {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl SSL_CTX {
    fn new(method: &SSL_METHOD) -> SSL_CTX {
        SSL_CTX {
            magic: *MAGIC,
            versions: method.versions.to_vec(),
            certificates: None,
            private_key: None,
            ca_roots: RootCertStore::empty(),
            session_cache_mode: SslSessionCacheModes::Both,
            session_cache_size: SSL_SESSION_CACHE_MAX_SIZE_DEFAULT,
            verify_modes: VerifyModes::VERIFY_PEER,
            mode: method.mode.clone(),
        }
    }
}

/// The main TLS structure which is created by a server or client per
/// established connection.
///
/// Pass a valid `SSL_CTX` object to `SSL_new` to create a new `SSL` object.
/// Then associate a valid socket file descriptor with `SSL_set_fd`.
#[allow(non_camel_case_types)]
pub struct SSL {
    magic: [u8; MAGIC_SIZE],
    context: Option<SSL_CTX_ARC>,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    hostname: Option<String>,
    io: Option<net::TcpStream>,
    session: Option<Connection>,
    last_error: Error,
    mode: ClientOrServerMode,
}

impl OpaquePointerGuard for SSL {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl Drop for SSL {
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

impl SSL {
    fn new(ctx: &SSL_CTX_ARC) -> SSL {
        let root_store = if ctx.ca_roots.is_empty() {
            let mut root_store = RootCertStore::empty();
            root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));
            root_store
        } else {
            ctx.ca_roots.clone()
        };

        let client_config_builder = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&ctx.versions)
            .unwrap();

        // Set client verify mode
        let client_config_builder_want_client_cert = match ctx.verify_modes {
            VerifyModes::VERIFY_NONE => {
                client_config_builder.with_custom_certificate_verifier(Arc::new(NoServerAuth {}))
            }
            _ => client_config_builder
                .with_custom_certificate_verifier(Arc::new(WebPkiVerifier::new(root_store, None))),
        };

        // Set client auth mode
        let mut client_config = match (ctx.certificates.as_ref(), ctx.private_key.as_ref()) {
            (Some(certificates), Some(private_key)) => client_config_builder_want_client_cert
                .with_single_cert(certificates.clone(), private_key.clone())
                .unwrap(),
            _ => client_config_builder_want_client_cert.with_no_client_auth(),
        };

        let server_config_builder = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&ctx.versions)
            .unwrap();

        let server_config_builder_want_server_cert = match ctx.verify_modes {
            VerifyModes::VERIFY_FAIL_IF_NO_PEER_CERT => server_config_builder
                .with_client_cert_verifier(AllowAnyAnonymousOrAuthenticatedClient::new(
                    ctx.ca_roots.clone(),
                )),
            VerifyModes::VERIFY_PEER => server_config_builder
                .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(ctx.ca_roots.clone())),
            _ => server_config_builder.with_no_client_auth(),
        };

        let mut server_config = match (ctx.certificates.as_ref(), ctx.private_key.as_ref()) {
            (Some(certificates), Some(private_key)) => server_config_builder_want_server_cert
                .with_single_cert(certificates.clone(), private_key.clone())
                .unwrap(),
            _ => server_config_builder_want_server_cert
                .with_cert_resolver(Arc::new(ResolvesServerCertUsingSni::new())),
        };

        // Set client/server session cache
        match ctx.session_cache_mode {
            SslSessionCacheModes::Off => {
                client_config.session_storage = Arc::new(NoClientSessionStorage {});
                server_config.session_storage = Arc::new(NoServerSessionStorage {});
            }
            SslSessionCacheModes::Client => {
                client_config.session_storage =
                    ClientSessionMemoryCache::new(ctx.session_cache_size);
                server_config.session_storage = Arc::new(NoServerSessionStorage {});
            }
            SslSessionCacheModes::Server => {
                client_config.session_storage = Arc::new(NoClientSessionStorage {});
                server_config.session_storage =
                    ServerSessionMemoryCache::new(ctx.session_cache_size);
            }
            SslSessionCacheModes::Both => {
                client_config.session_storage =
                    ClientSessionMemoryCache::new(ctx.session_cache_size);
                server_config.session_storage =
                    ServerSessionMemoryCache::new(ctx.session_cache_size);
            }
        }

        SSL {
            magic: *MAGIC,
            context: Some(ctx.clone()), // reference count +1
            client_config: Arc::new(client_config),
            server_config: Arc::new(server_config),
            hostname: None,
            io: None,
            session: None,
            last_error: Error::None,
            mode: ctx.mode.clone(),
        }
    }

    pub(crate) fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => match session {
                Connection::Client(conn) => {
                    let mut stream = Stream::new(conn, io);
                    stream.read(buf).map_err(|e| Error::Io(e.kind()))
                }
                Connection::Server(conn) => {
                    let mut stream = Stream::new(conn, io);
                    stream.read(buf).map_err(|e| Error::Io(e.kind()))
                }
            },
            _ => Err(Error::BadFuncArg),
        }
    }

    pub(crate) fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => match session {
                Connection::Client(conn) => {
                    let mut stream = Stream::new(conn, io);
                    stream.write(buf).map_err(|e| Error::Io(e.kind()))
                }
                Connection::Server(conn) => {
                    let mut stream = Stream::new(conn, io);
                    stream.write(buf).map_err(|e| Error::Io(e.kind()))
                }
            },
            _ => Err(Error::BadFuncArg),
        }
    }

    pub(crate) fn ssl_flush(&mut self) -> Result<(), Error> {
        match (self.session.as_mut(), self.io.as_mut()) {
            (Some(session), Some(io)) => match session {
                Connection::Client(conn) => {
                    let mut stream = Stream::new(conn, io);
                    stream.flush().map_err(|e| Error::Io(e.kind()))
                }
                Connection::Server(conn) => {
                    let mut stream = Stream::new(conn, io);
                    stream.flush().map_err(|e| Error::Io(e.kind()))
                }
            },
            _ => Err(Error::BadFuncArg),
        }
    }

    pub(crate) fn ssl_write_early_data(&mut self, buf: &[u8]) -> Result<usize, Error> {
        match self.session.as_mut() {
            Some(Connection::Client(session)) => {
                let mut early_writer = session
                    .early_data()
                    .ok_or(Error::Io(io::ErrorKind::InvalidData))?;
                early_writer.write(buf).map_err(|e| Error::Io(e.kind()))
            }
            _ => Err(Error::BadFuncArg),
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
pub extern "C" fn SSL_library_init() -> c_int {
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
pub extern "C" fn OpenSSL_add_ssl_algorithms() -> c_int {
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
pub extern "C" fn SSL_load_error_strings() {
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
pub extern "C" fn SSL_init_logger() {
    init_logger();
}

fn not_available_method() -> *const SSL_METHOD {
    let p: *const SSL_METHOD = ptr::null();
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
pub extern "C" fn TLS_method() -> *const SSL_METHOD {
    let versions = vec![&TLS12, &TLS13];
    let method = SSL_METHOD::new(versions, ClientOrServerMode::Both);
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
pub extern "C" fn TLS_client_method() -> *const SSL_METHOD {
    let method = SSL_METHOD::new(vec![&TLS12, &TLS13], ClientOrServerMode::Client);
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
pub extern "C" fn SSLv23_client_method() -> *const SSL_METHOD {
    TLS_client_method()
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
pub extern "C" fn SSLv3_client_method() -> *const SSL_METHOD {
    not_available_method()
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
pub extern "C" fn TLSv1_client_method() -> *const SSL_METHOD {
    not_available_method()
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
pub extern "C" fn TLSv1_1_client_method() -> *const SSL_METHOD {
    not_available_method()
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
pub extern "C" fn TLSv1_2_client_method() -> *const SSL_METHOD {
    let method = SSL_METHOD::new(vec![&TLS12], ClientOrServerMode::Client);
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
pub extern "C" fn TLSv1_3_client_method() -> *const SSL_METHOD {
    let method = SSL_METHOD::new(vec![&TLS13], ClientOrServerMode::Client);
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
pub extern "C" fn TLS_server_method() -> *const SSL_METHOD {
    let method = SSL_METHOD::new(vec![&TLS12, &TLS13], ClientOrServerMode::Server);
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

pub extern "C" fn SSLv23_server_method() -> *const SSL_METHOD {
    TLS_server_method()
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

pub extern "C" fn SSLv3_server_method() -> *const SSL_METHOD {
    not_available_method()
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

pub extern "C" fn TLSv1_server_method() -> *const SSL_METHOD {
    not_available_method()
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

pub extern "C" fn TLSv1_1_server_method() -> *const SSL_METHOD {
    not_available_method()
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

pub extern "C" fn TLSv1_2_server_method() -> *const SSL_METHOD {
    let method = SSL_METHOD::new(vec![&TLS12], ClientOrServerMode::Server);
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
pub extern "C" fn TLSv1_3_server_method() -> *const SSL_METHOD {
    let method = SSL_METHOD::new(vec![&TLS13], ClientOrServerMode::Server);
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
pub extern "C" fn SSL_CTX_new(method_ptr: *const SSL_METHOD) -> *mut SSL_CTX_ARC {
    check_inner_result!(inner_ssl_ctx_new(method_ptr), ptr::null_mut())
}

fn inner_ssl_ctx_new(method_ptr: *const SSL_METHOD) -> InnerResult<*mut SSL_CTX_ARC> {
    let method = sanitize_const_ptr_for_ref(method_ptr)?;
    let context = SSL_CTX::new(method);
    let _ = unsafe { Box::from_raw(method_ptr as *mut SSL_METHOD) };
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
pub extern "C" fn SSL_CTX_load_verify_locations(
    ctx_ptr: *mut SSL_CTX_ARC,
    cafile_ptr: *const c_char,
    capath_ptr: *const c_char,
) -> c_int {
    check_inner_result!(
        inner_ssl_ctx_load_verify_locations(ctx_ptr, cafile_ptr, capath_ptr),
        SSL_FAILURE
    )
}

fn inner_ssl_ctx_load_verify_locations(
    ctx_ptr: *mut SSL_CTX_ARC,
    cafile_ptr: *const c_char,
    capath_ptr: *const c_char,
) -> InnerResult<c_int> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    if cafile_ptr.is_null() && capath_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let ctx = util::get_context_mut(ctx);
    if !cafile_ptr.is_null() {
        let cafile = unsafe {
            ffi::CStr::from_ptr(cafile_ptr)
                .to_str()
                .map_err(|_| Error::BadFuncArg)?
        };
        load_cert_into_root_store(&mut ctx.ca_roots, path::Path::new(cafile))?;
    }
    if !capath_ptr.is_null() {
        let capath = unsafe {
            ffi::CStr::from_ptr(capath_ptr)
                .to_str()
                .map_err(|_| Error::BadFuncArg)?
        };
        let dir = fs::read_dir(path::Path::new(capath)).map_err(|_| Error::BadFuncArg)?;
        for file_path in dir {
            let file_path = file_path.map_err(|_| Error::BadFuncArg)?;
            load_cert_into_root_store(&mut ctx.ca_roots, &file_path.path())?;
        }
    }

    Ok(SSL_SUCCESS)
}

fn load_cert_into_root_store(store: &mut RootCertStore, path: &path::Path) -> InnerResult<()> {
    let file = fs::File::open(path).map_err(|e| Error::Io(e.kind()))?;
    let mut reader = io::BufReader::new(file);
    let der_certificates = rustls_pemfile::certs(&mut reader).map_err(|_| Error::BadFuncArg)?;
    let _ = store.add_parsable_certificates(&der_certificates);
    Ok(())
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
pub extern "C" fn SSL_CTX_use_certificate_chain_file(
    ctx_ptr: *mut SSL_CTX_ARC,
    filename_ptr: *const c_char,
    _format: c_int,
) -> c_int {
    check_inner_result!(
        inner_ssl_ctx_use_certificate_chain_file(ctx_ptr, filename_ptr),
        SSL_FAILURE
    )
}

fn inner_ssl_ctx_use_certificate_chain_file(
    ctx_ptr: *mut SSL_CTX_ARC,
    filename_ptr: *const c_char,
) -> InnerResult<c_int> {
    use crate::libcrypto::pem;

    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    if filename_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let filename = unsafe {
        ffi::CStr::from_ptr(filename_ptr)
            .to_str()
            .map_err(|_| Error::BadFuncArg)?
    };
    let file = fs::File::open(filename).map_err(|e| Error::Io(e.kind()))?;
    let mut buf_reader = io::BufReader::new(file);
    let certs = pem::get_certificate_chain(&mut buf_reader);
    if certs.is_empty() {
        return Err(Error::BadFuncArg);
    }
    util::get_context_mut(ctx).certificates = Some(certs);
    Ok(SSL_SUCCESS)
}

/// `SSL_CTX_use_certificate` loads the certificate x into ctx. The rest of the
/// certificates needed to form the complete certificate chain can be specified
/// using the `SSL_CTX_add_extra_chain_cert` function.
#[no_mangle]
pub extern "C" fn SSL_CTX_use_certificate(ctx_ptr: *mut SSL_CTX_ARC, x509_ptr: *mut X509) -> c_int {
    check_inner_result!(
        inner_ssl_ctx_add_certificate(ctx_ptr, x509_ptr),
        SSL_FAILURE
    )
}

#[no_mangle]
pub extern "C" fn SSL_CTX_add_extra_chain_cert(
    ctx_ptr: *mut SSL_CTX_ARC,
    x509_ptr: *mut X509,
) -> c_int {
    check_inner_result!(
        inner_ssl_ctx_add_certificate(ctx_ptr, x509_ptr),
        SSL_FAILURE
    )
}

fn inner_ssl_ctx_add_certificate(
    ctx_ptr: *mut SSL_CTX_ARC,
    x509_ptr: *mut X509,
) -> InnerResult<c_int> {
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
    Ok(SSL_SUCCESS)
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
pub extern "C" fn SSL_CTX_use_certificate_ASN1(
    ctx_ptr: *mut SSL_CTX_ARC,
    len: c_int,
    d: *mut c_uchar,
) -> c_int {
    check_inner_result!(
        inner_ssl_ctx_use_certificate_asn1(ctx_ptr, len, d),
        SSL_FAILURE
    )
}

fn inner_ssl_ctx_use_certificate_asn1(
    ctx_ptr: *mut SSL_CTX_ARC,
    len: c_int,
    d: *mut c_uchar,
) -> InnerResult<c_int> {
    if d.is_null() {
        return Err(Error::NullPointer);
    }
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let buf: &[u8] = unsafe { slice::from_raw_parts_mut(d, len as usize) };
    {
        let ctx_mut_ref = util::get_context_mut(ctx);
        if ctx_mut_ref.certificates.is_none() {
            ctx_mut_ref.certificates = Some(vec![]);
        }
        ctx_mut_ref
            .certificates
            .as_mut()
            .unwrap()
            .push(Certificate(buf.to_vec()));
    }
    Ok(SSL_SUCCESS)
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
pub extern "C" fn SSL_use_certificate_ASN1(
    ssl_ptr: *mut SSL,
    d: *mut c_uchar,
    len: c_int,
) -> c_int {
    check_inner_result!(inner_ssl_use_certificate_asn1(ssl_ptr, d, len), SSL_FAILURE)
}

fn inner_ssl_use_certificate_asn1(
    ssl_ptr: *mut SSL,
    d: *mut c_uchar,
    len: c_int,
) -> InnerResult<c_int> {
    let ctx_ptr = inner_ssl_get_ssl_ctx(ssl_ptr)?;
    let _ = inner_ssl_ctx_use_certificate_asn1(ctx_ptr, len, d)?;
    let _ = inner_ssl_set_ssl_ctx(ssl_ptr, ctx_ptr)?;
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
pub extern "C" fn SSL_CTX_use_PrivateKey(
    ctx_ptr: *mut SSL_CTX_ARC,
    pkey_ptr: *mut EVP_PKEY,
) -> c_int {
    check_inner_result!(inner_ssl_ctx_use_privatekey(ctx_ptr, pkey_ptr), SSL_FAILURE)
}

fn inner_ssl_ctx_use_privatekey(
    ctx_ptr: *mut SSL_CTX_ARC,
    pkey_ptr: *mut EVP_PKEY,
) -> InnerResult<c_int> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let pkey = sanitize_ptr_for_mut_ref(pkey_ptr)?;
    let key = pkey.inner.clone();
    util::get_context_mut(ctx).private_key = Some(key);
    Ok(SSL_SUCCESS)
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
pub extern "C" fn SSL_CTX_use_PrivateKey_file(
    ctx_ptr: *mut SSL_CTX_ARC,
    filename_ptr: *const c_char,
    _format: c_int,
) -> c_int {
    check_inner_result!(
        inner_ssl_ctx_use_privatekey_file(ctx_ptr, filename_ptr),
        SSL_FAILURE
    )
}

fn inner_ssl_ctx_use_privatekey_file(
    ctx_ptr: *mut SSL_CTX_ARC,
    filename_ptr: *const c_char,
) -> InnerResult<c_int> {
    use crate::libcrypto::pem;

    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    if filename_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let filename = unsafe {
        ffi::CStr::from_ptr(filename_ptr)
            .to_str()
            .map_err(|_| Error::BadFuncArg)?
    };
    let file = fs::File::open(filename).map_err(|e| Error::Io(e.kind()))?;
    let mut buf_reader = io::BufReader::new(file);
    let key =
        pem::get_either_rsa_or_ecdsa_private_key(&mut buf_reader).map_err(|_| Error::BadFuncArg)?;
    util::get_context_mut(ctx).private_key = Some(key);
    Ok(SSL_SUCCESS)
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
pub extern "C" fn SSL_CTX_use_PrivateKey_ASN1(
    pk_type: c_int,
    ctx_ptr: *mut SSL_CTX_ARC,
    d: *mut c_uchar,
    len: c_long,
) -> c_int {
    check_inner_result!(
        inner_ssl_ctx_use_privatekey_asn1(pk_type, ctx_ptr, d, len),
        SSL_FAILURE
    )
}

fn inner_ssl_ctx_use_privatekey_asn1(
    _pk_type: c_int,
    ctx_ptr: *mut SSL_CTX_ARC,
    d: *mut c_uchar,
    len: c_long,
) -> InnerResult<c_int> {
    if d.is_null() {
        return Err(Error::NullPointer);
    }
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let buf: &[u8] = unsafe { slice::from_raw_parts_mut(d, len as usize) };
    let pkey = PrivateKey(buf.to_vec());
    util::get_context_mut(ctx).private_key = Some(pkey);
    Ok(SSL_SUCCESS)
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
pub extern "C" fn SSL_use_PrivateKey_ASN1(
    pk_type: c_int,
    ssl_ptr: *mut SSL,
    d: *mut c_uchar,
    len: c_long,
) -> c_int {
    check_inner_result!(
        inner_ssl_use_privatekey_asn1(pk_type, ssl_ptr, d, len),
        SSL_FAILURE
    )
}

fn inner_ssl_use_privatekey_asn1(
    pk_type: c_int,
    ssl_ptr: *mut SSL,
    d: *mut c_uchar,
    len: c_long,
) -> InnerResult<c_int> {
    let ctx_ptr = inner_ssl_get_ssl_ctx(ssl_ptr)?;
    let _ = inner_ssl_ctx_use_privatekey_asn1(pk_type, ctx_ptr, d, len)?;
    let _ = inner_ssl_set_ssl_ctx(ssl_ptr, ctx_ptr)?;
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
pub extern "C" fn SSL_CTX_check_private_key(ctx_ptr: *mut SSL_CTX_ARC) -> c_int {
    check_inner_result!(inner_ssl_ctx_check_private_key(ctx_ptr), SSL_FAILURE)
}

fn inner_ssl_ctx_check_private_key(ctx_ptr: *mut SSL_CTX_ARC) -> InnerResult<c_int> {
    use rustls::sign;
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    match (&ctx.certificates, &ctx.private_key) {
        (&Some(ref certs), &Some(ref key)) => {
            let signing_key = sign::any_supported_type(key).map_err(|_| Error::BadFuncArg)?;
            let _ = sign::CertifiedKey::new(certs.clone(), signing_key)
                .end_entity_cert()
                .map_err(|_| Error::BadFuncArg)?; // SignError
            Ok(SSL_SUCCESS)
        }
        _ => Err(Error::BadFuncArg),
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
pub extern "C" fn SSL_check_private_key(ctx_ptr: *mut SSL) -> c_int {
    check_inner_result!(inner_ssl_check_private_key(ctx_ptr), SSL_FAILURE)
}

fn inner_ssl_check_private_key(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;

    let ctx = ssl.context.as_ref().ok_or(Error::BadFuncArg)?;
    let ctx_ptr = ctx as *const SSL_CTX_ARC as *mut SSL_CTX_ARC;
    inner_ssl_ctx_check_private_key(ctx_ptr)
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
pub extern "C" fn SSL_CTX_set_verify(
    ctx_ptr: *mut SSL_CTX_ARC,
    mode: c_int,
    _cb: Option<extern "C" fn(c_int, *mut c_void) -> c_int>,
) -> c_int {
    check_inner_result!(inner_ssl_ctx_set_verify(ctx_ptr, mode), SSL_FAILURE)
}

fn inner_ssl_ctx_set_verify(ctx_ptr: *mut SSL_CTX_ARC, mode: c_int) -> InnerResult<c_int> {
    let mode = VerifyModes::from_bits(mode).ok_or(Error::BadFuncArg)?;
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let ctx_mut = util::get_context_mut(ctx);
    ctx_mut.verify_modes = mode;
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
pub extern "C" fn SSL_CTX_set_session_cache_mode(
    ctx_ptr: *mut SSL_CTX_ARC,
    mode: c_long,
) -> c_long {
    let error_ret: c_long = SSL_ERROR.into();
    check_inner_result!(
        inner_ssl_ctx_set_session_cache_mode(ctx_ptr, mode),
        error_ret
    )
}

fn inner_ssl_ctx_set_session_cache_mode(
    ctx_ptr: *mut SSL_CTX_ARC,
    mode: c_long,
) -> InnerResult<c_long> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let prev_mode = ctx.session_cache_mode.clone() as c_long;
    let ctx_mut = util::get_context_mut(ctx);

    if mode == SslSessionCacheModes::Off as c_long {
        ctx_mut.session_cache_mode = SslSessionCacheModes::Off;
    } else if mode == SslSessionCacheModes::Client as c_long {
        ctx_mut.session_cache_mode = SslSessionCacheModes::Client;
    } else if mode == SslSessionCacheModes::Server as c_long {
        ctx_mut.session_cache_mode = SslSessionCacheModes::Server;
    } else if mode == SslSessionCacheModes::Both as c_long {
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
pub extern "C" fn SSL_CTX_get_session_cache_mode(ctx_ptr: *mut SSL_CTX_ARC) -> c_long {
    let error_ret: c_long = SSL_ERROR.into();
    check_inner_result!(inner_ssl_ctx_get_session_cache_mode(ctx_ptr), error_ret)
}

fn inner_ssl_ctx_get_session_cache_mode(ctx_ptr: *mut SSL_CTX_ARC) -> InnerResult<c_long> {
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
pub extern "C" fn SSL_CTX_sess_set_cache_size(ctx_ptr: *mut SSL_CTX_ARC, t: c_long) -> c_long {
    let error_ret: c_long = SSL_ERROR.into();
    check_inner_result!(inner_ssl_ctx_sess_set_cache_size(ctx_ptr, t), error_ret)
}

fn inner_ssl_ctx_sess_set_cache_size(ctx_ptr: *mut SSL_CTX_ARC, t: c_long) -> InnerResult<c_long> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let prev_size = ctx.session_cache_size;
    let ctx_mut = util::get_context_mut(ctx);
    ctx_mut.session_cache_size = t as usize;
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
pub extern "C" fn SSL_CTX_sess_get_cache_size(ctx_ptr: *mut SSL_CTX_ARC) -> c_long {
    let error_ret: c_long = SSL_ERROR.into();
    check_inner_result!(inner_ssl_ctx_sess_get_cache_size(ctx_ptr), error_ret)
}

fn inner_ssl_ctx_sess_get_cache_size(ctx_ptr: *mut SSL_CTX_ARC) -> InnerResult<c_long> {
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
pub extern "C" fn SSL_new(ctx_ptr: *mut SSL_CTX_ARC) -> *mut SSL {
    check_inner_result!(inner_ssl_new(ctx_ptr), ptr::null_mut())
}

fn inner_ssl_new(ctx_ptr: *mut SSL_CTX_ARC) -> InnerResult<*mut SSL> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    Ok(Box::into_raw(Box::new(SSL::new(ctx))))
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
pub extern "C" fn SSL_get_SSL_CTX(ssl_ptr: *mut SSL) -> *const SSL_CTX_ARC {
    check_inner_result!(inner_ssl_get_ssl_ctx(ssl_ptr), ptr::null())
}

fn inner_ssl_get_ssl_ctx(ssl_ptr: *mut SSL) -> InnerResult<*mut SSL_CTX_ARC> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;
    let ctx = ssl.context.as_ref().ok_or(Error::BadFuncArg)?;
    Ok(ctx as *const SSL_CTX_ARC as *mut SSL_CTX_ARC)
}

/// `SSL_set_SSL_CTX` - set the SSL_CTX object of an SSL object.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx);
/// ```
#[no_mangle]
pub extern "C" fn SSL_set_SSL_CTX(
    ssl_ptr: *mut SSL,
    ctx_ptr: *mut SSL_CTX_ARC,
) -> *const SSL_CTX_ARC {
    check_inner_result!(inner_ssl_set_ssl_ctx(ssl_ptr, ctx_ptr), ptr::null())
}

fn inner_ssl_set_ssl_ctx(
    ssl_ptr: *mut SSL,
    ctx_ptr: *mut SSL_CTX_ARC,
) -> InnerResult<*const SSL_CTX_ARC> {
    let ctx = sanitize_ptr_for_mut_ref(ctx_ptr)?;
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    ssl.context = Some(ctx.clone());
    let ctx_ref = ssl.context.as_ref().ok_or(Error::BadFuncArg)?;
    Ok(ctx_ref as *const SSL_CTX_ARC)
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
pub extern "C" fn SSL_get_current_cipher(ssl_ptr: *mut SSL) -> *mut CIPHER {
    check_inner_result!(inner_ssl_get_current_cipher(ssl_ptr), ptr::null_mut())
}

fn inner_ssl_get_current_cipher(ssl_ptr: *mut SSL) -> InnerResult<*mut CIPHER> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;
    let session = ssl.session.as_ref().ok_or(Error::BadFuncArg)?;
    let ciphersuite = session.negotiated_cipher_suite().ok_or(Error::BadFuncArg)?;
    Ok(Box::into_raw(Box::new(CIPHER::new(ciphersuite)))) // Allocates memory!
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
pub extern "C" fn SSL_CIPHER_get_name(cipher_ptr: *mut CIPHER) -> *const c_char {
    check_inner_result!(inner_ssl_cipher_get_name(cipher_ptr), ptr::null())
}

#[cfg(feature = "error_strings")]
fn inner_ssl_cipher_get_name(cipher_ptr: *mut CIPHER) -> InnerResult<*const c_char> {
    let ciphersuite = sanitize_ptr_for_ref(cipher_ptr)?;
    Ok(
        util::suite_to_name_str(ciphersuite.ciphersuite.suite().get_u16()).as_ptr()
            as *const c_char,
    )
}

#[no_mangle]
#[cfg(not(feature = "error_strings"))]
pub extern "C" fn SSL_CIPHER_get_name(cipher_ptr: *mut CIPHER) -> *const c_char {
    check_inner_result!(inner_ssl_cipher_get_name(cipher_ptr), ptr::null())
}

#[cfg(not(feature = "error_strings"))]
fn inner_ssl_cipher_get_name(cipher_ptr: *mut CIPHER) -> InnerResult<*const c_char> {
    let _ = sanitize_ptr_for_ref(cipher_ptr)?;
    Ok(CONST_NOTBUILTIN_STR.as_ptr() as *const c_char)
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
pub extern "C" fn SSL_CIPHER_get_version(cipher_ptr: *mut CIPHER) -> *const c_char {
    inner_ssl_cipher_get_version(cipher_ptr)
}

fn inner_ssl_cipher_get_version(cipher_ptr: *mut CIPHER) -> *const c_char {
    match sanitize_ptr_for_ref(cipher_ptr) {
        Ok(ciphersuite) => {
            let version = util::suite_to_version_str(ciphersuite.ciphersuite.suite().get_u16());
            version.as_ptr() as *const c_char
        }
        Err(_) => util::CONST_NONE_STR.as_ptr() as *const c_char,
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
pub extern "C" fn SSL_get_cipher_name(ssl_ptr: *mut SSL) -> *const c_char {
    let cipher = SSL_get_current_cipher(ssl_ptr);
    let ret = SSL_CIPHER_get_name(cipher);
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
pub extern "C" fn SSL_get_cipher(ssl_ptr: *mut SSL) -> *const c_char {
    SSL_get_cipher_name(ssl_ptr)
}

/// `SSL_get_cipher_version` - returns the protocol name.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// char* SSL_get_cipher_version(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn SSL_get_cipher_version(ssl_ptr: *mut SSL) -> *const c_char {
    let cipher = SSL_get_current_cipher(ssl_ptr);
    let ret = SSL_CIPHER_get_version(cipher);
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
pub extern "C" fn SSL_get_peer_certificate(ssl_ptr: *mut SSL) -> *mut X509 {
    check_inner_result!(inner_ssl_get_peer_certificate(ssl_ptr), ptr::null_mut())
}

fn inner_ssl_get_peer_certificate(ssl_ptr: *mut SSL) -> InnerResult<*mut X509> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let certs = get_peer_certificates(ssl)?;
    let x509 = X509::new(certs[0].clone());
    Ok(Box::into_raw(Box::new(x509)) as *mut X509)
}

/// `SSL_get_peer_certificates` - get the X509 certificate chain of the peer
///
/// ```c
///  #include <openssl/ssl.h>
///
/// STACK_OF(X509) *SSL_get_peer_certificates(const SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn SSL_get_peer_certificates(ssl_ptr: *mut SSL) -> *mut STACK_X509 {
    check_inner_result!(inner_ssl_get_peer_certificates(ssl_ptr), ptr::null_mut())
}

fn inner_ssl_get_peer_certificates(ssl_ptr: *mut SSL) -> InnerResult<*mut STACK_X509> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;

    let certs = get_peer_certificates(ssl)?;
    let mut vec: Vec<X509> = Vec::new();
    for cert in certs {
        let x509 = X509::new(cert.clone());
        vec.push(x509);
    }
    let x509_stack = STACK_X509::new(vec);
    Ok(Box::into_raw(Box::new(x509_stack)) as *mut STACK_X509)
}

fn get_peer_certificates(ssl: &SSL) -> InnerResult<&[Certificate]> {
    let session = ssl.session.as_ref().ok_or(Error::BadFuncArg)?;
    session
        .peer_certificates()
        .ok_or(Error::BadFuncArg)
        .and_then(|certs| {
            if certs.is_empty() {
                Err(Error::BadFuncArg)
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
pub extern "C" fn SSL_set_tlsext_host_name(
    ssl_ptr: *mut SSL,
    hostname_ptr: *const c_char,
) -> c_int {
    check_inner_result!(
        inner_ssl_set_tlsext_host_name(ssl_ptr, hostname_ptr),
        SSL_FAILURE
    )
}

fn inner_ssl_set_tlsext_host_name(
    ssl_ptr: *mut SSL,
    hostname_ptr: *const c_char,
) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    if hostname_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let hostname = unsafe {
        ffi::CStr::from_ptr(hostname_ptr)
            .to_str()
            .map_err(|_| Error::BadFuncArg)?
    };
    let _ = webpki::DnsNameRef::try_from_ascii_str(hostname).map_err(|_| Error::BadFuncArg)?;
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
pub extern "C" fn SSL_set_fd(ssl_ptr: *mut SSL, fd: c_int) -> c_int {
    #[cfg(unix)]
    {
        check_inner_result!(inner_ssl_set_fd(ssl_ptr, fd), SSL_FAILURE)
    }

    #[cfg(windows)]
    {
        check_inner_result!(
            inner_ssl_set_socket(ssl_ptr, fd as libc::SOCKET),
            SSL_FAILURE
        )
    }
}

#[cfg(unix)]
fn inner_ssl_set_fd(ssl_ptr: *mut SSL, fd: c_int) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    if fd < 0 {
        return Err(Error::BadFuncArg);
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
pub extern "C" fn SSL_get_fd(ssl_ptr: *mut SSL) -> c_int {
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
fn inner_measlink_ssl_get_fd(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;
    let socket = ssl.io.as_ref().ok_or(Error::BadFuncArg)?;
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
pub extern "C" fn SSL_set_socket(ssl_ptr: *mut SSL, sock: libc::SOCKET) -> c_int {
    check_inner_result!(inner_ssl_set_socket(ssl_ptr, sock), SSL_FAILURE)
}

#[cfg(windows)]
fn inner_ssl_set_socket(ssl_ptr: *mut SSL, sock: libc::SOCKET) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    if sock == 0 {
        return Err(Error::BadFuncArg);
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
pub extern "C" fn SSL_get_socket(ssl_ptr: *mut SSL) -> libc::SOCKET {
    check_inner_result!(inner_measlink_ssl_get_socket(ssl_ptr), 0)
}

#[cfg(windows)]
fn inner_measlink_ssl_get_socket(ssl_ptr: *mut SSL) -> InnerResult<libc::SOCKET> {
    let ssl = sanitize_ptr_for_ref(ssl_ptr)?;
    let socket = ssl.io.as_ref().ok_or(Error::BadFuncArg)?;
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
pub extern "C" fn SSL_set_connect_state(ssl_ptr: *mut SSL) {
    let _ = check_inner_result!(inner_ssl_set_mode(ssl_ptr, false), SSL_FAILURE);
}

/// `SSL_set_accept_state` sets *ssl* to work in server mode.
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// void SSL_set_accept_state(SSL *ssl);
/// ```
#[no_mangle]
pub extern "C" fn SSL_set_accept_state(ssl_ptr: *mut SSL) {
    let _ = check_inner_result!(inner_ssl_set_mode(ssl_ptr, true), SSL_FAILURE);
}

fn inner_ssl_set_mode(ssl_ptr: *mut SSL, is_server: bool) -> InnerResult<c_int> {
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
pub extern "C" fn SSL_is_server(ssl_ptr: *mut SSL) -> c_int {
    check_inner_result!(inner_is_server_mode(ssl_ptr), SSL_FAILURE)
}

fn inner_is_server_mode(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
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
pub extern "C" fn SSL_do_handshake(ssl_ptr: *mut SSL) -> c_int {
    check_inner_result!(inner_ssl_do_handshake(ssl_ptr), SSL_FAILURE)
}

fn inner_ssl_do_handshake(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let _ = setup_ssl_if_ready(ssl)?;
    Ok(SSL_SUCCESS)
}

fn setup_ssl_if_ready(ssl: &mut SSL) -> InnerResult<c_int> {
    if ssl.session.is_none() {
        match ssl.mode {
            ClientOrServerMode::Client | ClientOrServerMode::Both => {
                let hostname = ssl.hostname.as_ref().ok_or(Error::BadFuncArg)?.clone();

                let server_name =
                    ServerName::try_from(hostname.as_str()).map_err(|_| Error::BadFuncArg)?;
                let client_session = ClientConnection::new(ssl.client_config.clone(), server_name)
                    .map_err(|_| Error::BadFuncArg)?;
                ssl.session = Some(Connection::Client(client_session));
            }
            ClientOrServerMode::Server => {
                let server_session = ServerConnection::new(ssl.server_config.clone())
                    .map_err(|_| Error::BadFuncArg)?;
                ssl.session = Some(Connection::Server(server_session));
            }
        }
    }
    Ok(SSL_SUCCESS)
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
pub extern "C" fn SSL_connect(ssl_ptr: *mut SSL) -> c_int {
    check_inner_result!(inner_ssl_connect(ssl_ptr), SSL_FAILURE)
}

fn inner_ssl_connect(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    ssl.mode = ClientOrServerMode::Client;
    let _ = setup_ssl_if_ready(ssl)?;
    Ok(SSL_SUCCESS)
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
pub extern "C" fn SSL_accept(ssl_ptr: *mut SSL) -> c_int {
    check_inner_result!(inner_ssl_accept(ssl_ptr), SSL_FAILURE)
}

fn inner_ssl_accept(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    ssl.mode = ClientOrServerMode::Server;
    let _ = setup_ssl_if_ready(ssl)?;
    Ok(SSL_SUCCESS)
}

/// `SSL_get_error` - obtain result code for TLS/SSL I/O operation
///
/// ```c
/// #include <mesalink/openssl/ssl.h>
///
/// int SSL_get_error(const SSL *ssl, int ret);
/// ```
#[no_mangle]
pub extern "C" fn SSL_get_error(ssl_ptr: *mut SSL, ret: c_int) -> c_int {
    check_inner_result!(inner_ssl_get_error(ssl_ptr, ret), SSL_FAILURE)
}

fn inner_ssl_get_error(ssl_ptr: *mut SSL, ret: c_int) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    if ret > 0 {
        Ok(ErrorCode::None as c_int)
    } else {
        match &ssl.last_error {
            Error::None => Ok(ErrorCode::None as c_int),
            Error::Io(e) => match e {
                io::ErrorKind::WouldBlock => Ok(ErrorCode::WantRead as c_int),
                _ => Ok(ErrorCode::Syscall as c_int),
            },
            Error::Tls(_) => Ok(ErrorCode::Ssl as c_int),
            _ => Ok(ErrorCode::InvalidInput as c_int),
        }
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
pub extern "C" fn SSL_read(ssl_ptr: *mut SSL, buf_ptr: *mut c_void, buf_len: c_int) -> c_int {
    check_inner_result!(inner_ssl_read(ssl_ptr, buf_ptr, buf_len), SSL_FAILURE)
}

fn inner_ssl_read(ssl_ptr: *mut SSL, buf_ptr: *mut c_void, buf_len: c_int) -> InnerResult<c_int> {
    if buf_ptr.is_null() || buf_len < 0 {
        return Err(Error::BadFuncArg);
    }
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let buf = unsafe { slice::from_raw_parts_mut(buf_ptr as *mut c_uchar, buf_len as usize) };
    ssl.ssl_read(buf).map(|ret| ret as c_int).or_else(|e| {
        if let Error::Io(io::ErrorKind::WouldBlock) = e {
            return Ok(SSL_ERROR);
        }
        ssl.last_error = e.clone();
        Err(e)
    })
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
pub extern "C" fn SSL_write(ssl_ptr: *mut SSL, buf_ptr: *const c_void, buf_len: c_int) -> c_int {
    check_inner_result!(inner_ssl_write(ssl_ptr, buf_ptr, buf_len), SSL_FAILURE)
}

fn inner_ssl_write(
    ssl_ptr: *mut SSL,
    buf_ptr: *const c_void,
    buf_len: c_int,
) -> InnerResult<c_int> {
    if buf_ptr.is_null() || buf_len < 0 {
        return Err(Error::BadFuncArg);
    }
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let buf = unsafe { slice::from_raw_parts(buf_ptr as *const c_uchar, buf_len as usize) };
    ssl.ssl_write(buf).map(|ret| ret as c_int).or_else(|e| {
        if let Error::Io(io::ErrorKind::WouldBlock) = e {
            return Ok(SSL_ERROR);
        }
        ssl.last_error = e.clone();
        Err(e)
    })
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
pub extern "C" fn SSL_flush(ssl_ptr: *mut SSL) -> c_int {
    check_inner_result!(inner_ssl_flush(ssl_ptr), SSL_FAILURE)
}

fn inner_ssl_flush(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    ssl.ssl_flush().map(|_| SSL_SUCCESS).or_else(|e| {
        if let Error::Io(io::ErrorKind::WouldBlock) = e {
            return Ok(SSL_ERROR);
        }
        ssl.last_error = e.clone();
        Err(e)
    })
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
pub extern "C" fn SSL_write_early_data(
    ssl_ptr: *mut SSL,
    buf_ptr: *const c_uchar,
    buf_len: c_int,
    written_len_ptr: *mut size_t,
) -> c_int {
    check_inner_result!(
        inner_ssl_write_early_data(ssl_ptr, buf_ptr, buf_len, written_len_ptr),
        SSL_FAILURE
    )
}

fn inner_ssl_write_early_data(
    ssl_ptr: *mut SSL,
    buf_ptr: *const c_uchar,
    buf_len: c_int,
    written_len_ptr: *mut size_t,
) -> InnerResult<c_int> {
    if buf_ptr.is_null() || buf_len < 0 {
        return Err(Error::BadFuncArg);
    }
    if written_len_ptr.is_null() {
        return Err(Error::NullPointer);
    }
    let _ = inner_ssl_connect(ssl_ptr)?; // creates a client session
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let buf = unsafe { slice::from_raw_parts(buf_ptr, buf_len as usize) };
    match ssl.ssl_write_early_data(buf) {
        Ok(count) => {
            let written_size: size_t = count;
            unsafe { ptr::write(written_len_ptr, written_size) };
            Ok(SSL_SUCCESS)
        }
        Err(e) => {
            if let Error::Io(io::ErrorKind::WouldBlock) = e {
                return Ok(SSL_ERROR);
            }
            ssl.last_error = e.clone();
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
pub extern "C" fn SSL_get_early_data_status(ssl_ptr: *mut SSL) -> c_int {
    check_inner_result!(inner_ssl_get_early_data_status(ssl_ptr), SSL_FAILURE)
}

fn inner_ssl_get_early_data_status(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let session = ssl.session.as_mut().ok_or(Error::BadFuncArg)?;

    match session {
        Connection::Client(s) => {
            if s.is_early_data_accepted() {
                Ok(2)
            } else {
                Ok(1)
            }
        }
        _ => Ok(1),
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
pub extern "C" fn SSL_shutdown(ssl_ptr: *mut SSL) -> c_int {
    check_inner_result!(inner_ssl_shutdown(ssl_ptr), SSL_FAILURE)
}

fn inner_ssl_shutdown(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let session = ssl.session.as_mut().ok_or(Error::BadFuncArg)?;
    session.send_close_notify();
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
pub extern "C" fn SSL_get_version(ssl_ptr: *mut SSL) -> *const c_char {
    check_inner_result!(inner_ssl_get_version(ssl_ptr), ptr::null())
}

fn inner_ssl_get_version(ssl_ptr: *mut SSL) -> InnerResult<*const c_char> {
    let ssl = sanitize_ptr_for_mut_ref(ssl_ptr)?;
    let session = ssl.session.as_ref().ok_or(Error::BadFuncArg)?;
    let version = session.protocol_version().ok_or(Error::BadFuncArg)?;
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
pub extern "C" fn SSL_CTX_free(ctx_ptr: *mut SSL_CTX_ARC) {
    let _ = check_inner_result!(inner_ssl_ctx_free(ctx_ptr), SSL_FAILURE);
}

fn inner_ssl_ctx_free(ctx_ptr: *mut SSL_CTX_ARC) -> InnerResult<c_int> {
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
pub extern "C" fn SSL_free(ssl_ptr: *mut SSL) {
    let _ = check_inner_result!(inner_ssl_free(ssl_ptr), SSL_FAILURE);
}

fn inner_ssl_free(ssl_ptr: *mut SSL) -> InnerResult<c_int> {
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

    pub fn get_context_mut(ctx: &mut ssl::SSL_CTX_ARC) -> &mut ssl::SSL_CTX {
        Arc::make_mut(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libssl::err::ERR_clear_error;
    use crate::libssl::x509::*;
    use libc::{c_long, c_ulong};
    use std::{ptr, str, thread};

    const CONST_CA_FILE: &'static [u8] = b"tests/ca.cert\0";
    const CONST_INTER_CA_FILE: &'static [u8] = b"tests/inter.cert\0";
    const CONST_SERVER_CERT_CHAIN_FILE: &'static [u8] = b"tests/end.fullchain\0";
    const CONST_SERVER_CERT_FILE: &'static [u8] = b"tests/end.cert\0";
    const CONST_SERVER_KEY_FILE: &'static [u8] = b"tests/end.key\0";
    const CONST_CLIENT_CERT_FILE: &'static [u8] = b"tests/client.fullchain\0";
    const CONST_CLIENT_KEY_FILE: &'static [u8] = b"tests/client.key\0";
    const CONST_SERVER_ADDR: &'static str = "127.0.0.1";

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
            let _ = SSL_CTX_set_session_cache_mode(ctx, SslSessionCacheModes::Both as c_long);
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
                SSL_CTX_use_PrivateKey_file(
                    ctx,
                    CONST_CLIENT_KEY_FILE.as_ptr() as *const c_char,
                    0,
                ),
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
                SSL_CTX_use_PrivateKey_file(
                    ctx,
                    CONST_SERVER_KEY_FILE.as_ptr() as *const c_char,
                    0,
                ),
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
            (&TlsVersion::Tlsv12, false) => TLSv1_2_client_method(),
            (&TlsVersion::Tlsv13, false) => TLSv1_3_client_method(),
            (&TlsVersion::Both, false) => TLS_client_method(),
            (&TlsVersion::Tlsv12, true) => TLSv1_2_server_method(),
            (&TlsVersion::Tlsv13, true) => TLSv1_3_server_method(),
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
                &TlsVersion::Tlsv12 => {
                    assert_eq!(cipher_name, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
                }
                &TlsVersion::Tlsv13 => assert_eq!(cipher_name, "TLS13_AES_256_GCM_SHA384"),
                _ => (),
            };

            let cipher_version_ptr = SSL_get_cipher_version(ssl);
            let cipher_version =
                unsafe { ffi::CStr::from_ptr(cipher_version_ptr).to_str().unwrap() };
            match version {
                &TlsVersion::Tlsv12 => assert_eq!(cipher_version, "TLS1.2"),
                &TlsVersion::Tlsv13 => assert_eq!(cipher_version, "TLS1.3"),
                _ => (),
            };

            let ssl_version_ptr = SSL_get_version(ssl);
            let ssl_version = unsafe { ffi::CStr::from_ptr(ssl_version_ptr).to_str().unwrap() };
            match version {
                &TlsVersion::Tlsv12 => assert_eq!(ssl_version, "TLS1.2"),
                &TlsVersion::Tlsv13 => assert_eq!(ssl_version, "TLS1.3"),
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
        assert_eq!(true, sock.set_nonblocking(true).is_ok());
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
    fn ssl_ctx_is_thread_safe() {
        let ctx_ptr = SSL_CTX_new(TLS_client_method());
        let ctx = sanitize_ptr_for_mut_ref(ctx_ptr);
        let _ = &ctx as &dyn Send;
        let _ = &ctx as &dyn Sync;
        SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn ssl_is_thread_safe() {
        let ctx_ptr = SSL_CTX_new(TLS_client_method());
        let ssl_ptr = SSL_new(ctx_ptr);
        let ssl = sanitize_ptr_for_mut_ref(ssl_ptr);
        let _ = &ssl as &dyn Send;
        let _ = &ssl as &dyn Sync;
        SSL_free(ssl_ptr);
        SSL_CTX_free(ctx_ptr);
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
                b"tests/root_store/curl-root-ca.crt\0".as_ptr() as *const c_char,
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
            SSL_CTX_use_PrivateKey_file(
                ctx_ptr,
                CONST_SERVER_KEY_FILE.as_ptr() as *const c_char,
                0
            )
        );
        assert_eq!(SSL_SUCCESS, SSL_CTX_check_private_key(ctx_ptr));
        SSL_CTX_free(ctx_ptr);
    }

    #[test]
    fn verify_key_and_certificate_1() {
        let ctx_ptr = SSL_CTX_new(TLS_server_method());
        assert_eq!(
            SSL_SUCCESS,
            SSL_CTX_use_PrivateKey_file(
                ctx_ptr,
                CONST_SERVER_KEY_FILE.as_ptr() as *const c_char,
                0
            )
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
        use crate::libcrypto::{bio, evp, pem};

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
        let certificate_bytes = include_bytes!("../../tests/end.cert.der");
        let private_key_bytes = include_bytes!("../../tests/end.key.der");
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
        let certificate_bytes = include_bytes!("../../tests/end.cert.der");
        let private_key_bytes = include_bytes!("../../tests/end.key.der");
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
        assert_eq!((), SSL_load_error_strings());
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
        assert_eq!(
            SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Both as c_long
        );
        // Default cache size is SSL_SESSION_CACHE_MAX_SIZE_DEFAULT
        assert_eq!(
            SSL_CTX_sess_get_cache_size(ctx_ptr),
            SSL_SESSION_CACHE_MAX_SIZE_DEFAULT as c_long
        );
        // When cache mode is both, set the cache size to 100
        assert_eq!(
            SSL_CTX_sess_set_cache_size(ctx_ptr, 100),
            SSL_SESSION_CACHE_MAX_SIZE_DEFAULT as c_long
        );
        // Turn off session cache
        assert_eq!(
            SSL_CTX_set_session_cache_mode(ctx_ptr, SslSessionCacheModes::Off as c_long),
            SslSessionCacheModes::Both as c_long
        );
        // Now the cache mode is Off
        assert_eq!(
            SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Off as c_long
        );
        // The cache size to 100
        assert_eq!(SSL_CTX_sess_get_cache_size(ctx_ptr), 100);
        // When cache mode is Off, set the cache size to 200
        assert_eq!(SSL_CTX_sess_set_cache_size(ctx_ptr, 200), 100);
        // Set the cache mode to Client
        assert_eq!(
            SSL_CTX_set_session_cache_mode(ctx_ptr, SslSessionCacheModes::Client as c_long),
            SslSessionCacheModes::Off as c_long
        );
        assert_eq!(
            SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Client as c_long
        );
        // The cache size to 100
        assert_eq!(SSL_CTX_sess_get_cache_size(ctx_ptr), 200);
        // When cache mode is Client, set the cache size to 300
        assert_eq!(SSL_CTX_sess_set_cache_size(ctx_ptr, 300), 200);
        // Set the cache mode to Server
        assert_eq!(
            SSL_CTX_set_session_cache_mode(ctx_ptr, SslSessionCacheModes::Server as c_long),
            SslSessionCacheModes::Client as c_long
        );
        // Now the cache mode is Server
        assert_eq!(
            SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Server as c_long
        );
        // The cache size to 300
        assert_eq!(SSL_CTX_sess_get_cache_size(ctx_ptr), 300);
        // When cache mode is Server, set the cache size to 400
        assert_eq!(SSL_CTX_sess_set_cache_size(ctx_ptr, 400), 300);
        assert_eq!(
            SSL_CTX_set_session_cache_mode(ctx_ptr, SslSessionCacheModes::Both as c_long),
            SslSessionCacheModes::Server as c_long
        );
        assert_eq!(
            SSL_CTX_get_session_cache_mode(ctx_ptr),
            SslSessionCacheModes::Both as c_long
        );
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
}
