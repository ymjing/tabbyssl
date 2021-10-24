/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 */

//! # Synopsis
//! This sub-module implements the error-handling APIs of OpenSSL. TabbySSL
//! follows the same design as OpenSSL and uses a thread-local error queue. A
//! failed API call typically returns -1/0 and pushes an error code into the
//! error queue. The error code can be acquired by calling `ERR_get_error` or
//! `SSL_get_error`.
//!
//! TabbySSL always use a 32-bit unsigned integer to represent error codes.
//!
//! ```text
//!  7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     source    |     unused    |     errno     |   sub errno   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The highest 8 bits represent the source of the error. 0x1: the error comes
//! from TabbySSL itself. For example, a NULL or malformed SSL_CTX pointer is
//! used. 0x2: the error comes from system I/O. For example, a certificate file
//! is not found. 0x3: the error is TLS specific. For example, the remote server
//! does not have a valid certifcate. The lowest 16 bits represent the specific
//! error, including 8 bites error number and 8 bits optional sub error number.
//! For a human-readable decription of an ErrorCode, call
//! `ERR_reason_error_string`. An non-exhaustive list of error codes is as
//! follows.
//!
//! ```c
//!   TABBY_ERROR_NONE = 0,
//!   TABBY_ERROR_ZERO_RETURN = 1,
//!   TABBY_ERROR_WANT_READ = 2,
//!   TABBY_ERROR_WANT_WRITE = 3,
//!   TABBY_ERROR_WANT_CONNECT = 7,
//!   TABBY_ERROR_WANT_ACCEPT = 8,
//!   TABBY_ERROR_SYSCALL = 5,
//!   TABBY_ERROR_SSL = 0x55,
//!   TABBY_ERROR_NULL_POINTER = 0xe0,
//!   TABBY_ERROR_MALFORMED_OBJECT = 0xe1,
//!   TABBY_ERROR_BAD_FUNC_ARG = 0xe2,
//!   TABBY_ERROR_PANIC = 0xe3,
//!   TABBY_ERROR_LOCK = 0xe4,
//!   IO_ERROR_NOT_FOUND = 0x0200_0001,
//!   IO_ERROR_PERMISSION_DENIED = 0x0200_0002,
//!   IO_ERROR_CONNECTION_REFUSED = 0x0200_0003,
//!   IO_ERROR_CONNECTION_RESET = 0x0200_0004,
//!   IO_ERROR_CONNECTION_ABORTED = 0x0200_0005,
//!   IO_ERROR_NOT_CONNECTED = 0x0200_0006,
//!   IO_ERROR_ADDR_IN_USE = 0x0200_0007,
//!   IO_ERROR_ADDR_NOT_AVAILABLE = 0x0200_0008,
//!   IO_ERROR_BROKEN_PIPE = 0x0200_0009,
//!   IO_ERROR_ALREADY_EXISTS = 0x0200_000a,
//!   IO_ERROR_WOULD_BLOCK = 0x0200_000b,
//!   IO_ERROR_INVALID_INPUT = 0x0200_000c,
//!   IO_ERROR_INVALID_DATA = 0x0200_000d,
//!   IO_ERROR_TIMED_OUT = 0x0200_000e,
//!   IO_ERROR_WRITE_ZERO = 0x0200_000f,
//!   IO_ERROR_INTERRUPTED = 0x0200_0010,
//!   IO_ERROR_OTHER = 0x0200_0011,
//!   IO_ERROR_UNEXPECTED_EOF = 0x0200_0012,
//!   TLS_ERROR_INAPPROPRIATE_MESSAGE = 0x0300_0100,
//!   TLS_ERROR_INAPPROPRIATE_HANDSHAKE_MESSAGE = 0x0300_0200,
//!   TLS_ERROR_CORRUPT_MESSAGE = 0x0300_0300,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD = 0x0300_0400,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_ALERT = 0x0300_0401,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_CHANGE_CIPHER_SPEC = 0x0300_0402,
//!   TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_HANDSHAKE = 0x0300_0403,
//!   TLS_ERROR_NO_CERTIFICATES_PRESENTED = 0x0300_0500,
//!   TLS_ERROR_DECRYPT_ERROR = 0x0300_0600,
//!   TLS_ERROR_PEER_INCOMPATIBLE_ERROR = 0x0300_0700,
//!   TLS_ERROR_PEER_MISBEHAVED_ERROR = 0x0300_0800,
//!   TLS_ERROR_ALERT_RECEIVED_CLOSE_NOTIFY = 0x0300_0901,
//!   TLS_ERROR_ALERT_RECEIVED_UNEXPECTED_MESSAGE = 0x0300_0902,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_RECORD_MAC = 0x0300_0903,
//!   TLS_ERROR_ALERT_RECEIVED_DECRYPTION_FAILED = 0x0300_0904,
//!   TLS_ERROR_ALERT_RECEIVED_RECORD_OVERFLOW = 0x0300_0905,
//!   TLS_ERROR_ALERT_RECEIVED_DECOMPRESSION_FAILURE = 0x0300_0906,
//!   TLS_ERROR_ALERT_RECEIVED_HANDSHAKE_FAILURE = 0x0300_0907,
//!   TLS_ERROR_ALERT_RECEIVED_NO_CERTIFICATE = 0x0300_0908,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE = 0x0300_0909,
//!   TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_CERTIFICATE = 0x0300_090a,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REVOKED = 0x0300_090b,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_EXPIRED = 0x0300_090c,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNKNOWN = 0x0300_090d,
//!   TLS_ERROR_ALERT_RECEIVED_ILLEGAL_PARAMETER = 0x0300_090e,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN_CA = 0x0300_090f,
//!   TLS_ERROR_ALERT_RECEIVED_ACCESS_DENIED = 0x0300_0910,
//!   TLS_ERROR_ALERT_RECEIVED_DECODE_ERROR = 0x0300_0911,
//!   TLS_ERROR_ALERT_RECEIVED_DECRYPT_ERROR = 0x0300_0912,
//!   TLS_ERROR_ALERT_RECEIVED_EXPORT_RESTRICTION = 0x0300_0913,
//!   TLS_ERROR_ALERT_RECEIVED_PROTOCOL_VERSION = 0x0300_0914,
//!   TLS_ERROR_ALERT_RECEIVED_INSUFFICIENT_SECURITY = 0x0300_0915,
//!   TLS_ERROR_ALERT_RECEIVED_INTERNAL_ERROR = 0x0300_0916,
//!   TLS_ERROR_ALERT_RECEIVED_INAPPROPRIATE_FALLBACK = 0x0300_0917,
//!   TLS_ERROR_ALERT_RECEIVED_USER_CANCELED = 0x0300_0918,
//!   TLS_ERROR_ALERT_RECEIVED_NO_RENEGOTIATION = 0x0300_0919,
//!   TLS_ERROR_ALERT_RECEIVED_MISSING_EXTENSION = 0x0300_091a,
//!   TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_EXTENSION = 0x0300_091b,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNOBTAINABLE = 0x0300_091c,
//!   TLS_ERROR_ALERT_RECEIVED_UNRECOGNISED_NAME = 0x0300_091d,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_STATUS_RESPONSE = 0x0300_091e,
//!   TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_HASH_VALUE = 0x0300_091f,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN_PSK_IDENTITY = 0x0300_0920,
//!   TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REQUIRED = 0x0300_0921,
//!   TLS_ERROR_ALERT_RECEIVED_NO_APPLICATION_PROTOCOL = 0x0300_0922,
//!   TLS_ERROR_ALERT_RECEIVED_UNKNOWN = 0x0300_09ff,
//!   TLS_ERROR_WEBPKI_BAD_DER = 0x0300_0a01,
//!   TLS_ERROR_WEBPKI_BAD_DER_TIME = 0x0300_0a02,
//!   TLS_ERROR_WEBPKI_CA_USED_AS_END_ENTITY = 0x0300_0a03,
//!   TLS_ERROR_WEBPKI_CERT_EXPIRED = 0x0300_0a04,
//!   TLS_ERROR_WEBPKI_CERT_NOT_VALID_FOR_NAME = 0x0300_0a05,
//!   TLS_ERROR_WEBPKI_CERT_NOT_VALID_YET = 0x0300_0a06,
//!   TLS_ERROR_WEBPKI_END_ENTITY_USED_AS_CA = 0x0300_0a07,
//!   TLS_ERROR_WEBPKI_EXTENSION_VALUE_INVALID = 0x0300_0a08,
//!   TLS_ERROR_WEBPKI_INVALID_CERT_VALIDITY = 0x0300_0a09,
//!   TLS_ERROR_WEBPKI_INVALID_SIGNATURE_FOR_PUBLIC_KEY = 0x0300_0a0a,
//!   TLS_ERROR_WEBPKI_NAME_CONSTRAINT_VIOLATION = 0x0300_0a0b,
//!   TLS_ERROR_WEBPKI_PATH_LEN_CONSTRAINT_VIOLATED = 0x0300_0a0c,
//!   TLS_ERROR_WEBPKI_SIGNATURE_ALGORITHM_MISMATCH = 0x0300_0a0d,
//!   TLS_ERROR_WEBPKI_REQUIRED_EKU_NOT_FOUND = 0x0300_0a0e,
//!   TLS_ERROR_WEBPKI_UNKNOWN_ISSUER = 0x0300_0a0f,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_CERT_VERSION = 0x0300_0a10,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_CRITICAL_EXTENSION = 0x0300_0a11,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_PUBLIC_KEY = 0x0300_0a12,
//!   TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM = 0x0300_0a13,
//!   TLS_ERROR_INVALID_SCT = 0x0300_0b00,
//!   TLS_ERROR_GENERAL = 0x0300_0c00,
//!   TLS_ERROR_FAILED_TO_GET_CURRENT_TIME = 0x0300_0d00,
//!   TLS_ERROR_INVALID_DNS_NAME = 0x0300_0e00,
//!   TLS_ERROR_HANDSHAKE_NOT_COMPLETE = 0x0300_0f00,
//!   TLS_ERROR_PEER_SENT_OVERSIZED_RECORD = 0x0300_1000,
//!   UNDEFINED_ERROR = 0x0eeeeeee,
//! ```

use libc::{self, c_char, c_ulong, size_t};
use rustls;
use std::{error, fmt, io, slice};

use std::cell::RefCell;
use std::collections::VecDeque;
thread_local! {
    static ERROR_QUEUE: RefCell<VecDeque<Error>> = RefCell::new(VecDeque::new());
}

#[doc(hidden)]
#[repr(C)]
#[derive(PartialEq, Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum OpensslError {
    None,
    ZeroReturn,
    WantRead,
    WantWrite,
    WantConnect,
    WantAccept,
    Syscall,
    Ssl,
    NullPointer,
    MalformedObject,
    BadFuncArg,
    Panic,
    Lock,
}

#[doc(hidden)]
impl fmt::Display for OpensslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpensslError: {:?}", self)
    }
}

#[doc(hidden)]
impl error::Error for OpensslError {
    fn description(&self) -> &str {
        match *self {
            OpensslError::None => "SSL_ERROR_NONE",
            OpensslError::ZeroReturn => "SSL_ERROR_ZERO_RETURN",
            OpensslError::WantRead => "SSL_ERROR_WANT_READ",
            OpensslError::WantWrite => "SSL_ERROR_WANT_WRITE",
            OpensslError::WantConnect => "SSL_ERROR_WANT_CONNECT",
            OpensslError::WantAccept => "SSL_ERROR_WANT_ACCEPT",
            OpensslError::Syscall => "SSL_ERROR_SYSCALL",
            OpensslError::Ssl => "SSL_ERROR_SSL",
            OpensslError::NullPointer => "TABBY_ERROR_NULL_POINTER",
            OpensslError::MalformedObject => "TABBY_ERROR_MALFORMED_OBJECT",
            OpensslError::BadFuncArg => "TABBY_ERROR_BAD_FUNCTION_ARGUMENT",
            OpensslError::Panic => "TABBY_ERROR_PANIC_AT_FFI",
            OpensslError::Lock => "TABBY_ERROR_LOCK_FAILED",
        }
    }
}

#[cfg_attr(feature = "error_strings", derive(Debug))]
#[doc(hidden)]
pub(crate) enum ErrorKind {
    Io(io::Error),
    Tls(rustls::Error),
    Builtin(OpensslError),
}

#[doc(hidden)]
impl From<io::Error> for ErrorKind {
    fn from(err: io::Error) -> ErrorKind {
        ErrorKind::Io(err)
    }
}

#[doc(hidden)]
impl From<rustls::Error> for ErrorKind {
    fn from(err: rustls::Error) -> ErrorKind {
        ErrorKind::Tls(err)
    }
}

#[doc(hidden)]
impl From<OpensslError> for ErrorKind {
    fn from(err: OpensslError) -> ErrorKind {
        ErrorKind::Builtin(err)
    }
}

#[cfg_attr(feature = "error_strings", derive(Debug))]
#[doc(hidden)]
pub(crate) struct Error {
    pub error: ErrorKind,
    call_site: &'static str,
}

impl Error {
    pub fn new(error: ErrorKind, call_site: &'static str) -> Error {
        Error { error, call_site }
    }
}

#[doc(hidden)]
pub(crate) type InnerResult<T> = Result<T, Error>;

#[doc(hidden)]
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(feature = "error_strings", derive(EnumToU8, Debug))]
pub enum ErrorCode {
    // OpenSSL error codes
    OpensslErrorNone = 0,
    OpensslErrorZeroReturn = 1,
    OpensslErrorWantRead = 2,
    OpensslErrorWantWrite = 3,
    OpensslErrorWantConnect = 7,
    OpensslErrorWantAccept = 8,
    OpensslErrorSyscall = 5,
    OpensslErrorSsl = 0x55,
    OpensslNullPointer = 0xe0,
    OpensslErrorMalformedObject = 0xe1,
    OpensslErrorBadFuncArg = 0xe2,
    OpensslErrorPanic = 0xe3,
    OpensslErrorLock = 0xe4,
    // Rust IO ErrorKind codes
    IoErrorNotFound = 0x0200_0001,
    IoErrorPermissionDenied = 0x0200_0002,
    IoErrorConnectionRefused = 0x0200_0003,
    IoErrorConnectionReset = 0x0200_0004,
    IoErrorConnectionAborted = 0x0200_0005,
    IoErrorNotConnected = 0x0200_0006,
    IoErrorAddrInUse = 0x0200_0007,
    IoErrorAddrNotAvailable = 0x0200_0008,
    IoErrorBrokenPipe = 0x0200_0009,
    IoErrorAlreadyExists = 0x0200_000a,
    IoErrorWouldBlock = 0x0200_000b,
    IoErrorInvalidInput = 0x0200_000c,
    IoErrorInvalidData = 0x0200_000d,
    IoErrorTimedOut = 0x0200_000e,
    IoErrorWriteZero = 0x0200_000f,
    IoErrorInterrupted = 0x0200_0010,
    IoErrorOther = 0x0200_0011,
    IoErrorUnexpectedEof = 0x0200_0012,
    // TLS error codes
    InappropriateMessage = 0x0300_0100,
    InappropriateHandshakeMessage = 0x0300_0200,
    CorruptMessage = 0x0300_0300,
    CorruptMessagePayload = 0x0300_0400,
    CorruptMessagePayloadAlert = 0x0300_0401,
    CorruptMessagePayloadChangeCipherSpec = 0x0300_0402,
    CorruptMessagePayloadHandshake = 0x0300_0403,
    NoCertificatesPresented = 0x0300_0500,
    DecryptError = 0x0300_0600,
    PeerIncompatibleError = 0x0300_0700,
    PeerMisbehavedError = 0x0300_0800,
    AlertReceivedCloseNotify = 0x0300_0901,
    AlertReceivedUnexpectedMessage = 0x0300_0902,
    AlertReceivedBadRecordMac = 0x0300_0903,
    AlertReceivedDecryptionFailed = 0x0300_0904,
    AlertReceivedRecordOverflow = 0x0300_0905,
    AlertReceivedDecompressionFailure = 0x0300_0906,
    AlertReceivedHandshakeFailure = 0x0300_0907,
    AlertReceivedNoCertificate = 0x0300_0908,
    AlertReceivedBadCertificate = 0x0300_0909,
    AlertReceivedUnsupportedCertificate = 0x0300_090a,
    AlertReceivedCertificateRevoked = 0x0300_090b,
    AlertReceivedCertificateExpired = 0x0300_090c,
    AlertReceivedCertificateUnknown = 0x0300_090d,
    AlertReceivedIllegalParameter = 0x0300_090e,
    AlertReceivedUnknownCA = 0x0300_090f,
    AlertReceivedAccessDenied = 0x0300_0910,
    AlertReceivedDecodeError = 0x0300_0911,
    AlertReceivedDecryptError = 0x0300_0912,
    AlertReceivedExportRestriction = 0x0300_0913,
    AlertReceivedProtocolVersion = 0x0300_0914,
    AlertReceivedInsufficientSecurity = 0x0300_0915,
    AlertReceivedInternalError = 0x0300_0916,
    AlertReceivedInappropriateFallback = 0x0300_0917,
    AlertReceivedUserCanceled = 0x0300_0918,
    AlertReceivedNoRenegotiation = 0x0300_0919,
    AlertReceivedMissingExtension = 0x0300_091a,
    AlertReceivedUnsupportedExtension = 0x0300_091b,
    AlertReceivedCertificateUnobtainable = 0x0300_091c,
    AlertReceivedUnrecognisedName = 0x0300_091d,
    AlertReceivedBadCertificateStatusResponse = 0x0300_091e,
    AlertReceivedBadCertificateHashValue = 0x0300_091f,
    AlertReceivedUnknownPSKIdentity = 0x0300_0920,
    AlertReceivedCertificateRequired = 0x0300_0921,
    AlertReceivedNoApplicationProtocol = 0x0300_0922,
    AlertReceivedUnknown = 0x0300_09ff,
    InvalidSCT = 0x0300_0b00,
    General = 0x0300_0c00,
    InvalidDNSName = 0x0300_0e00,
    HandshakeNotComplete = 0x0300_0f00,
    PeerSentOversizedRecord = 0x0300_1000,
    NoApplicationProtocol = 0x0300_1100,
    EncryptError = 0x0300_1200,
    UnsupportedNameType = 0x0300_1300,
    InvalidCertificateEncoding = 0x0300_1400,
    InvalidCertificateSignatureType = 0x0300_1500,
    InvalidCertificateSignature = 0x0300_1600,
    InvalidCertificateData = 0x0300_1700,
    FailedToGetCurrentTime = 0x0300_1800,
    FailedToGetRandomBytes = 0x0300_1900,
    BadMaxFragmentSize = 0x0300_1a00,
    UndefinedError = 0x0eee_eeee,
}

#[doc(hidden)]
impl ErrorCode {
    #[cfg(feature = "error_strings")]
    pub fn as_u8_slice(self) -> &'static [u8] {
        self.enum_to_u8()
    }

    #[cfg(not(feature = "error_strings"))]
    pub fn as_u8_slice(&self) -> &'static [u8] {
        b"Error string not built-in\0"
    }
}

#[doc(hidden)]
impl Default for ErrorCode {
    fn default() -> ErrorCode {
        ErrorCode::OpensslErrorNone
    }
}

#[doc(hidden)]
impl From<u32> for ErrorCode {
    fn from(e: u32) -> ErrorCode {
        match e {
            0 => ErrorCode::OpensslErrorNone,
            1 => ErrorCode::OpensslErrorZeroReturn,
            2 => ErrorCode::OpensslErrorWantRead,
            3 => ErrorCode::OpensslErrorWantWrite,
            7 => ErrorCode::OpensslErrorWantConnect,
            8 => ErrorCode::OpensslErrorWantAccept,
            5 => ErrorCode::OpensslErrorSyscall,
            0x55 => ErrorCode::OpensslErrorSsl,
            0xe0 => ErrorCode::OpensslNullPointer,
            0xe1 => ErrorCode::OpensslErrorMalformedObject,
            0xe2 => ErrorCode::OpensslErrorBadFuncArg,
            0xe3 => ErrorCode::OpensslErrorPanic,
            0xe4 => ErrorCode::OpensslErrorLock,
            0x0200_0001 => ErrorCode::IoErrorNotFound,
            0x0200_0002 => ErrorCode::IoErrorPermissionDenied,
            0x0200_0003 => ErrorCode::IoErrorConnectionRefused,
            0x0200_0004 => ErrorCode::IoErrorConnectionReset,
            0x0200_0005 => ErrorCode::IoErrorConnectionAborted,
            0x0200_0006 => ErrorCode::IoErrorNotConnected,
            0x0200_0007 => ErrorCode::IoErrorAddrInUse,
            0x0200_0008 => ErrorCode::IoErrorAddrNotAvailable,
            0x0200_0009 => ErrorCode::IoErrorBrokenPipe,
            0x0200_000a => ErrorCode::IoErrorAlreadyExists,
            0x0200_000b => ErrorCode::IoErrorWouldBlock,
            0x0200_000c => ErrorCode::IoErrorInvalidInput,
            0x0200_000d => ErrorCode::IoErrorInvalidData,
            0x0200_000e => ErrorCode::IoErrorTimedOut,
            0x0200_000f => ErrorCode::IoErrorWriteZero,
            0x0200_0010 => ErrorCode::IoErrorInterrupted,
            0x0200_0011 => ErrorCode::IoErrorOther,
            0x0200_0012 => ErrorCode::IoErrorUnexpectedEof,
            0x0300_0100 => ErrorCode::InappropriateMessage,
            0x0300_0200 => ErrorCode::InappropriateHandshakeMessage,
            0x0300_0300 => ErrorCode::CorruptMessage,
            0x0300_0400 => ErrorCode::CorruptMessagePayload,
            0x0300_0401 => ErrorCode::CorruptMessagePayloadAlert,
            0x0300_0402 => ErrorCode::CorruptMessagePayloadChangeCipherSpec,
            0x0300_0403 => ErrorCode::CorruptMessagePayloadHandshake,
            0x0300_0500 => ErrorCode::NoCertificatesPresented,
            0x0300_0600 => ErrorCode::DecryptError,
            0x0300_0700 => ErrorCode::PeerIncompatibleError,
            0x0300_0800 => ErrorCode::PeerMisbehavedError,
            0x0300_0901 => ErrorCode::AlertReceivedCloseNotify,
            0x0300_0902 => ErrorCode::AlertReceivedUnexpectedMessage,
            0x0300_0903 => ErrorCode::AlertReceivedBadRecordMac,
            0x0300_0904 => ErrorCode::AlertReceivedDecryptionFailed,
            0x0300_0905 => ErrorCode::AlertReceivedRecordOverflow,
            0x0300_0906 => ErrorCode::AlertReceivedDecompressionFailure,
            0x0300_0907 => ErrorCode::AlertReceivedHandshakeFailure,
            0x0300_0908 => ErrorCode::AlertReceivedNoCertificate,
            0x0300_0909 => ErrorCode::AlertReceivedBadCertificate,
            0x0300_090a => ErrorCode::AlertReceivedUnsupportedCertificate,
            0x0300_090b => ErrorCode::AlertReceivedCertificateRevoked,
            0x0300_090c => ErrorCode::AlertReceivedCertificateExpired,
            0x0300_090d => ErrorCode::AlertReceivedCertificateUnknown,
            0x0300_090e => ErrorCode::AlertReceivedIllegalParameter,
            0x0300_090f => ErrorCode::AlertReceivedUnknownCA,
            0x0300_0910 => ErrorCode::AlertReceivedAccessDenied,
            0x0300_0911 => ErrorCode::AlertReceivedDecodeError,
            0x0300_0912 => ErrorCode::AlertReceivedDecryptError,
            0x0300_0913 => ErrorCode::AlertReceivedExportRestriction,
            0x0300_0914 => ErrorCode::AlertReceivedProtocolVersion,
            0x0300_0915 => ErrorCode::AlertReceivedInsufficientSecurity,
            0x0300_0916 => ErrorCode::AlertReceivedInternalError,
            0x0300_0917 => ErrorCode::AlertReceivedInappropriateFallback,
            0x0300_0918 => ErrorCode::AlertReceivedUserCanceled,
            0x0300_0919 => ErrorCode::AlertReceivedNoRenegotiation,
            0x0300_091a => ErrorCode::AlertReceivedMissingExtension,
            0x0300_091b => ErrorCode::AlertReceivedUnsupportedExtension,
            0x0300_091c => ErrorCode::AlertReceivedCertificateUnobtainable,
            0x0300_091d => ErrorCode::AlertReceivedUnrecognisedName,
            0x0300_091e => ErrorCode::AlertReceivedBadCertificateStatusResponse,
            0x0300_091f => ErrorCode::AlertReceivedBadCertificateHashValue,
            0x0300_0920 => ErrorCode::AlertReceivedUnknownPSKIdentity,
            0x0300_0921 => ErrorCode::AlertReceivedCertificateRequired,
            0x0300_0922 => ErrorCode::AlertReceivedNoApplicationProtocol,
            0x0300_09ff => ErrorCode::AlertReceivedUnknown,
            0x0300_0b00 => ErrorCode::InvalidSCT,
            0x0300_0c00 => ErrorCode::General,
            0x0300_0d00 => ErrorCode::FailedToGetCurrentTime,
            0x0300_0e00 => ErrorCode::InvalidDNSName,
            0x0300_0f00 => ErrorCode::HandshakeNotComplete,
            0x0300_1000 => ErrorCode::PeerSentOversizedRecord,
            0x0300_1100 => ErrorCode::NoApplicationProtocol,
            0x0300_1200 => ErrorCode::EncryptError,
            0x0300_1300 => ErrorCode::UnsupportedNameType,
            0x0300_1400 => ErrorCode::InvalidCertificateEncoding,
            0x0300_1500 => ErrorCode::InvalidCertificateSignatureType,
            0x0300_1600 => ErrorCode::InvalidCertificateSignature,
            0x0300_1700 => ErrorCode::InvalidCertificateData,
            0x0300_1800 => ErrorCode::FailedToGetCurrentTime,
            0x0300_1900 => ErrorCode::FailedToGetRandomBytes,
            0x0300_1a00 => ErrorCode::BadMaxFragmentSize,
            _ => ErrorCode::UndefinedError,
        }
    }
}

#[doc(hidden)]
impl From<u64> for ErrorCode {
    fn from(e: u64) -> ErrorCode {
        ErrorCode::from(e as u32)
    }
}

#[doc(hidden)]
#[allow(unused_variables)]
#[rustfmt::skip]
impl<'a> From<&'a Error> for ErrorCode {
    fn from(e: &'a Error) -> ErrorCode {
        use rustls::internal::msgs::enums::{AlertDescription, ContentType};
        use rustls::Error as TlsError;
        match e.error {
            ErrorKind::Builtin(ref e) => match *e {
                OpensslError::None => ErrorCode::OpensslErrorNone,
                OpensslError::ZeroReturn => ErrorCode::OpensslErrorZeroReturn,
                OpensslError::WantRead => ErrorCode::OpensslErrorWantRead,
                OpensslError::WantWrite => ErrorCode::OpensslErrorWantWrite,
                OpensslError::WantConnect => ErrorCode::OpensslErrorWantConnect,
                OpensslError::WantAccept => ErrorCode::OpensslErrorWantAccept,
                OpensslError::Syscall => ErrorCode::OpensslErrorSyscall,
                OpensslError::Ssl => ErrorCode::OpensslErrorSsl,
                OpensslError::NullPointer => ErrorCode::OpensslNullPointer,
                OpensslError::MalformedObject => ErrorCode::OpensslErrorMalformedObject,
                OpensslError::BadFuncArg => ErrorCode::OpensslErrorBadFuncArg,
                OpensslError::Panic => ErrorCode::OpensslErrorPanic,
                OpensslError::Lock => ErrorCode::OpensslErrorLock,
            },
            ErrorKind::Io(ref e) => match e.kind() {
                io::ErrorKind::NotFound => ErrorCode::IoErrorNotFound,
                io::ErrorKind::PermissionDenied => ErrorCode::IoErrorPermissionDenied,
                io::ErrorKind::ConnectionRefused => ErrorCode::IoErrorConnectionRefused,
                io::ErrorKind::ConnectionReset => ErrorCode::IoErrorConnectionReset,
                io::ErrorKind::ConnectionAborted => ErrorCode::IoErrorConnectionAborted,
                io::ErrorKind::NotConnected => ErrorCode::IoErrorNotConnected,
                io::ErrorKind::AddrInUse => ErrorCode::IoErrorAddrInUse,
                io::ErrorKind::AddrNotAvailable => ErrorCode::IoErrorAddrNotAvailable,
                io::ErrorKind::BrokenPipe => ErrorCode::IoErrorBrokenPipe,
                io::ErrorKind::AlreadyExists => ErrorCode::IoErrorAlreadyExists,
                io::ErrorKind::WouldBlock => ErrorCode::IoErrorWouldBlock,
                io::ErrorKind::InvalidInput => ErrorCode::IoErrorInvalidInput,
                io::ErrorKind::InvalidData => ErrorCode::IoErrorInvalidData,
                io::ErrorKind::TimedOut => ErrorCode::IoErrorTimedOut,
                io::ErrorKind::WriteZero => ErrorCode::IoErrorWriteZero,
                io::ErrorKind::Interrupted => ErrorCode::IoErrorInterrupted,
                io::ErrorKind::Other => ErrorCode::IoErrorOther,
                io::ErrorKind::UnexpectedEof => ErrorCode::IoErrorUnexpectedEof,
                _ => ErrorCode::UndefinedError,
            },
            ErrorKind::Tls(ref e) => match *e {
                TlsError::InappropriateMessage {
                    ref expect_types,
                    ref got_type,
                } => ErrorCode::InappropriateMessage,
                TlsError::InappropriateHandshakeMessage {
                    ref expect_types,
                    ref got_type,
                } => ErrorCode::InappropriateHandshakeMessage,
                TlsError::CorruptMessage => ErrorCode::CorruptMessage,
                TlsError::CorruptMessagePayload(c) => match c {
                    ContentType::Alert => ErrorCode::CorruptMessagePayloadAlert,
                    ContentType::ChangeCipherSpec => ErrorCode::CorruptMessagePayloadChangeCipherSpec,
                    ContentType::Handshake => ErrorCode::CorruptMessagePayloadHandshake,
                    _ => ErrorCode::CorruptMessagePayload,
                },
                TlsError::NoCertificatesPresented => ErrorCode::NoCertificatesPresented,
                TlsError::UnsupportedNameType => ErrorCode::UnsupportedNameType,
                TlsError::DecryptError => ErrorCode::DecryptError,
                TlsError::EncryptError => ErrorCode::EncryptError,
                TlsError::PeerIncompatibleError(_) => ErrorCode::PeerIncompatibleError,
                TlsError::PeerMisbehavedError(_) => ErrorCode::PeerMisbehavedError,
                TlsError::AlertReceived(alert) => match alert {
                    AlertDescription::CloseNotify => ErrorCode::AlertReceivedCloseNotify,
                    AlertDescription::UnexpectedMessage => ErrorCode::AlertReceivedUnexpectedMessage,
                    AlertDescription::BadRecordMac => ErrorCode::AlertReceivedBadRecordMac,
                    AlertDescription::DecryptionFailed => ErrorCode::AlertReceivedDecryptionFailed,
                    AlertDescription::RecordOverflow => ErrorCode::AlertReceivedRecordOverflow,
                    AlertDescription::DecompressionFailure => ErrorCode::AlertReceivedDecompressionFailure,
                    AlertDescription::HandshakeFailure => ErrorCode::AlertReceivedHandshakeFailure,
                    AlertDescription::NoCertificate => ErrorCode::AlertReceivedNoCertificate,
                    AlertDescription::BadCertificate => ErrorCode::AlertReceivedBadCertificate,
                    AlertDescription::UnsupportedCertificate => ErrorCode::AlertReceivedUnsupportedCertificate,
                    AlertDescription::CertificateRevoked => ErrorCode::AlertReceivedCertificateRevoked,
                    AlertDescription::CertificateExpired => ErrorCode::AlertReceivedCertificateExpired,
                    AlertDescription::CertificateUnknown => ErrorCode::AlertReceivedCertificateUnknown,
                    AlertDescription::IllegalParameter => ErrorCode::AlertReceivedIllegalParameter,
                    AlertDescription::UnknownCA => ErrorCode::AlertReceivedUnknownCA,
                    AlertDescription::AccessDenied => ErrorCode::AlertReceivedAccessDenied,
                    AlertDescription::DecodeError => ErrorCode::AlertReceivedDecodeError,
                    AlertDescription::DecryptError => ErrorCode::AlertReceivedDecryptError,
                    AlertDescription::ExportRestriction => ErrorCode::AlertReceivedExportRestriction,
                    AlertDescription::ProtocolVersion => ErrorCode::AlertReceivedProtocolVersion,
                    AlertDescription::InsufficientSecurity => ErrorCode::AlertReceivedInsufficientSecurity,
                    AlertDescription::InternalError => ErrorCode::AlertReceivedInternalError,
                    AlertDescription::InappropriateFallback => ErrorCode::AlertReceivedInappropriateFallback,
                    AlertDescription::UserCanceled => ErrorCode::AlertReceivedUserCanceled,
                    AlertDescription::NoRenegotiation => ErrorCode::AlertReceivedNoRenegotiation,
                    AlertDescription::MissingExtension => ErrorCode::AlertReceivedMissingExtension,
                    AlertDescription::UnsupportedExtension => ErrorCode::AlertReceivedUnsupportedExtension,
                    AlertDescription::CertificateUnobtainable => ErrorCode::AlertReceivedCertificateUnobtainable,
                    AlertDescription::UnrecognisedName => ErrorCode::AlertReceivedUnrecognisedName,
                    AlertDescription::BadCertificateStatusResponse => ErrorCode::AlertReceivedBadCertificateStatusResponse,
                    AlertDescription::BadCertificateHashValue => ErrorCode::AlertReceivedBadCertificateHashValue,
                    AlertDescription::UnknownPSKIdentity => ErrorCode::AlertReceivedUnknownPSKIdentity,
                    AlertDescription::CertificateRequired => ErrorCode::AlertReceivedCertificateRequired,
                    AlertDescription::NoApplicationProtocol => ErrorCode::AlertReceivedNoApplicationProtocol,
                    AlertDescription::Unknown(_) => ErrorCode::AlertReceivedUnknown,
                },
                TlsError::InvalidCertificateEncoding => ErrorCode::InvalidCertificateEncoding,
                TlsError::InvalidCertificateSignatureType => ErrorCode::InvalidCertificateSignatureType,
                TlsError::InvalidCertificateSignature => ErrorCode::InvalidCertificateSignature,
                TlsError::InvalidCertificateData(_) => ErrorCode::InvalidCertificateData,
                TlsError::InvalidSct(_) => ErrorCode::InvalidSCT,
                TlsError::General(_) => ErrorCode::General,
                TlsError::FailedToGetCurrentTime => ErrorCode::FailedToGetCurrentTime,
                TlsError::FailedToGetRandomBytes => ErrorCode::FailedToGetRandomBytes,
                TlsError::HandshakeNotComplete => ErrorCode::HandshakeNotComplete,
                TlsError::PeerSentOversizedRecord => ErrorCode::PeerSentOversizedRecord,
                TlsError::NoApplicationProtocol => ErrorCode::NoApplicationProtocol,
                TlsError::BadMaxFragmentSize => ErrorCode::BadMaxFragmentSize,
            },
        }
    }
}

/// `ERR_load_error_strings` - compatibility only
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void SSL_load_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_ERR_load_error_strings() {
    // compatibility only
}

/// `ERR_free_error_strings` - compatibility only
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void SSL_free_error_strings(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_ERR_free_error_strings() {
    // compatibility only
}

/// `ERR_error_string_n` - generates a human-readable string representing the
/// error code `e`, and places `len` bytes at `buf`. Note that this function is
/// not thread-safe and does no checks on the size of the buffer.
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void ERR_error_string_n(unsigned long e, char *buf, size_t len);
///
/// ```
///
/// # Safety
/// This API is Rust-unsafe because it dereferences a pointer provided by users
/// Use with caution!
#[no_mangle]
pub unsafe extern "C" fn tabby_ERR_error_string_n(
    error_code: c_ulong,
    buf_ptr: *mut c_char,
    buf_len: size_t,
) -> *const c_char {
    let error_string: &'static [u8] = ErrorCode::from(error_code).as_u8_slice();
    let error_string_len = error_string.len();
    let buf_len: usize = buf_len;
    let error_string: &'static [c_char] = &*(error_string as *const [u8] as *const [c_char]);
    if buf_ptr.is_null() {
        return error_string.as_ptr() as *const c_char;
    }
    let buf = slice::from_raw_parts_mut(buf_ptr, buf_len);
    if error_string_len > buf_len {
        buf.copy_from_slice(&error_string[0..buf_len]);
        buf[buf_len - 1] = 0;
    } else {
        buf[0..error_string_len].copy_from_slice(error_string);
    }
    buf_ptr
}

/// `ERR_error_reason_error_string` - returns a human-readable string representing
/// the error code e. This API does not allocate additional memory.
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// const char *ERR_reason_error_string(unsigned long e);
/// ```
#[no_mangle]
pub extern "C" fn tabby_ERR_reason_error_string(e: c_ulong) -> *const c_char {
    let error_code: ErrorCode = ErrorCode::from(e);
    error_code.as_u8_slice().as_ptr() as *const c_char
}

#[doc(hidden)]
pub(crate) struct ErrorQueue {}

impl ErrorQueue {
    pub fn push_error(e: Error) {
        ERROR_QUEUE.with(|q| {
            if ErrorCode::from(&e) != ErrorCode::OpensslErrorNone {
                q.borrow_mut().push_back(e);
            }
        });
    }
}

/// `ERR_get_error` - returns the earliest error code from the thread's error
/// queue and removes the entry. This function can be called repeatedly until
/// there are no more error codes to return.
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// unsigned long ERR_get_error(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_ERR_get_error() -> c_ulong {
    ERROR_QUEUE.with(|q| match q.borrow_mut().pop_front() {
        Some(e) => ErrorCode::from(&e) as c_ulong,
        None => 0,
    })
}

/// `ERR_peek_last_error` - returns the latest error code from the thread's error
/// queue without modifying it.
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// unsigned long ERR_peek_last_error(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_ERR_peek_last_error() -> c_ulong {
    ERROR_QUEUE.with(|q| match q.borrow().front() {
        Some(e) => ErrorCode::from(e) as c_ulong,
        None => 0,
    })
}

/// `ERR_clear_error` - empty the current thread's error queue.
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void ERR_clear_error(void);
/// ```
#[no_mangle]
pub extern "C" fn tabby_ERR_clear_error() {
    ERROR_QUEUE.with(|q| {
        q.borrow_mut().clear();
    });
}

/// `ERR_print_errors_fp` - a convenience function that prints the error
/// strings for all errors that OpenSSL has recorded to `fp`, thus emptying the
/// error queue.
///
/// ```c
/// #include <tabbyssl/openssl/err.h>
///
/// void ERR_print_errors_fp(FILE *fp);
/// ```
///
/// # Safety
/// This API is Rust-unsafe because it dereferences a pointer provided by users
/// Use with caution!
#[no_mangle]
pub unsafe extern "C" fn tabby_ERR_print_errors_fp(fp: *mut libc::FILE) {
    use crate::libcrypto::bio::FromFileStream;
    use std::io::Write;
    use std::{fs, str};
    if fp.is_null() {
        return;
    }
    let fd = libc::fileno(fp);
    if fd < 0 {
        return;
    }
    let mut file = fs::File::from_file_stream(fp);
    ERROR_QUEUE.with(|q| {
        let mut queue = q.borrow_mut();
        for e in queue.drain(0..) {
            let error_code = ErrorCode::from(&e);
            let error_string = format!(
                "error:[0x{:X}]:[tabbyssl]:[{}]:[{}]\n",
                error_code as c_ulong,
                e.call_site,
                str::from_utf8(error_code.as_u8_slice()).unwrap(),
            );
            let _ = file.write(error_string.as_bytes());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::thread;

    macro_rules! error {
        ($code:expr) => {{
            crate::libssl::err::Error::new($code, call_site!())
        }};
    }

    #[test]
    fn empty() {
        assert_eq!(0, tabby_ERR_get_error());
        tabby_ERR_clear_error();
    }

    #[test]
    fn push() {
        let error_code = ErrorCode::OpensslNullPointer;
        ErrorQueue::push_error(error!(OpensslError::NullPointer.into()));
        assert_eq!(error_code, ErrorCode::from(tabby_ERR_get_error()));
        tabby_ERR_clear_error();
    }

    #[test]
    fn clear() {
        ErrorQueue::push_error(error!(OpensslError::NullPointer.into()));
        tabby_ERR_clear_error();
        assert_eq!(0, tabby_ERR_get_error());
        tabby_ERR_clear_error();
    }

    #[test]
    fn get_should_remove_error() {
        ErrorQueue::push_error(error!(OpensslError::NullPointer.into()));
        let _ = tabby_ERR_get_error();
        assert_eq!(0, tabby_ERR_get_error());
        tabby_ERR_clear_error();
    }

    #[test]
    fn peek_should_not_remove_error() {
        let error_code = ErrorCode::OpensslNullPointer;
        ErrorQueue::push_error(error!(OpensslError::NullPointer.into()));
        let _ = tabby_ERR_peek_last_error();
        assert_eq!(error_code, ErrorCode::from(tabby_ERR_get_error()));
        tabby_ERR_clear_error();
    }

    #[test]
    fn error_queue_is_thread_local() {
        let thread = thread::spawn(|| {
            ErrorQueue::push_error(error!(OpensslError::NullPointer.into()));
            ErrorCode::from(tabby_ERR_get_error())
        });
        ErrorQueue::push_error(error!(OpensslError::MalformedObject.into()));

        let main_thread_error_code = ErrorCode::from(tabby_ERR_get_error());
        let sub_thread_error_code = thread.join().unwrap();
        assert_ne!(main_thread_error_code, sub_thread_error_code);
        tabby_ERR_clear_error();
    }

    #[test]
    fn invalid_error_codes() {
        use std;
        assert_eq!(ErrorCode::UndefinedError, ErrorCode::from(std::u32::MAX));
        assert_eq!(ErrorCode::UndefinedError, ErrorCode::from(std::u64::MAX));
        assert_eq!(
            ErrorCode::UndefinedError,
            ErrorCode::from(std::i32::MIN as u64)
        );
        assert_eq!(
            ErrorCode::OpensslErrorNone,
            ErrorCode::from(std::i64::MIN as u64)
        );
    }

    const ERROR_CODES: [ErrorCode; 85] = [
        ErrorCode::OpensslErrorNone,
        ErrorCode::OpensslErrorZeroReturn,
        ErrorCode::OpensslErrorWantRead,
        ErrorCode::OpensslErrorWantWrite,
        ErrorCode::OpensslErrorWantConnect,
        ErrorCode::OpensslErrorWantAccept,
        ErrorCode::OpensslErrorSyscall,
        ErrorCode::OpensslErrorSsl,
        ErrorCode::OpensslNullPointer,
        ErrorCode::OpensslErrorMalformedObject,
        ErrorCode::OpensslErrorBadFuncArg,
        ErrorCode::OpensslErrorPanic,
        ErrorCode::OpensslErrorLock,
        ErrorCode::IoErrorNotFound,
        ErrorCode::IoErrorPermissionDenied,
        ErrorCode::IoErrorConnectionRefused,
        ErrorCode::IoErrorConnectionReset,
        ErrorCode::IoErrorConnectionAborted,
        ErrorCode::IoErrorNotConnected,
        ErrorCode::IoErrorAddrInUse,
        ErrorCode::IoErrorAddrNotAvailable,
        ErrorCode::IoErrorBrokenPipe,
        ErrorCode::IoErrorAlreadyExists,
        ErrorCode::IoErrorWouldBlock,
        ErrorCode::IoErrorInvalidInput,
        ErrorCode::IoErrorInvalidData,
        ErrorCode::IoErrorTimedOut,
        ErrorCode::IoErrorWriteZero,
        ErrorCode::IoErrorInterrupted,
        ErrorCode::IoErrorOther,
        ErrorCode::IoErrorUnexpectedEof,
        ErrorCode::InappropriateMessage,
        ErrorCode::InappropriateHandshakeMessage,
        ErrorCode::CorruptMessage,
        ErrorCode::CorruptMessagePayload,
        ErrorCode::CorruptMessagePayloadAlert,
        ErrorCode::CorruptMessagePayloadChangeCipherSpec,
        ErrorCode::CorruptMessagePayloadHandshake,
        ErrorCode::NoCertificatesPresented,
        ErrorCode::DecryptError,
        ErrorCode::PeerIncompatibleError,
        ErrorCode::PeerMisbehavedError,
        ErrorCode::AlertReceivedCloseNotify,
        ErrorCode::AlertReceivedUnexpectedMessage,
        ErrorCode::AlertReceivedBadRecordMac,
        ErrorCode::AlertReceivedDecryptionFailed,
        ErrorCode::AlertReceivedRecordOverflow,
        ErrorCode::AlertReceivedDecompressionFailure,
        ErrorCode::AlertReceivedHandshakeFailure,
        ErrorCode::AlertReceivedNoCertificate,
        ErrorCode::AlertReceivedBadCertificate,
        ErrorCode::AlertReceivedUnsupportedCertificate,
        ErrorCode::AlertReceivedCertificateRevoked,
        ErrorCode::AlertReceivedCertificateExpired,
        ErrorCode::AlertReceivedCertificateUnknown,
        ErrorCode::AlertReceivedIllegalParameter,
        ErrorCode::AlertReceivedUnknownCA,
        ErrorCode::AlertReceivedAccessDenied,
        ErrorCode::AlertReceivedDecodeError,
        ErrorCode::AlertReceivedDecryptError,
        ErrorCode::AlertReceivedExportRestriction,
        ErrorCode::AlertReceivedProtocolVersion,
        ErrorCode::AlertReceivedInsufficientSecurity,
        ErrorCode::AlertReceivedInternalError,
        ErrorCode::AlertReceivedInappropriateFallback,
        ErrorCode::AlertReceivedUserCanceled,
        ErrorCode::AlertReceivedNoRenegotiation,
        ErrorCode::AlertReceivedMissingExtension,
        ErrorCode::AlertReceivedUnsupportedExtension,
        ErrorCode::AlertReceivedCertificateUnobtainable,
        ErrorCode::AlertReceivedUnrecognisedName,
        ErrorCode::AlertReceivedBadCertificateStatusResponse,
        ErrorCode::AlertReceivedBadCertificateHashValue,
        ErrorCode::AlertReceivedUnknownPSKIdentity,
        ErrorCode::AlertReceivedCertificateRequired,
        ErrorCode::AlertReceivedNoApplicationProtocol,
        ErrorCode::AlertReceivedUnknown,
        ErrorCode::InvalidSCT,
        ErrorCode::General,
        ErrorCode::FailedToGetCurrentTime,
        ErrorCode::InvalidDNSName,
        ErrorCode::HandshakeNotComplete,
        ErrorCode::PeerSentOversizedRecord,
        ErrorCode::NoApplicationProtocol,
        ErrorCode::UndefinedError,
    ];

    #[test]
    fn error_code_conversion_from_long() {
        for code in ERROR_CODES.iter() {
            assert_eq!(*code, ErrorCode::from(*code as c_ulong));
        }
    }

    #[test]
    fn tabby_error_code_conversion() {
        let tabby_errors: [OpensslError; 11] = [
            OpensslError::ZeroReturn,
            OpensslError::WantRead,
            OpensslError::WantWrite,
            OpensslError::WantConnect,
            OpensslError::WantAccept,
            OpensslError::Syscall,
            OpensslError::Ssl,
            OpensslError::NullPointer,
            OpensslError::MalformedObject,
            OpensslError::BadFuncArg,
            OpensslError::Panic,
        ];

        for error in tabby_errors.iter() {
            let tabby_error = error!(ErrorKind::Builtin(error.clone()));
            let error_code = ErrorCode::from(&tabby_error);
            println!("{}, {}", error, error.to_string());
            assert_eq!(true, 0 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn io_error_conversion() {
        let io_errors: [io::ErrorKind; 18] = [
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
            io::ErrorKind::AddrInUse,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::AlreadyExists,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::InvalidData,
            io::ErrorKind::TimedOut,
            io::ErrorKind::WriteZero,
            io::ErrorKind::Interrupted,
            io::ErrorKind::Other,
            io::ErrorKind::UnexpectedEof,
        ];

        for error_kind in io_errors.iter() {
            let io_error = io::Error::from(*error_kind);
            let tabby_error = error!(ErrorKind::Io(io_error));
            let error_code = ErrorCode::from(&tabby_error);
            assert_eq!(true, 2 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn tls_error_conversion() {
        use rustls::internal::msgs::enums::{AlertDescription, ContentType, HandshakeType};
        let tls_errors: [rustls::Error; 23] = [
            rustls::Error::InappropriateMessage {
                expect_types: vec![],
                got_type: ContentType::Heartbeat,
            },
            rustls::Error::InappropriateHandshakeMessage {
                expect_types: vec![],
                got_type: HandshakeType::Finished,
            },
            rustls::Error::CorruptMessage,
            rustls::Error::CorruptMessagePayload(ContentType::Heartbeat),
            rustls::Error::NoCertificatesPresented,
            rustls::Error::UnsupportedNameType,
            rustls::Error::DecryptError,
            rustls::Error::EncryptError,
            rustls::Error::PeerIncompatibleError("".to_string()),
            rustls::Error::PeerMisbehavedError("".to_string()),
            rustls::Error::AlertReceived(AlertDescription::CloseNotify),
            rustls::Error::InvalidCertificateEncoding,
            rustls::Error::InvalidCertificateSignatureType,
            rustls::Error::InvalidCertificateSignature,
            rustls::Error::InvalidCertificateData("".to_string()),
            rustls::Error::InvalidSct(sct::Error::InvalidSignature),
            rustls::Error::General("".to_string()),
            rustls::Error::FailedToGetCurrentTime,
            rustls::Error::FailedToGetRandomBytes,
            rustls::Error::HandshakeNotComplete,
            rustls::Error::PeerSentOversizedRecord,
            rustls::Error::NoApplicationProtocol,
            rustls::Error::BadMaxFragmentSize,
        ];

        for error in tls_errors.iter() {
            let tabby_error = error!(ErrorKind::Tls(error.clone()));
            let error_code = ErrorCode::from(&tabby_error);
            assert_eq!(true, 3 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn tls_alert_error_conversion() {
        use rustls::internal::msgs::enums::AlertDescription;
        let alerts: [AlertDescription; 34] = [
            AlertDescription::CloseNotify,
            AlertDescription::UnexpectedMessage,
            AlertDescription::BadRecordMac,
            AlertDescription::DecryptionFailed,
            AlertDescription::RecordOverflow,
            AlertDescription::DecompressionFailure,
            AlertDescription::HandshakeFailure,
            AlertDescription::NoCertificate,
            AlertDescription::BadCertificate,
            AlertDescription::UnsupportedCertificate,
            AlertDescription::CertificateRevoked,
            AlertDescription::CertificateExpired,
            AlertDescription::CertificateUnknown,
            AlertDescription::IllegalParameter,
            AlertDescription::UnknownCA,
            AlertDescription::AccessDenied,
            AlertDescription::DecodeError,
            AlertDescription::DecryptError,
            AlertDescription::ExportRestriction,
            AlertDescription::ProtocolVersion,
            AlertDescription::InsufficientSecurity,
            AlertDescription::InternalError,
            AlertDescription::InappropriateFallback,
            AlertDescription::UserCanceled,
            AlertDescription::NoRenegotiation,
            AlertDescription::MissingExtension,
            AlertDescription::UnsupportedExtension,
            AlertDescription::CertificateUnobtainable,
            AlertDescription::UnrecognisedName,
            AlertDescription::BadCertificateStatusResponse,
            AlertDescription::BadCertificateHashValue,
            AlertDescription::UnknownPSKIdentity,
            AlertDescription::CertificateRequired,
            AlertDescription::NoApplicationProtocol,
        ];

        for alert in alerts.iter() {
            let error = rustls::Error::AlertReceived(*alert);
            let tabby_error = error!(ErrorKind::Tls(error));
            let error_code = ErrorCode::from(&tabby_error);
            assert_eq!(true, 3 == error_code as c_ulong >> 24);
            assert_eq!(true, 0 != error_code as c_ulong & 0xFFFFFF);
        }
    }

    #[test]
    fn error_strings() {
        for code in ERROR_CODES.iter() {
            let error_string_ptr: *const c_char = tabby_ERR_reason_error_string(*code as c_ulong);
            assert_ne!(ptr::null(), error_string_ptr);
            let len = unsafe { libc::strlen(error_string_ptr) };
            let ptr = code.as_u8_slice().as_ptr() as *const c_char;
            assert_eq!(0, unsafe { libc::strncmp(ptr, error_string_ptr, len) });
        }
    }

    #[test]
    fn error_string_n_with_big_buf() {
        let mut buf = [0u8; 256];
        let buf_ptr = buf.as_mut_ptr() as *mut c_char;
        for code in ERROR_CODES.iter() {
            let builtin_error_string_ptr: *const c_char =
                tabby_ERR_reason_error_string(*code as c_ulong);
            let buf_error_string_ptr =
                unsafe { tabby_ERR_error_string_n(*code as c_ulong, buf_ptr, buf.len()) };
            let builtin_error_string_len = unsafe { libc::strlen(builtin_error_string_ptr) };
            let buf_error_string_len = unsafe { libc::strlen(buf_error_string_ptr) };
            assert_eq!(buf_error_string_len, builtin_error_string_len);
            assert_eq!(0, unsafe {
                libc::strncmp(
                    builtin_error_string_ptr,
                    buf_error_string_ptr,
                    builtin_error_string_len,
                )
            });
            assert_eq!(false, builtin_error_string_ptr == buf_error_string_ptr);
        }
    }

    #[test]
    fn error_string_n_with_small_buf() {
        const BUF_SIZE: usize = 10;
        let mut buf = [0u8; BUF_SIZE];
        let buf_ptr = buf.as_mut_ptr() as *mut c_char;
        for code in ERROR_CODES.iter() {
            let builtin_error_string_ptr: *const c_char =
                tabby_ERR_reason_error_string(*code as c_ulong);
            let buf_error_string_ptr =
                unsafe { tabby_ERR_error_string_n(*code as c_ulong, buf_ptr, buf.len()) };
            let buf_error_string_len = unsafe { libc::strlen(buf_error_string_ptr) };
            //assert_eq!(buf_error_string_len, buf_error_string_len);
            assert_eq!(0, unsafe {
                libc::strncmp(
                    builtin_error_string_ptr,
                    buf_error_string_ptr,
                    buf_error_string_len,
                )
            });
            assert_eq!(false, builtin_error_string_ptr == buf_error_string_ptr);
        }
    }

    #[test]
    fn error_string_n_with_null_buf() {
        for code in ERROR_CODES.iter() {
            let builtin_error_string_ptr: *const c_char =
                tabby_ERR_reason_error_string(*code as c_ulong);
            let buf_error_string_ptr = unsafe {
                tabby_ERR_error_string_n(*code as c_ulong, ptr::null_mut() as *mut c_char, 0)
            };

            let builtin_error_string_len = unsafe { libc::strlen(builtin_error_string_ptr) };
            let buf_error_string_len = unsafe { libc::strlen(buf_error_string_ptr) };
            assert_eq!(buf_error_string_len, builtin_error_string_len);
            assert_eq!(0, unsafe {
                libc::strncmp(
                    builtin_error_string_ptr,
                    buf_error_string_ptr,
                    builtin_error_string_len,
                )
            });
            assert_eq!(true, builtin_error_string_ptr == buf_error_string_ptr);
        }
    }

    #[test]
    fn err_print_errors_fp() {
        use crate::libcrypto::bio::OpenFileStream;
        use std::io;

        tabby_ERR_load_error_strings();
        ErrorQueue::push_error(error!(OpensslError::None.into()));
        ErrorQueue::push_error(error!(OpensslError::BadFuncArg.into()));
        ErrorQueue::push_error(error!(OpensslError::MalformedObject.into()));
        let stderr = io::stderr();
        let file = unsafe { stderr.open_file_stream_w() };
        unsafe {
            tabby_ERR_print_errors_fp(file);
            tabby_ERR_print_errors_fp(ptr::null_mut());
        }
        tabby_ERR_clear_error();
        tabby_ERR_free_error_strings();
    }
}
