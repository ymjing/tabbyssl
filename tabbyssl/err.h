/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#ifndef TABBYSSL_ERR_H
#define TABBYSSL_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <tabbyssl/options.h>
#include <tabbyssl/version.h>
#include <tabbyssl/visibility.h>
#include <stdio.h>

enum
{
  // OpenSSL error codes
  OPENSSL_ERROR_NONE = 0,
  OPENSSL_ERROR_ZERO_RETURN = 1,
  OPENSSL_ERROR_WANT_READ = 2,
  OPENSSL_ERROR_WANT_WRITE = 3,
  OPENSSL_ERROR_WANT_CONNECT = 7,
  OPENSSL_ERROR_WANT_ACCEPT = 8,
  OPENSSL_ERROR_SYSCALL = 5,
  OPENSSL_ERROR_SSL = 0x55,
  OPENSSL_ERROR_NULL_POINTER = 0xe0,
  OPENSSL_ERROR_MALFORMED_OBJECT = 0xe1,
  OPENSSL_ERROR_BAD_FUNC_ARG = 0xe2,
  OPENSSL_ERROR_PANIC = 0xe3,
  OPENSSL_ERROR_LOCK = 0xe4,
  // Rust IO ErrorKind codes
  IO_ERROR_NOT_FOUND = 0x02000001,
  IO_ERROR_PERMISSION_DENIED = 0x02000002,
  IO_ERROR_CONNECTION_REFUSED = 0x02000003,
  IO_ERROR_CONNECTION_RESET = 0x02000004,
  IO_ERROR_CONNECTION_ABORTED = 0x02000005,
  IO_ERROR_NOT_CONNECTED = 0x02000006,
  IO_ERROR_ADDR_IN_USE = 0x02000007,
  IO_ERROR_ADDR_NOT_AVAILABLE = 0x02000008,
  IO_ERROR_BROKEN_PIPE = 0x02000009,
  IO_ERROR_ALREADY_EXISTS = 0x0200000a,
  IO_ERROR_WOULD_BLOCK = 0x0200000b,
  IO_ERROR_INVALID_INPUT = 0x0200000c,
  IO_ERROR_INVALID_DATA = 0x0200000d,
  IO_ERROR_TIMED_OUT = 0x0200000e,
  IO_ERROR_WRITE_ZERO = 0x0200000f,
  IO_ERROR_INTERRUPTED = 0x02000010,
  IO_ERROR_OTHER = 0x02000011,
  IO_ERROR_UNEXPECTED_EOF = 0x02000012,
  // TLS error codes
  TLS_ERROR_INAPPROPRIATE_MESSAGE = 0x03000100,
  TLS_ERROR_INAPPROPRIATE_HANDSHAKE_MESSAGE = 0x03000200,
  TLS_ERROR_CORRUPT_MESSAGE = 0x03000300,
  TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD = 0x03000400,
  TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_ALERT = 0x03000401,
  TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_CHANGE_CIPHER_SPEC = 0x03000402,
  TLS_ERROR_CORRUPT_MESSAGE_PAYLOAD_HANDSHAKE = 0x03000403,
  TLS_ERROR_NO_CERTIFICATES_PRESENTED = 0x03000500,
  TLS_ERROR_DECRYPT_ERROR = 0x03000600,
  TLS_ERROR_PEER_INCOMPATIBLE_ERROR = 0x03000700,
  TLS_ERROR_PEER_MISBEHAVED_ERROR = 0x03000800,
  TLS_ERROR_ALERT_RECEIVED_ERRORS = 0x03000900,
  TLS_ERROR_ALERT_RECEIVED_CLOSE_NOTIFY = 0x03000901,
  TLS_ERROR_ALERT_RECEIVED_UNEXPECTED_MESSAGE = 0x03000902,
  TLS_ERROR_ALERT_RECEIVED_BAD_RECORD_MAC = 0x03000903,
  TLS_ERROR_ALERT_RECEIVED_DECRYPTION_FAILED = 0x03000904,
  TLS_ERROR_ALERT_RECEIVED_RECORD_OVERFLOW = 0x03000905,
  TLS_ERROR_ALERT_RECEIVED_DECOMPRESSION_FAILURE = 0x03000906,
  TLS_ERROR_ALERT_RECEIVED_HANDSHAKE_FAILURE = 0x03000907,
  TLS_ERROR_ALERT_RECEIVED_NO_CERTIFICATE = 0x03000908,
  TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE = 0x03000909,
  TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_CERTIFICATE = 0x0300090a,
  TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REVOKED = 0x0300090b,
  TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_EXPIRED = 0x0300090c,
  TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNKNOWN = 0x0300090d,
  TLS_ERROR_ALERT_RECEIVED_ILLEGAL_PARAMETER = 0x0300090e,
  TLS_ERROR_ALERT_RECEIVED_UNKNOWN_CA = 0x0300090f,
  TLS_ERROR_ALERT_RECEIVED_ACCESS_DENIED = 0x03000910,
  TLS_ERROR_ALERT_RECEIVED_DECODE_ERROR = 0x03000911,
  TLS_ERROR_ALERT_RECEIVED_DECRYPT_ERROR = 0x03000912,
  TLS_ERROR_ALERT_RECEIVED_EXPORT_RESTRICTION = 0x03000913,
  TLS_ERROR_ALERT_RECEIVED_PROTOCOL_VERSION = 0x03000914,
  TLS_ERROR_ALERT_RECEIVED_INSUFFICIENT_SECURITY = 0x03000915,
  TLS_ERROR_ALERT_RECEIVED_INTERNAL_ERROR = 0x03000916,
  TLS_ERROR_ALERT_RECEIVED_INAPPROPRIATE_FALLBACK = 0x03000917,
  TLS_ERROR_ALERT_RECEIVED_USER_CANCELED = 0x03000918,
  TLS_ERROR_ALERT_RECEIVED_NO_RENEGOTIATION = 0x03000919,
  TLS_ERROR_ALERT_RECEIVED_MISSING_EXTENSION = 0x0300091a,
  TLS_ERROR_ALERT_RECEIVED_UNSUPPORTED_EXTENSION = 0x0300091b,
  TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_UNOBTAINABLE = 0x0300091c,
  TLS_ERROR_ALERT_RECEIVED_UNRECOGNISED_NAME = 0x0300091d,
  TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_STATUS_RESPONSE = 0x0300091e,
  TLS_ERROR_ALERT_RECEIVED_BAD_CERTIFICATE_HASH_VALUE = 0x0300091f,
  TLS_ERROR_ALERT_RECEIVED_UNKNOWN_PSK_IDENTITY = 0x03000920,
  TLS_ERROR_ALERT_RECEIVED_CERTIFICATE_REQUIRED = 0x03000921,
  TLS_ERROR_ALERT_RECEIVED_NO_APPLICATION_PROTOCOL = 0x03000922,
  TLS_ERROR_ALERT_RECEIVED_UNKNOWN = 0x030009ff,
  TLS_ERROR_WEBPKI_ERRORS = 0x03000a00,
  TLS_ERROR_WEBPKI_BAD_DER = 0x03000a01,
  TLS_ERROR_WEBPKI_BAD_DER_TIME = 0x03000a02,
  TLS_ERROR_WEBPKI_CA_USED_AS_END_ENTITY = 0x03000a03,
  TLS_ERROR_WEBPKI_CERT_EXPIRED = 0x03000a04,
  TLS_ERROR_WEBPKI_CERT_NOT_VALID_FOR_NAME = 0x03000a05,
  TLS_ERROR_WEBPKI_CERT_NOT_VALID_YET = 0x03000a06,
  TLS_ERROR_WEBPKI_END_ENTITY_USED_AS_CA = 0x03000a07,
  TLS_ERROR_WEBPKI_EXTENSION_VALUE_INVALID = 0x03000a08,
  TLS_ERROR_WEBPKI_INVALID_CERT_VALIDITY = 0x03000a09,
  TLS_ERROR_WEBPKI_INVALID_SIGNATURE_FOR_PUBLIC_KEY = 0x03000a0a,
  TLS_ERROR_WEBPKI_NAME_CONSTRAINT_VIOLATION = 0x03000a0b,
  TLS_ERROR_WEBPKI_PATH_LEN_CONSTRAINT_VIOLATED = 0x03000a0c,
  TLS_ERROR_WEBPKI_SIGNATURE_ALGORITHM_MISMATCH = 0x03000a0d,
  TLS_ERROR_WEBPKI_REQUIRED_EKU_NOT_FOUND = 0x03000a0e,
  TLS_ERROR_WEBPKI_UNKNOWN_ISSUER = 0x03000a0f,
  TLS_ERROR_WEBPKI_UNSUPPORTED_CERT_VERSION = 0x03000a10,
  TLS_ERROR_WEBPKI_UNSUPPORTED_CRITICAL_EXTENSION = 0x03000a11,
  TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_PUBLIC_KEY = 0x03000a12,
  TLS_ERROR_WEBPKI_UNSUPPORTED_SIGNATURE_ALGORITHM = 0x03000a13,
  TLS_ERROR_INVALID_SCT = 0x03000b00,
  TLS_ERROR_GENERAL = 0x03000c00,
  TLS_ERROR_FAILED_TO_GET_CURRENT_TIME = 0x03000d00,
  TLS_ERROR_INVALID_DNS_NAME = 0x03000e00,
  TLS_ERROR_HANDSHAKE_NOT_COMPLETE = 0x03000f00,
  TLS_ERROR_PEER_SENT_OVERSIZED_RECORD = 0x03001000,
  UNDEFINED_ERROR = 0xeeeeeeee,
};

TABBY_API const char *tabby_ERR_error_string_n(unsigned long e,
                                                     char *buf, size_t len);
TABBY_API const char *tabby_ERR_reason_error_string(unsigned long e);

TABBY_API unsigned long tabby_ERR_get_error(void);
TABBY_API unsigned long tabby_ERR_peek_last_error(void);
TABBY_API void tabby_ERR_clear_error(void);

TABBY_API void tabby_ERR_print_errors_fp(const FILE *);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* TABBYSSL_ERR_H */
