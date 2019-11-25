/*
 * Copyright (c) 2019, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

/* This file is a test shim for the BoringSSL-Go ('bogo') TLS test suite,
 * which is in part based upon the Rustls implementation in bogo_shim.rs.
 *
 * ISC License (ISC)
 * Copyright (c) 2016, Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

use env_logger;
use libc;

use std::env;
use std::ffi::CString;
use std::io::Write;
use std::net;
use std::process;
use tabbyssl::libssl::err::ErrorCode;
use tabbyssl::libssl::{err, ssl};

static BOGO_NACK: i32 = 89;

macro_rules! println_err(
  ($($arg:tt)*) => { {
    writeln!(&mut ::std::io::stderr(), $($arg)*).unwrap();
  } }
);

#[derive(Debug)]
struct Options {
    port: u16,
    server: bool,
    resume_count: usize,
    shim_writes_first: bool,
    shim_shut_down: bool,
    check_close_notify: bool,
    host_name: String,
    use_sni: bool,
    key_file: String,
    cert_file: String,
    support_tls13: bool,
    support_tls12: bool,
    min_version: Option<u16>,
    max_version: Option<u16>,
    read_size: usize,
    enable_early_data: bool,
    expect_ticket_supports_early_data: bool,
    expect_accept_early_data: bool,
    expect_reject_early_data: bool,
    shim_writes_first_on_resume: bool,
    expect_version: u16,
}

impl Options {
    fn new() -> Options {
        Options {
            port: 0,
            server: false,
            resume_count: 0,
            host_name: "example.com".to_string(),
            use_sni: false,
            shim_writes_first: false,
            shim_shut_down: false,
            check_close_notify: false,
            key_file: "".to_string(),
            cert_file: "".to_string(),
            support_tls13: true,
            support_tls12: true,
            min_version: None,
            max_version: None,
            read_size: 512,
            enable_early_data: false,
            expect_ticket_supports_early_data: false,
            expect_accept_early_data: false,
            expect_reject_early_data: false,
            shim_writes_first_on_resume: false,
            expect_version: 0,
        }
    }

    fn version_allowed(&self, vers: u16) -> bool {
        (self.min_version.is_none() || vers >= self.min_version.unwrap())
            && (self.max_version.is_none() || vers <= self.max_version.unwrap())
    }

    fn tls13_supported(&self) -> bool {
        self.support_tls13 && (self.version_allowed(0x0304) || self.version_allowed(0x7f1c))
    }

    fn tls12_supported(&self) -> bool {
        self.support_tls12 && self.version_allowed(0x0303)
    }
}

fn quit(why: &str) -> ! {
    println_err!("{}", why);
    process::exit(0)
}

fn quit_err(why: &str) -> ! {
    println_err!("{}", why);
    process::exit(1)
}

fn handle_err(err: ErrorCode) -> ! {
    match err {
        ErrorCode::TLSErrorInappropriateMessage
        | ErrorCode::TLSErrorInappropriateHandshakeMessage => quit(":UNEXPECTED_MESSAGE:"),
        ErrorCode::TLSErrorAlertReceivedRecordOverflow => quit(":TLSV1_ALERT_RECORD_OVERFLOW:"),
        ErrorCode::TLSErrorAlertReceivedHandshakeFailure => quit(":HANDSHAKE_FAILURE:"),
        ErrorCode::TLSErrorCorruptMessagePayloadAlert => quit(":BAD_ALERT:"),
        ErrorCode::TLSErrorCorruptMessagePayloadChangeCipherSpec => {
            quit(":BAD_CHANGE_CIPHER_SPEC:")
        }
        ErrorCode::TLSErrorCorruptMessagePayloadHandshake => quit(":BAD_HANDSHAKE_MSG:"),
        ErrorCode::TLSErrorCorruptMessagePayload => quit(":GARBAGE:"),
        ErrorCode::TLSErrorCorruptMessage => quit(":GARBAGE:"),
        ErrorCode::TLSErrorDecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
        ErrorCode::TLSErrorPeerIncompatibleError => quit(":INCOMPATIBLE:"),
        ErrorCode::TLSErrorPeerMisbehavedError => quit(":PEER_MISBEHAVIOUR:"),
        ErrorCode::TLSErrorNoCertificatesPresented => quit(":NO_CERTS:"),
        ErrorCode::TLSErrorAlertReceivedUnexpectedMessage => quit(":BAD_ALERT:"),
        ErrorCode::TLSErrorAlertReceivedDecompressionFailure => {
            quit(":SSLV3_ALERT_DECOMPRESSION_FAILURE:")
        }
        ErrorCode::TLSErrorWebpkiBadDER => quit(":CANNOT_PARSE_LEAF_CERT:"),
        ErrorCode::TLSErrorWebpkiInvalidSignatureForPublicKey => quit(":BAD_SIGNATURE:"),
        ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey => {
            quit(":WRONG_SIGNATURE_TYPE:")
        }
        ErrorCode::TLSErrorPeerSentOversizedRecord => quit(":DATA_LENGTH_TOO_LONG:"),
        ErrorCode::TLSErrorAlertReceivedProtocolVersion => quit(":PEER_MISBEHAVIOUR:"),
        _ => {
            println_err!("unhandled error: {:?}", err);
            quit(":FIXME:")
        }
    }
}

fn setup_ctx(opts: &Options) -> *mut ssl::TABBY_CTX_ARC {
    let method = match (opts.tls12_supported(), opts.tls13_supported(), opts.server) {
        (true, true, false) => ssl::tabby_TLS_client_method(),
        (true, true, true) => ssl::tabby_TLS_server_method(),
        (true, false, false) => ssl::tabby_TLSv1_2_client_method(),
        (true, false, true) => ssl::tabby_TLSv1_2_server_method(),
        (false, true, false) => ssl::tabby_TLSv1_3_client_method(),
        (false, true, true) => ssl::tabby_TLSv1_3_server_method(),
        _ => return std::ptr::null_mut(),
    };
    let ctx = ssl::tabby_SSL_CTX_new(method as *mut ssl::TABBY_METHOD);
    ssl::tabby_SSL_CTX_set_session_cache_mode(ctx, 0x3); // enable both client and server session cache
    if opts.server {
        if ssl::tabby_SSL_CTX_use_certificate_chain_file(
            ctx,
            CString::new(opts.cert_file.clone()).unwrap().as_ptr() as *const libc::c_char,
            0,
        ) != 1
        {
            println_err!("tabby_SSL_CTX_use_certificate_chain_file failed");
            println_err!("{:?}", ErrorCode::from(err::tabby_ERR_peek_last_error()));
        }
        if ssl::tabby_SSL_CTX_use_PrivateKey_file(
            ctx,
            CString::new(opts.key_file.clone()).unwrap().as_ptr() as *const libc::c_char,
            0,
        ) != 1
        {
            println_err!("tabby_SSL_CTX_use_PrivateKey_file failed");
            println_err!("{:?}", ErrorCode::from(err::tabby_ERR_peek_last_error()));
        }
        if ssl::tabby_SSL_CTX_check_private_key(ctx) != 1 {
            println_err!("tabby_SSL_CTX_check_private_key failed");
            println_err!("{:?}", ErrorCode::from(err::tabby_ERR_peek_last_error()));
        }
    }
    ssl::tabby_SSL_CTX_set_verify(ctx, 0, None);
    ctx
}

fn cleanup(ssl: *mut ssl::TABBY_SSL, ctx: *mut ssl::TABBY_CTX_ARC) {
    if !ssl.is_null() {
        ssl::tabby_SSL_free(ssl);
    }
    if !ctx.is_null() {
        ssl::tabby_SSL_CTX_free(ctx);
    }
}

fn do_connection(opts: &Options, ctx: *mut ssl::TABBY_CTX_ARC, count: usize) {
    use std::os::unix::io::AsRawFd;
    let conn = net::TcpStream::connect(("localhost", opts.port)).expect("cannot connect");
    let mut sent_shutdown = false;
    let mut seen_eof = false;

    let ssl: *mut ssl::TABBY_SSL = ssl::tabby_SSL_new(ctx);

    if ssl.is_null() {
        ssl::tabby_SSL_CTX_free(ctx);
        quit_err("TABBY_SSL is null");
    }

    if ssl::tabby_SSL_set_tlsext_host_name(
        ssl,
        CString::new(opts.host_name.clone()).unwrap().as_ptr() as *const libc::c_char,
    ) != 1
    {
        cleanup(ssl, ctx);
        quit_err("tabby_SSL_set_tlsext_host_name failed\n");
    }
    if ssl::tabby_SSL_set_fd(ssl, conn.as_raw_fd()) != 1 {
        cleanup(ssl, ctx);
        quit_err("tabby_SSL_set_fd failed\n");
    }

    if opts.shim_writes_first_on_resume && count > 0 && opts.enable_early_data {
        let len: libc::size_t = 0;
        let len_ptr = Box::into_raw(Box::new(len));
        let buf = b"hello";
        ssl::tabby_SSL_write_early_data(ssl, buf.as_ptr() as *const libc::c_uchar, 5, len_ptr);
        let written_len = unsafe { Box::from_raw(len_ptr) };
        if *written_len < 5 {
            let remaining_buf = &buf[*written_len..];
            ssl::tabby_SSL_write(
                ssl,
                remaining_buf.as_ptr() as *const libc::c_uchar,
                (5 - *written_len) as libc::c_int,
            );
        }
    }

    use std::{thread, time};
    if !opts.server {
        if ssl::tabby_SSL_connect(ssl) != 1 {
            let err = ErrorCode::from(ssl::tabby_SSL_get_error(ssl, -1) as libc::c_ulong);
            ssl::tabby_SSL_flush(ssl);
            thread::sleep(time::Duration::from_millis(200));
            cleanup(ssl, ctx);
            handle_err(err);
        }
    } else {
        if ssl::tabby_SSL_accept(ssl) != 1 {
            let err = ErrorCode::from(ssl::tabby_SSL_get_error(ssl, -1) as libc::c_ulong);
            ssl::tabby_SSL_flush(ssl);
            thread::sleep(time::Duration::from_millis(200));
            cleanup(ssl, ctx);
            handle_err(err);
        }
    }

    if opts.shim_writes_first {
        ssl::tabby_SSL_write(
            ssl,
            b"hello".as_ptr() as *const libc::c_uchar,
            5 as libc::c_int,
        );
    }

    let mut len;
    let mut buf = [0u8; 1024];
    loop {
        ssl::tabby_SSL_flush(ssl);

        if opts.enable_early_data && count > 0 {
            let early_data_accepted = ssl::tabby_SSL_get_early_data_status(ssl) == 2;
            if opts.expect_accept_early_data && !early_data_accepted {
                quit_err("Early data was not accepted, but we expect the opposite");
            } else if opts.expect_reject_early_data && early_data_accepted {
                quit_err("Early data was accepted, but we expect the opposite");
            }
            if opts.expect_version == 0x0304 {
                let version_ptr = ssl::tabby_SSL_get_version(ssl);
                let version = unsafe { std::ffi::CStr::from_ptr(version_ptr).to_str().unwrap() };
                if version != "TLS1.3" {
                    quit_err("wrong protocol version");
                }
            }
        }

        len = ssl::tabby_SSL_read(
            ssl,
            buf.as_mut_ptr() as *mut libc::c_uchar,
            opts.read_size as libc::c_int,
        );
        if len == 0 {
            let error = ErrorCode::from(ssl::tabby_SSL_get_error(ssl, len) as u32);
            match error {
                ErrorCode::OpensslErrorNone => (),
                ErrorCode::OpensslErrorWantRead | ErrorCode::OpensslErrorWantWrite => continue,
                ErrorCode::IoErrorConnectionAborted => {
                    if opts.check_close_notify {
                        println!("close notify ok");
                    }
                    println!("EOF (tls)");
                    ssl::tabby_SSL_flush(ssl);
                    ssl::tabby_SSL_free(ssl);
                    return;
                }
                ErrorCode::IoErrorConnectionReset => {
                    if opts.check_close_notify {
                        cleanup(ssl, ctx);
                        quit_err(":CLOSE_WITHOUT_CLOSE_NOTIFY:")
                    }
                }
                _ => {
                    ssl::tabby_SSL_flush(ssl);
                    cleanup(ssl, ctx);
                    handle_err(error);
                }
            };
            if opts.check_close_notify {
                if !seen_eof {
                    seen_eof = true;
                } else {
                    ssl::tabby_SSL_flush(ssl);
                    cleanup(ssl, ctx);
                    quit_err(":CLOSE_WITHOUT_CLOSE_NOTIFY:");
                }
            } else {
                println!("EOF (plain)");
                ssl::tabby_SSL_flush(ssl);
                ssl::tabby_SSL_free(ssl);
                return;
            }
        } else if len < 0 {
            let err = ErrorCode::from(ssl::tabby_SSL_get_error(ssl, len) as libc::c_ulong);
            ssl::tabby_SSL_flush(ssl);
            cleanup(ssl, ctx);
            handle_err(err);
        }

        if opts.shim_shut_down && !sent_shutdown {
            ssl::tabby_SSL_shutdown(ssl);
            sent_shutdown = true;
        }

        for b in buf.iter_mut() {
            *b ^= 0xff;
        }

        ssl::tabby_SSL_write(ssl, buf.as_ptr() as *const libc::c_uchar, len);
    }
    // unreachable
}

fn main() {
    let mut args: Vec<_> = env::args().collect();
    env_logger::init();

    args.remove(0);

    if !args.is_empty() && args[0] == "-is-handshaker-supported" {
        println!("No");
        process::exit(0);
    }
    println!("options: {:?}", args);

    let mut opts = Options::new();

    while !args.is_empty() {
        let arg = args.remove(0);
        match arg.as_ref() {
            "-port" => {
                opts.port = args.remove(0).parse::<u16>().unwrap();
            }
            "-server" => {
                opts.server = true;
            }
            "-key-file" => {
                opts.key_file = args.remove(0);
            }
            "-cert-file" => {
                opts.cert_file = args.remove(0);
            }
            "-resume-count" => {
                opts.resume_count = args.remove(0).parse::<usize>().unwrap();
            }
           "-no-tls13" => {
                opts.support_tls13 = false;
            }
            "-no-tls12" => {
                opts.support_tls12 = false;
            }
            "-min-version" => {
                let min = args.remove(0).parse::<u16>().unwrap();
                opts.min_version = Some(min);
            }
            "-max-version" => {
                let max = args.remove(0).parse::<u16>().unwrap();
                opts.max_version = Some(max);
            }
            "-max-send-fragment" => {
                println!("not checking {}; disabled for TabbySSL", arg);
                process::exit(BOGO_NACK);
            }
            "-read-size" => {
                opts.read_size = args.remove(0).parse::<usize>().unwrap();
            }
            "-tls13-variant" => {
                let variant = args.remove(0).parse::<u16>().unwrap();
                if variant != 1 {
                    println!("NYI TLS1.3 variant selection: {:?} {:?}", arg, variant);
                    process::exit(BOGO_NACK);
                }
            }
            "-max-cert-list" |
            "-expect-curve-id" |
            "-expect-resume-curve-id" |
            "-expect-peer-signature-algorithm" |
            "-expect-peer-verify-pref" |
            "-expect-advertised-alpn" |
            "-expect-alpn" |
            "-expect-server-name" |
            "-expect-ocsp-response" |
            "-expect-signed-cert-timestamps" |
            "-expect-certificate-types" |
            "-handshaker-path" |
            "-expect-msg-callback" => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }
            "-expect-client-ca-list" => {
                println!("not checking {} {}; NYI; disabled for TabbySSL", arg, args.remove(0));
                process::exit(BOGO_NACK);
            }
            "-expect-secure-renegotiation" |
            "-expect-no-session-id" |
            "-expect-session-id" => {
                println!("not checking {}; NYI", arg);
            }

            "-export-keying-material" |
            "-export-label" |
            "-export-context" |
            "-use-export-context" |
            "-no-ticket" |
            "-on-resume-no-ticket" => {
                println!("not checking {}; disabled for TabbySSL", arg);
                process::exit(BOGO_NACK);
            }

            "-ocsp-response" |
            "-select-alpn" |
            "-require-any-client-certificate" |
            "-verify-peer" |
            "-signed-cert-timestamps" |
            "-advertise-alpn" |
            "-use-null-client-ca-list" |
            "-enable-signed-cert-timestamps" => {
                println!("not checking {}; disabled for TabbySSL", arg);
                process::exit(BOGO_NACK);
            }
            "-enable-early-data" |
            "-on-resume-enable-early-data" => {
                opts.enable_early_data = true;
            }
            "-on-resume-shim-writes-first" => {
                opts.shim_writes_first_on_resume = true;
            }
            "-expect-ticket-supports-early-data" => {
                opts.expect_ticket_supports_early_data = true;
            }
            "-expect-accept-early-data" => {
                opts.expect_accept_early_data = true;
            }
            "-expect-reject-early-data" => {
                opts.expect_reject_early_data = true;
            }
            "-shim-writes-first" => {
                opts.shim_writes_first = true;
            }
            "-shim-shuts-down" => {
                opts.shim_shut_down = true;
            }
            "-check-close-notify" => {
                opts.check_close_notify = true;
            }
            "-host-name" => {
                opts.host_name = args.remove(0);
                opts.use_sni = true;
            }
            "-expect-version" => {
                opts.expect_version = args.remove(0).parse::<u16>().unwrap();
            }

            // defaults:
            "-enable-all-curves" |
            "-renegotiate-ignore" |
            "-no-tls11" |
            "-no-tls1" |
            "-no-ssl3" |
            "-handoff" |
            "-decline-alpn" |
            "-expect-no-session" |
            "-expect-session-miss" |
            "-expect-extended-master-secret" |
            "-expect-ticket-renewal" |
            "-enable-ocsp-stapling" |
            // internal openssl details:
            "-async" |
            "-implicit-handshake" |
            "-use-old-client-cert-callback" |
            "-use-early-callback" => {}

            // Not implemented things
            "-dtls" |
            "-cipher" |
            "-psk" |
            "-renegotiate-freely" |
            "-false-start" |
            "-fallback-scsv" |
            "-fail-early-callback" |
            "-fail-cert-callback" |
            "-install-ddos-callback" |
            "-advertise-npn" |
            "-verify-fail" |
            "-expect-channel-id" |
            "-send-channel-id" |
            "-select-next-proto" |
            "-p384-only" |
            "-expect-verify-result" |
            "-send-alert" |
            "-signing-prefs" |
            "-digest-prefs" |
            "-use-exporter-between-reads" |
            "-ticket-key" |
            "-tls-unique" |
            "-enable-server-custom-extension" |
            "-enable-client-custom-extension" |
            "-expect-dhe-group-size" |
            "-use-ticket-callback" |
            "-enable-grease" |
            "-enable-channel-id" |
            "-resumption-delay" |
            "-expect-early-data-info" |
            "-expect-cipher-aes" |
            "-retain-only-sha256-client-cert-initial" |
            "-use-client-ca-list" |
            "-expect-draft-downgrade" |
            "-allow-unknown-alpn-protos" |
            "-on-initial-tls13-variant" |
            "-on-initial-expect-curve-id" |
            "-enable-ed25519" |
            "-on-resume-export-early-keying-material" |
            "-export-early-keying-material" |
            "-handshake-twice" |
            "-on-resume-verify-fail" |
            "-reverify-on-resume" |
            "-verify-prefs" |
            "-no-op-extra-handshake" |
            "-read-with-unfinished-write" |
            "-on-resume-read-with-unfinished-write" |
            "-expect-peer-cert-file" |
            "-no-rsa-pss-rsae-certs" |
            "-on-initial-expect-peer-cert-file" => {
                println!("NYI option {:?}", arg);
                process::exit(BOGO_NACK);
            }

            _ => {
                println!("unhandled option {:?}", arg);
                process::exit(1);
            }
        }
    }

    if opts.enable_early_data && opts.server {
        println!("For now we only test client-side early data");
        process::exit(BOGO_NACK);
    }

    println!("opts {:?}", opts);

    let ctx = setup_ctx(&opts);

    if ctx.is_null() {
        quit_err("TABBY_SSL_CTX is null");
    }

    for i in 0..opts.resume_count + 1 {
        do_connection(&opts, ctx, i);
    }
    if !ctx.is_null() {
        ssl::tabby_SSL_CTX_free(ctx);
    }
}
