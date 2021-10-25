/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 * All rights reserved.
 */

extern crate tabbyssl;

use std::os::unix::io::AsRawFd;
use std::{net, str};
use tabbyssl::libssl::ssl::*;

fn main() {
    const HTTP_REQUEST: &[u8; 82] = b"GET / HTTP/1.1\r\n\
            Host: google.com\r\n\
            Connection: close\r\n\
            Accept-Encoding: identity\r\n\
            \r\n";

    let method = tabby_TLS_client_method();
    let ctx = tabby_SSL_CTX_new(method);
    let ssl = tabby_SSL_new(ctx);
    tabby_SSL_set_tlsext_host_name(ssl, b"google.com\0".as_ptr() as *const libc::c_char);
    let sock = net::TcpStream::connect("google.com:443").expect("Connect error");
    let _ret = tabby_SSL_set_fd(ssl, sock.as_raw_fd());
    let _ret = tabby_SSL_connect(ssl);
    let wr_len = tabby_SSL_write(ssl, HTTP_REQUEST.as_ptr() as *const libc::c_uchar, 82);
    eprintln!("Written {} bytes", wr_len);
    let buf = [0u8; 256];
    let rd_len = tabby_SSL_read(ssl, buf.as_ptr() as *mut libc::c_uchar, 256);
    eprintln!("Read {} bytes", rd_len);
    eprintln!("{}", str::from_utf8(&buf).unwrap());
    tabby_SSL_free(ssl);
    tabby_SSL_CTX_free(ctx);
}