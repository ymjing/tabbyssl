<p align="center"><img src="logo.png" height="86" /></p>
<h1 align="center">OpenSSL compatibility layer for the Rust SSL/TLS stack</h1>

[![Build Status](https://travis-ci.com/ymjing/tabbyssl.svg?branch=master)](https://travis-ci.com/ymjing/tabbyssl)
[![Build Status](https://dev.azure.com/tabbyssl/TabbySSL/_apis/build/status/ymjing.tabbyssl?branchName=master)](https://dev.azure.com/tabbyssl/TabbySSL/_build/latest?definitionId=1&branchName=master)
[![Coverage Status](https://codecov.io/gh/ymjing/tabbyssl/branch/master/graph/badge.svg)](https://codecov.io/gh/ymjing/tabbyssl)
[![Release](https://img.shields.io/github/release/ymjing/tabbyssl.svg)](https://github.com/ymjing/tabbyssl/releases)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

Previously [MesaLink](https://mesalink.io), **TabbySSL** is an OpenSSL compatibility
layer for the Rust SSL/TLS stack.

## Release history
* 0.10.0 (11/24/2019)
  - Forked from the master branch of MesaLink

## Supported ciphersuites
> Same as rustls

* TLS13-CHACHA20-POLY1305-SHA256
* TLS13-AES-256-GCM-SHA384
* TLS13-AES-128-GCM_SHA256
* TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256
* TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256
* TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
* TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
* TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
* TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

## Building instructions for Autotools

```
$ sudo apt-get install m4 autoconf automake libtool make gcc curl
$ curl https://sh.rustup.rs -sSf | sh

$ git clone https://github.com/ymjing/tabbyssl.git
$ ./autogen.sh --enable-examples
$ make
```

## Building instructions for CMake

```
$ sudo apt-get install cmake make gcc curl
$ curl https://sh.rustup.rs -sSf | sh

$ git clone https://github.com/ymjing/tabbyssl.git
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
```

## Examples
To enable examples, use `configure --enable-examples` or `cmake
-DHAVE_EXAMPLES=on`.

```
$ ./examples/client/client api.ipify.org
[+] Negotiated ciphersuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, enc_length=16, version=TLS1.2
[+] Subject name: /OU=Domain Control Validated/OU=PositiveSSL Wildcard/CN=*.ipify.org
[+] Subject alternative names:*.ipify.org ipify.org
[+] Sent 85 bytes

GET / HTTP/1.0
Host: api.ipify.org
Connection: close
Accept-Encoding: identity


HTTP/1.1 200 OK
Server: Cowboy
Connection: close
Content-Type: text/plain
Vary: Origin
Date: Thu, 09 Aug 2018 21:44:35 GMT
Content-Length: 10
Via: 1.1 vegur

1.2.3.4
[+] TLS protocol version: TLS1.2

[+] Received 177 bytes
```

```
$ ./examples/server/server
Usage: ./examples/server/server <portnum> <cert_file> <private_key_file>
$ cd examples/server/server
$ ./server 8443 certificates private_key
[+] Listening at 0.0.0.0:8443
[+] Negotiated ciphersuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, enc_length=16, version=TLS1.2
[+] Received:
GET / HTTP/1.1
Host: 127.0.0.1:8443
Connection: keep-alive
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
```

## Acknowledgments
TabbySSL/MesaLink would not have been possible without the following
high-quality open source projects in the Rust community. Thanks for code and
inspiration!

  * `rustls`: A modern TLS library in Rust, maintained by Joseph Birr-Pixton
    [@ctz](https://github.com/ctz)
  * `sct.rs`: Certificate transparency SCT verification library in rust,
    maintained by Joseph Birr-Pixton [@ctz](https://github.com/ctz)
  * `ring`: Safe, fast, small crypto using Rust, by Brian Smith
    [@briansmith](https://github.com/briansmith)
  * `webpki`: WebPKI X.509 Certificate Validation in Rust, maintained by Brian
    Smith [@briansmith](https://github.com/briansmith)

## Maintainer

 * 2019.11 - Present: Yiming Jing `<yjing@apache.org>` [@ymjing](https://github.com/ymjing)

## License
TabbySSL is provided under the 3-Clause BSD license. For a copy, see the LICENSE
file.
