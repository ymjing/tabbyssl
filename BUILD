load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_shared_library", "rust_test")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "tabbyssl_rlib",
    srcs = glob(["src/**/*.rs"]),
    crate_features = [
        "tls12",
        "error_strings",
        "verifier",
    ],
    crate_name = "tabbyssl",
    deps = [
        "//cargo:base64",
        "//cargo:bitflags",
        "//cargo:env_logger",
        "//cargo:lazy_static",
        "//cargo:libc",
        "//cargo:ring",
        "//cargo:rustls",
        "//cargo:rustls_pemfile",
        "//cargo:sct",
        "//cargo:thiserror",
        "//cargo:untrusted",
        "//cargo:webpki",
        "//cargo:webpki_roots",
    ],
)

rust_binary(
    name = "example_simple_client_rs",
    srcs = [
        "examples/simple_client.rs",
    ],
    deps = [
        ":tabbyssl_rlib",
        "//cargo:libc",
        "//cargo:webpki_roots",
    ],
)

rust_shared_library(
    name = "tabbyssl_dylib",
    srcs = glob(["src/**/*.rs"]),
    crate_features = [
        "tls12",
        "error_strings",
        "verifier",
    ],
    deps = [
        "//cargo:base64",
        "//cargo:bitflags",
        "//cargo:env_logger",
        "//cargo:lazy_static",
        "//cargo:libc",
        "//cargo:ring",
        "//cargo:rustls",
        "//cargo:rustls_pemfile",
        "//cargo:sct",
        "//cargo:thiserror",
        "//cargo:untrusted",
        "//cargo:webpki",
        "//cargo:webpki_roots",
    ],
)

rust_test(
    name = "tabbyssl_test",
    srcs = ["tests/ssl.rs"],
    data = ["tests/certs"],
    deps = [
        ":tabbyssl_rlib",
        "//cargo:libc",
    ],
)

cc_library(
    name = "tabbyssl",
    hdrs = ["include/tabbyssl/ssl.h"],
    includes = ["include"],
    deps = [
        ":tabbyssl_dylib",
    ],
)

cc_binary(
    name = "example_simple_client_c",
    srcs = [
        "examples/simple_client.c",
    ],
    deps = [
        ":tabbyssl",
    ],
)
