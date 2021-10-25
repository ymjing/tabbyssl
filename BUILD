load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "tabbyssl_rlib",
    srcs = glob(["src/**/*.rs"]),
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
    ]
)

rust_binary(
    name = "example_simple_client",
    srcs = [
        "examples/simple_client.rs"
    ],
    deps = [
        ":tabbyssl_rlib",
        "//cargo:libc",
        "//cargo:webpki_roots",
    ]
)
