# Description

Simple test of ACERT (Attribute Certificate) support with OpenSSL
and wolfSSL compat layer.

Supports:

- printing
- signing (openssl only)
- verifying

## Contents

- certs (test attribute certs)
- openssl (clone of openssl)
- scripts (useful scripts)
- test (simple test program)
- wolfssl (clone of wolfssl)
- README.md (you'r reading it now)

## Prerequisites

```sh
$ git clone https://github.com/openssl/openssl.git
$ git clone https://github.com/philljj/wolfssl.git
$ cd wolfssl
$ git co x509_acert_support
```

Build openssl and wolfssl with:

```sh
$ ./scripts/openssl/build_openssl
```

```sh
$ ./scripts/wolfssl/build_wolfssl
```

## Building Test

Build test with: `./scripts/test/build_test`.

To build with openssl:
```sh
$./scripts/test/build_test
```

To build with wolfssl:

```sh
$./scripts/test/build_test wolf
```

## ACERT verification with pubkey

```sh
$ ./test/test_acert -f certs/signed/acert.pem -k certs/signed/acert_pubkey.pem
info: using acert file: certs/signed/acert.pem
info: using pubkey file: certs/signed/acert_pubkey.pem
info: holder tag index: 2
info: PEM_read_bio_X509_ACERT: good
info: acert version: 1
info: PEM_read_bio_PUBKEY: good
info: X509_ACERT_verify: good
info: acert_do_test: good
success
```
