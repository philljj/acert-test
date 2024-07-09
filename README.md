# Description

Simple test of ACERT (Attribute Certificate) support with OpenSSL
and wolfSSL compat layer.

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

```sh
$ ./scripts/openssl/build_openssl
```

```sh
$ ./scripts/wolfssl/build_wolfssl
```

## Testing OpenSSL

```sh
$./scripts/test/build_test
$./test/test_acert -f certs/acert.pem
info: using acert: certs/acert.pem
Attribute Certificate:
    Data:
        Version: 2 (0x1)
        Serial Number: 01
        Holder:
            Issuer: CN=TPM Manufacturer
...
```

## Testing wolfSSL

```sh
$./scripts/test/build_test wolf
$$./test/test_acert  -f certs/acert.pem -v
info: using acert: certs/acert.pem
...lots of verbose output...
```

## Unit Tests

```sh
$./scripts/unit/unit_test 
info: certs/acert_bc1.pem: pass
info: certs/acert_bc2.pem: pass
info: certs/acert_ietf.pem: pass
info: certs/acert.pem: pass
```

```sh
$./scripts/unit/unit_test wolf
error: certs/acert_bc1.pem: fail
info: certs/acert_bc2.pem: pass
info: certs/acert_ietf.pem: pass
info: certs/acert.pem: pass
```
