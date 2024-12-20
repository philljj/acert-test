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
- test (a little attribute cert test program)
- wolfssl (clone of wolfssl)
- README.md (you're reading it now)

## Prerequisites

```sh
$ git clone https://github.com/openssl/openssl.git
$ git clone https://github.com/philljj/wolfssl.git
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

## Unit Tests

Unit test scripts located here:
```sh
$ls scripts/unit/
basic_test  mask_function  salt_len  sign_verify_test
```

Testing OpenSSL and wolfSSL with different mask generation functions:

```sh
$./scripts/unit/mask_function 
  info: test_acert sign verify: mgf1 with sha1: good
  info: test_acert read verify: mgf1 with sha1: good
  info: test_acert read verify (wolf): mgf1 with sha1: good
info: certs/acert.pem: pass

  info: test_acert sign verify: mgf1 with sha224: good
  info: test_acert read verify: mgf1 with sha224: good
  info: test_acert read verify (wolf): mgf1 with sha224: good
info: certs/acert.pem: pass

  info: test_acert sign verify: mgf1 with sha256: good
  info: test_acert read verify: mgf1 with sha256: good
  info: test_acert read verify (wolf): mgf1 with sha256: good
info: certs/acert.pem: pass

  info: test_acert sign verify: mgf1 with sha384: good
  info: test_acert read verify: mgf1 with sha384: good
  info: test_acert read verify (wolf): mgf1 with sha384: good
info: certs/acert.pem: pass

  info: test_acert sign verify: mgf1 with sha512: good
  info: test_acert read verify: mgf1 with sha512: good
  info: test_acert read verify (wolf): mgf1 with sha512: good
info: certs/acert.pem: pass
```

## Examples

### ACERT verification with pubkey

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
### Sign ACERT with RSA-PSS with OpenSSL, verify with wolfSSL

1. Build against openssl:

```sh
$ ./scripts/test/build_test
info: linking against openssl
info: build good
```

2. Use `certs/acert.pem` as input `-f`, and generate new keys and sign `-s`,
   use RSA-PSS `-r`, and write to file `-w`:

```sh
$ ./test/test_acert -f certs/acert.pem -srw
info: using acert file: certs/acert.pem
info: using rsa_pss
info: PEM_read_bio_X509_ACERT: good
info: acert version: 1
info: X509_ACERT_sign: good
info: wrote acert to file: acert_new.pem
info: wrote pubkey to file: pkey_new.pem
info: X509_ACERT_verify: good
info: acert_do_test: good
success
```

3. Rebuild against wolfssl:

```sh
$ ./scripts/test/build_test wolf
info: linking against wolfssl
info: build good
```

4. Finally, test wolfssl verify using newly generated `acert_new.pem` and
   `pkey_new.pem`:
```sh
$ ./test/test_acert -f acert_new.pem -k pkey_new.pem
info: using acert file: acert_new.pem
info: using pubkey file: pkey_new.pem
info: issuer index: 4
info: PEM_read_bio_X509_ACERT: good
info: acert version: 1
info: PEM_read_bio_PUBKEY: good
info: X509_ACERT_verify: good
info: acert_do_test: good
success
```
