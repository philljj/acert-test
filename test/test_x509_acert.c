/* glibc includes */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(USE_WOLFSSL)
  /* wolfssl includes */
  #include <wolfssl/options.h>
  #include <wolfssl/openssl/bio.h>
  #include <wolfssl/openssl/ssl.h>
  #include <wolfssl/ssl.h>
#else
  /* openssl includes */
  #include <openssl/pem.h>
  #include <openssl/rsa.h>
  #include <openssl/x509_acert.h>
#endif

static int  acert_print_usage(void) __attribute__((noreturn));
static int  acert_parse_file(const char * file);
#if defined(USE_WOLFSSL)
static int  acert_parse_attr(const X509_ACERT * x509);
#endif /* if USE_WOLFSSL */
static void acert_dump_hex(const char * what, const byte * data, size_t len);

static int verbose = 0;

int
main(int    argc,
     char * argv[])
{
  const char * file = NULL;
  int          opt = 0;
  int          rc = 0;

  while ((opt = getopt(argc, argv, "f:v?")) != -1) {
    switch (opt) {
    case 'f':
      file = optarg;
      break;

    case 'v':
      verbose = 1;
      break;

    case '?':
    default:
      acert_print_usage();
      break;
    }
  }

  #if defined(USE_WOLFSSL)
  wolfSSL_Init();
  if (verbose) {
    wolfSSL_Debugging_ON();
  }
  #endif /* if USE_WOLFSSL */

  if (file == NULL) {
    printf("info: file: NULL\n");
    return EXIT_FAILURE;
  }

  printf("info: using acert: %s\n", file);

  rc = acert_parse_file(file);

  if (rc) {
    printf("error: acert_parse returned: %d\n", rc);
  }

  return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* Reads and parses an x509 acert from file.
 *
 * Returns: X509_ACERT *   on success.
 * Returns: NULL           on failure.
 * */
static X509_ACERT *
acert_read_print(const char * file)
{
  BIO *        bp = NULL;
  BIO *        bout = NULL;
  X509_ACERT * x509 = NULL;
  int          rc = -1;

  bp = BIO_new_file(file, "r");
  if (bp == NULL) {
    printf("error: BIO_new_file returned: NULL\n");
    goto end_acert_read_print;
  }

  bout = BIO_new_fp(stderr, BIO_NOCLOSE);

  if (bout == NULL) {
    printf("error: BIO_new_fp returned: NULL\n");
    goto end_acert_read_print;
  }

  x509 = PEM_read_bio_X509_ACERT(bp, NULL, NULL, NULL);

  if (x509 == NULL) {
    printf("error: PEM_read_bio_X509_ACERT returned: NULL\n");
    goto end_acert_read_print;
  }

  rc = X509_ACERT_print(bout, x509);

  if (rc != 1) {
    printf("error: X509_ACERT_print returned: %d\n", rc);
  }

  end_acert_read_print:

  if (bp != NULL) {
    BIO_free(bp);
    bp = NULL;
  }

  if (bout != NULL) {
    BIO_free(bout);
    bout = NULL;
  }

  return x509;
}

static int
acert_parse_file(const char * file)
{
  X509_ACERT * x509 = NULL;
  int          rc = 0;

  x509 = acert_read_print(file);

  if (x509 == NULL) {
    printf("error: acert_read_print returned: NULL\n");
    return -1;
  }

  #if defined(USE_WOLFSSL)
  rc = acert_parse_attr(x509);
  if (rc) {
    printf("error: acert_parse_attr returned: %d\n", rc);
  }
  #endif /* if USE_WOLFSSL */

  if (x509 != NULL) {
    X509_ACERT_free(x509);
    x509 = NULL;
  }

  return rc;
}

#if defined(USE_WOLFSSL)
/* Given an x509, retrieves the raw attributes buffer and
 * length, and then parses it.
 *
 * Returns   0  on success.
 * Returns < 0  on error.
 * */
static int
acert_parse_attr(const X509_ACERT * x509)
{
  const byte * attr = NULL;
  word32       attr_len = 0;
  word32       idx = 0;
  word32       max_idx = 0;
  int          seq_len = 0;
  int          rc = 0;

  rc = wolfSSL_X509_ACERT_get_attr_buf(x509, &attr, &attr_len);

  if (rc != 0) {
    printf("error: wolfSSL_X509_ACERT_get_attr_buf returned: %d\n", rc);
    return -1;
  }

  if (attr == NULL || attr_len <= 0) {
    printf("error: attr = %p, attr_len = %d\n", attr, attr_len);
    return -1;
  }

  acert_dump_hex("Attributes", attr, attr_len);

  max_idx = attr_len;

  seq_len = GetSequence(attr + idx, &idx, &seq_len, max_idx);

  if (seq_len <= 0) {
    printf("error: GetSequence(%p, %d, %d, %d) returned: %d\n", attr,
           idx, seq_len, max_idx, rc);
    return -1;
  }
  else {
    printf("info: GetSequence(%p, %d, %d, %d) returned: %d\n", attr,
           idx, seq_len, max_idx, rc);
  }

  return rc;
}
#endif /* if USE_WOLFSSL */

static int
acert_print_usage(void)
{
  printf("usage:\n");
  printf("  ./test/test_acert -f <path to acert file> [-v]\n");
  exit(EXIT_FAILURE);
}

#define BOLDRED    "\033[1m\033[31m"
#define BOLDGREEN  "\033[1m\033[32m"
#define BOLDWHITE  "\033[1m\033[37m"
#define BOLDBLUE   "\033[1m\033[34m"
#define BOLDYELLOW "\033[1m\033[33m"
#define RESET      "\033[0m"

/* Dump data as hex, with some pretty coding
 * of data.
 * */
static void
acert_dump_hex(const char * what,
               const byte * data,
               size_t       len)
{
  uint8_t  seq_list[1024];
  uint16_t n_seq = 0;
  uint8_t  str_list[1024];
  uint16_t n_str = 0;

  memset(str_list, 0, sizeof(str_list));

  printf("\ninfo: %s\n", what);

  for (size_t i = 0; i < len; ++i) {
    if (i % 8 == 0) {
      /* indent first element */
      printf("  ");
    }

    if (data[i] == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
      seq_list[n_seq] = i;
      n_seq++;

      printf(BOLDRED "0x%02x " RESET, data[i]);

      if ((i + 1) % 8 == 0) {
        printf("\n");
      }

      ++i;

      printf(BOLDGREEN "0x%02x " RESET, data[i]);
    }
    else if (data[i] == ASN_PRINTABLE_STRING) {
      str_list[n_str] = i;
      n_str++;

      printf(BOLDBLUE "0x%02x " RESET, data[i]);

      if ((i + 1) % 8 == 0) {
        printf("\n");
      }

      ++i;

      printf(BOLDYELLOW "0x%02x " RESET, data[i]);
    }
    else {
      printf("0x%02x ", data[i]);
    }

    if ((i + 1) % 8 == 0) {
      printf("\n");
    }
  }

  printf("\n\n");

  if (n_seq) {
    printf("constructed sequences\n");

    for (size_t n = 0; n < n_seq; ++n) {
      size_t  i = seq_list[n];
      uint8_t seq_len = data[i + 1];

      printf(BOLDRED "  0x%02x " RESET, data[i]);
      printf(BOLDGREEN "0x%02x " RESET, data[i + 1]);

      for (size_t j = 0; j < seq_len; ++j) {
        if (isalnum(data[i + 2 + j])) {
          printf("%c", data[i + 2 + j]);
        }
        else {
          //printf("%d", data[i + 2 + j]);
          printf(".");
        }
      }
      printf("\n");
    }
  }

  printf("\n");

  if (n_str) {
    printf("printable strings\n");

    for (size_t n = 0; n < n_str; ++n) {
      size_t  i = str_list[n];
      uint8_t str_len = data[i + 1];

      printf(BOLDBLUE "  0x%02x " RESET, data[i]);
      printf(BOLDYELLOW "0x%02x " RESET, data[i + 1]);

      for (size_t j = 0; j < str_len; ++j) {
        printf("%c", data[i + 2 + j]);
      }

      printf("\n");
    }
  }

  printf("\n");

  return;
}
