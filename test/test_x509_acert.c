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

static int verbose = 0;

int
main(int    argc,
     char * argv[])
{
  const char * acert_file = NULL;
  int          opt = 0;
  BIO *        bp = NULL;
  BIO *        bout = NULL;
  X509_ACERT * acert = NULL;
  int          rc = 0;

  while ((opt = getopt(argc, argv, "f:v?")) != -1) {
    switch (opt) {
    case 'f':
      acert_file = optarg;
      break;

    case 'v':
      verbose = 1;
      break;

    case '?':
      break;
    }
  }

  #if defined(USE_WOLFSSL)
  wolfSSL_Init();
  if (verbose) {
    wolfSSL_Debugging_ON();
  }
  #endif

  if (acert_file == NULL) {
    printf("info: acert_file: NULL\n");
    return EXIT_FAILURE;
  }

  printf("info: using acert: %s\n", acert_file);

  bp = BIO_new_file(acert_file, "r");
  if (bp == NULL) {
    printf("error: BIO_new_file returned: NULL\n");
    return EXIT_FAILURE;
  }

  bout = BIO_new_fp(stderr, BIO_NOCLOSE);

  if (bout == NULL) {
    printf("error: BIO_new_fp returned: NULL\n");
    return EXIT_FAILURE;
  }

  acert = PEM_read_bio_X509_ACERT(bp, NULL, NULL, NULL);

  if (acert == NULL) {
    printf("error: PEM_read_bio_X509_ACERT returned: NULL\n");
    return EXIT_FAILURE;
  }

  rc = X509_ACERT_print(bout, acert);

  if (rc != 1) {
    printf("error: X509_ACERT_print returned: %d\n", rc);
    return EXIT_FAILURE;
  }

  if (bp != NULL) {
    BIO_free(bp);
    bp = NULL;
  }

  if (bout != NULL) {
    BIO_free(bout);
    bout = NULL;
  }

  if (acert != NULL) {
    X509_ACERT_free(acert);
    acert = NULL;
  }

  return EXIT_SUCCESS;
}
