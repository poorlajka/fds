
/*
 *  Certificate generation and signing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"
/* md.h is included this early since MD_CAN_XXX macros are defined there. */
#include "mbedtls/md.h"

#include "combiner.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/oid.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "test/helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SET_OID(x, oid) \
    do { x.len = MBEDTLS_OID_SIZE(oid); x.p = (unsigned char *) oid; } while (0)

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_ISSUER_CRT          ""
#define DFL_REQUEST_FILE        ""
#define DFL_SUBJECT_KEY         "subject.key"
#define DFL_ISSUER_KEY          "ca.key"
#define DFL_SUBJECT_PWD         ""
#define DFL_ISSUER_PWD          ""
#define DFL_OUTPUT_FILENAME     "cert.crt"
#define DFL_SUBJECT_NAME        "CN=Cert,O=mbed TLS,C=UK"
#define DFL_ISSUER_NAME         "CN=CA,O=mbed TLS,C=UK"
#define DFL_NOT_BEFORE          "20010101000000"
#define DFL_NOT_AFTER           "20301231235959"
#define DFL_SERIAL              "1"
#define DFL_SERIAL_HEX          "1"
#define DFL_EXT_SUBJECTALTNAME  ""
#define DFL_SELFSIGN            1
#define DFL_IS_CA               1
#define DFL_MAX_PATHLEN         0
#define DFL_SIG_ALG             MBEDTLS_MD_SHA256
#define DFL_KEY_USAGE           0
#define DFL_EXT_KEY_USAGE       NULL
#define DFL_NS_CERT_TYPE        0
#define DFL_VERSION             3
#define DFL_AUTH_IDENT          1
#define DFL_SUBJ_IDENT          1
#define DFL_CONSTRAINTS         1
#define DFL_DIGEST              MBEDTLS_MD_SHA256
#define DFL_FORMAT              FORMAT_PEM

typedef enum {
    SERIAL_FRMT_UNSPEC,
    SERIAL_FRMT_DEC,
    SERIAL_FRMT_HEX
} serial_format_t;

/*
 * global options
 */
struct options {
    const char *issuer_crt;     /* filename of the issuer certificate   */
    const char *request_file;   /* filename of the certificate request  */
    const char *subject_key;    /* filename of the subject key file     */
    const char *issuer_key;     /* filename of the issuer key file      */
    const char *subject_pwd;    /* password for the subject key file    */
    const char *issuer_pwd;     /* password for the issuer key file     */
    const char *output_file;    /* where to store the constructed CRT   */
    const char *subject_name;   /* subject name for certificate         */
    mbedtls_x509_san_list *san_list; /* subjectAltName for certificate  */
    const char *issuer_name;    /* issuer name for certificate          */
    const char *not_before;     /* validity period not before           */
    const char *not_after;      /* validity period not after            */
    const char *serial;         /* serial number string (decimal)       */
    const char *serial_hex;     /* serial number string (hex)           */
    int selfsign;               /* selfsign the certificate             */
    int is_ca;                  /* is a CA certificate                  */
    int max_pathlen;            /* maximum CA path length               */
    int authority_identifier;   /* add authority identifier to CRT      */
    int subject_identifier;     /* add subject identifier to CRT        */
    int basic_constraints;      /* add basic constraints ext to CRT     */
    int version;                /* CRT version                          */
    mbedtls_md_type_t md;       /* Hash used for signing                */
    unsigned char key_usage;    /* key usage flags                      */
    mbedtls_asn1_sequence *ext_key_usage; /* extended key usages        */
    unsigned char ns_cert_type; /* NS cert type                         */
    int format;                 /* format                               */
    scheme_t* schemes;
    combiner_t combiner;
    size_t hybrid_len;
} opt;

static int write_certificate(mbedtls_x509write_cert *crt, const char *output_file,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    unsigned char *output_start;
    size_t len = 0;

    memset(output_buf, 0, 4096);
    if (opt.format == FORMAT_DER) {
        ret = mbedtls_x509write_crt_der(crt, output_buf, 4096,
                                        f_rng, p_rng);
        if (ret < 0) {
            return ret;
        }

        len = ret;
        output_start = output_buf + 4096 - len;
    } else {
        ret = mbedtls_x509write_crt_pem(crt, output_buf, 4096,
                                        f_rng, p_rng);
        if (ret < 0) {
            return ret;
        }

        len = strlen((char *) output_buf);
        output_start = output_buf;
    }

    if ((f = fopen(output_file, "w")) == NULL) {
        return -1;
    }

    if (fwrite(output_start, 1, len, f) != len) {
        fclose(f);
        return -1;
    }

    fclose(f);

    return 0;
}

static int parse_serial_decimal_format(unsigned char *obuf, size_t obufmax,
                                       const char *ibuf, size_t *len)
{
    unsigned long long int dec;
    unsigned int remaining_bytes = sizeof(dec);
    unsigned char *p = obuf;
    unsigned char val;
    char *end_ptr = NULL;

    errno = 0;
    dec = strtoull(ibuf, &end_ptr, 10);

    if ((errno != 0) || (end_ptr == ibuf)) {
        return -1;
    }

    *len = 0;

    while (remaining_bytes > 0) {
        if (obufmax < (*len + 1)) {
            return -1;
        }

        val = (dec >> ((remaining_bytes - 1) * 8)) & 0xFF;

        /* Skip leading zeros */
        if ((val != 0) || (*len != 0)) {
            *p = val;
            (*len)++;
            p++;
        }

        remaining_bytes--;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                       *subject_key = &loaded_subject_key;
    char buf[1024];
    int i;
    char *p, *q;
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr csr;
#endif
    mbedtls_x509write_cert crt;
    serial_format_t serial_frmt = SERIAL_FRMT_UNSPEC;
    unsigned char serial[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN];
    size_t serial_len;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "crt example app";
    mbedtls_asn1_named_data *ext_san_dirname = NULL;
    /*
     * Set to sane values
     */
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_init(&loaded_issuer_key);
    mbedtls_pk_init(&loaded_subject_key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_init(&csr);
#endif
    mbedtls_x509_crt_init(&issuer_crt);
    memset(buf, 0, sizeof(buf));
    memset(serial, 0, sizeof(serial));

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (argc < 2) {
        goto exit;
    }

    opt.issuer_crt          = DFL_ISSUER_CRT;
    opt.request_file        = DFL_REQUEST_FILE;
    opt.subject_key         = DFL_SUBJECT_KEY;
    opt.issuer_key          = DFL_ISSUER_KEY;
    opt.subject_pwd         = DFL_SUBJECT_PWD;
    opt.issuer_pwd          = DFL_ISSUER_PWD;
    opt.output_file         = DFL_OUTPUT_FILENAME;
    opt.subject_name        = DFL_SUBJECT_NAME;
    opt.issuer_name         = DFL_ISSUER_NAME;
    opt.not_before          = DFL_NOT_BEFORE;
    opt.not_after           = DFL_NOT_AFTER;
    opt.serial              = DFL_SERIAL;
    opt.serial_hex          = DFL_SERIAL_HEX;
    opt.selfsign            = DFL_SELFSIGN;
    opt.is_ca               = DFL_IS_CA;
    opt.max_pathlen         = DFL_MAX_PATHLEN;
    opt.key_usage           = DFL_KEY_USAGE;
    opt.ext_key_usage       = DFL_EXT_KEY_USAGE;
    opt.ns_cert_type        = DFL_NS_CERT_TYPE;
    opt.version             = DFL_VERSION - 1;
    opt.md                  = DFL_DIGEST;
    opt.subject_identifier   = DFL_SUBJ_IDENT;
    opt.authority_identifier = DFL_AUTH_IDENT;
    opt.basic_constraints    = DFL_CONSTRAINTS;
    opt.format              = DFL_FORMAT;
    opt.san_list            = NULL;

    for (i = 1; i < argc; i++) {
        p = argv[i];
        if ((q = strchr(p, '=')) == NULL) {
            return 0;
        }
        *q++ = '\0';

        if (strcmp(p, "issuer_key") == 0) {
            opt.issuer_key = q;
        } 
        else if (strcmp(p, "output_file") == 0) {
            opt.output_file = q;
        }
        else if (strcmp(p, "combiner") == 0) {
            if (strcmp(q, "CONCATENATION") == 0) {
                opt.combiner = CONCATENATION;
            }
            else if (strcmp(q, "STRONG_NESTING") == 0) {
                opt.combiner = STRONG_NESTING;
            }
        }
        else if (strcmp(p, "hybrid_len") == 0) {
            opt.hybrid_len = atoi(q);
            opt.schemes = malloc(sizeof(scheme_t) * opt.hybrid_len);
        }
        else if (strcmp(p, "schemes") == 0) {
            char* token;
            for (size_t j = 0; j < opt.hybrid_len; ++j) {
                token = strtok(q, ",");
                opt.schemes[j] = str_to_scheme_t(token);
            }
        }
    }
    mbedtls_printf("\n");

    /*
     * 0. Seed the PRNG
     */
    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_printf(" failed\n  !  mbedtls_ctr_drbg_seed returned %d - %s\n",
                       ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    // Parse serial to MPI
    //
    mbedtls_printf("  . Reading serial number...");
    fflush(stdout);

    if (serial_frmt == SERIAL_FRMT_HEX) {
        ret = mbedtls_test_unhexify(serial, sizeof(serial),
                                    opt.serial_hex, &serial_len);
    } else { // SERIAL_FRMT_DEC || SERIAL_FRMT_UNSPEC
        ret = parse_serial_decimal_format(serial, sizeof(serial),
                                          opt.serial, &serial_len);
    }

    if (ret != 0) {
        mbedtls_printf(" failed\n  !  Unable to parse serial\n");
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Loading the issuer key ...");
    fflush(stdout);

    /*
    ret = mbedtls_pk_parse_keyfile(&loaded_issuer_key, opt.issuer_key,
                                   opt.issuer_pwd, mbedtls_ctr_drbg_random, &ctr_drbg);
                                   */

    const mbedtls_pk_info_t *pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_PQC_HYBRID);
    mbedtls_pk_setup(issuer_key, pk_info);
    hybrid_t hybrid = {
        .len = opt.hybrid_len,
        .schemes = opt.schemes,
        .combiner = opt.combiner,
    };
    combiner_read_keypair(&hybrid, opt.issuer_key);
    /*
        TODO: This breaks the encapsulation and disregards the intended api.
        It is not the proper way to do it but for now I do it like this :)
    */
    issuer_key->private_pk_ctx = &hybrid;

    if (ret != 0) {
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile "
                       "returned -x%02x - %s\n\n", (unsigned int) -ret, buf);
        goto exit;
    }

    if (opt.selfsign) {
        opt.subject_name = opt.issuer_name;
        subject_key = issuer_key;
    }

    mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

    /*
     * 1.0. Check the names for validity
     */
    if ((ret = mbedtls_x509write_crt_set_subject_name(&crt, opt.subject_name)) != 0) {
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_subject_name "
                       "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
        goto exit;
    }

    if ((ret = mbedtls_x509write_crt_set_issuer_name(&crt, opt.issuer_name)) != 0) {
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_issuer_name "
                       "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
        goto exit;
    }

    mbedtls_printf("  . Setting certificate values ...");
    fflush(stdout);

    mbedtls_x509write_crt_set_version(&crt, opt.version);
    mbedtls_x509write_crt_set_md_alg(&crt, opt.md);

    ret = mbedtls_x509write_crt_set_serial_raw(&crt, serial, serial_len);
    if (ret != 0) {
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_serial_raw "
                       "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
        goto exit;
    }

    ret = mbedtls_x509write_crt_set_validity(&crt, opt.not_before, opt.not_after);
    if (ret != 0) {
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_validity "
                       "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    if (opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.basic_constraints != 0) {
        mbedtls_printf("  . Adding the Basic Constraints extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_basic_constraints(&crt, opt.is_ca,
                                                          opt.max_pathlen);
        if (ret != 0) {
            mbedtls_strerror(ret, buf, sizeof(buf));
            mbedtls_printf(" failed\n  !  x509write_crt_set_basic_constraints "
                           "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

#if defined(PSA_WANT_ALG_SHA_1)
    if (opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.subject_identifier != 0) {
        mbedtls_printf("  . Adding the Subject Key Identifier ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
        if (ret != 0) {
            mbedtls_strerror(ret, buf, sizeof(buf));
            mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_subject"
                           "_key_identifier returned -0x%04x - %s\n\n",
                           (unsigned int) -ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    if (opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.authority_identifier != 0) {
        mbedtls_printf("  . Adding the Authority Key Identifier ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
        if (ret != 0) {
            mbedtls_strerror(ret, buf, sizeof(buf));
            mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_authority_"
                           "key_identifier returned -0x%04x - %s\n\n",
                           (unsigned int) -ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }
#endif /* PSA_WANT_ALG_SHA_1 */

    if (opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.key_usage != 0) {
        mbedtls_printf("  . Adding the Key Usage extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_key_usage(&crt, opt.key_usage);
        if (ret != 0) {
            mbedtls_strerror(ret, buf, sizeof(buf));
            mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_key_usage "
                           "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    if (opt.san_list != NULL) {
        ret = mbedtls_x509write_crt_set_subject_alternative_name(&crt, opt.san_list);

        if (ret != 0) {
            mbedtls_printf(
                " failed\n  !  mbedtls_x509write_crt_set_subject_alternative_name returned %d",
                ret);
            goto exit;
        }
    }

    if (opt.ext_key_usage) {
        mbedtls_printf("  . Adding the Extended Key Usage extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_ext_key_usage(&crt, opt.ext_key_usage);
        if (ret != 0) {
            mbedtls_strerror(ret, buf, sizeof(buf));
            mbedtls_printf(
                " failed\n  !  mbedtls_x509write_crt_set_ext_key_usage returned -0x%02x - %s\n\n",
                (unsigned int) -ret,
                buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    if (opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.ns_cert_type != 0) {
        mbedtls_printf("  . Adding the NS Cert Type extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_ns_cert_type(&crt, opt.ns_cert_type);
        if (ret != 0) {
            mbedtls_strerror(ret, buf, sizeof(buf));
            mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_ns_cert_type "
                           "returned -0x%04x - %s\n\n", (unsigned int) -ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    /*
     * 1.2. Writing the certificate
     */
    mbedtls_printf("  . Writing the certificate...");
    fflush(stdout);

    if ((ret = write_certificate(&crt, opt.output_file,
                                 mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_printf(" failed\n  !  write_certificate -0x%04x - %s\n\n",
                       (unsigned int) -ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_free(&csr);
#endif /* MBEDTLS_X509_CSR_PARSE_C */
    mbedtls_asn1_free_named_data_list(&ext_san_dirname);
    mbedtls_x509_crt_free(&issuer_crt);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&loaded_subject_key);
    mbedtls_pk_free(&loaded_issuer_key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    mbedtls_exit(exit_code);
}
