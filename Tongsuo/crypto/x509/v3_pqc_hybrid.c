/*
 * Hybrid SM2+PQC certificate extensions (1.2.156.10260.4.1.6/7/8)
 * Readable printing for openssl x509 -text (hex dump, no binary garbage).
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include "ext_dat.h"

/*
 * extnValue 为裸 DER（SPKI / AlgorithmIdentifier / 签名），不是 OCTET STRING
 * 标签包裹；用自定义 d2i 原样装入 OCTET STRING 供 i2r 打印。
 */
static void *pqc_raw_ext_d2i(ASN1_OCTET_STRING **a, const unsigned char **in,
                             long len)
{
    ASN1_OCTET_STRING *os;

    if (in == NULL || *in == NULL || len < 0)
        return NULL;
    os = ASN1_OCTET_STRING_new();
    if (os == NULL)
        return NULL;
    if (!ASN1_OCTET_STRING_set(os, *in, len)) {
        ASN1_OCTET_STRING_free(os);
        return NULL;
    }
    *in += len;
    if (a != NULL)
        *a = os;
    return os;
}

static int print_hex_full(BIO *out, const unsigned char *data, int len, int indent)
{
    int i;

    if (data == NULL || len <= 0) {
        if (BIO_printf(out, "%*s<empty>\n", indent, "") <= 0)
            return 0;
        return 1;
    }
    for (i = 0; i < len; i++) {
        if (i % 16 == 0 && BIO_printf(out, "%*s", indent, "") <= 0)
            return 0;
        if (BIO_printf(out, "%02x%s", data[i],
                       (i + 1) % 16 == 0 ? "\n" :
                       (i + 1) % 8 == 0 ? "  " : " ") <= 0)
            return 0;
    }
    if (len % 16 != 0 && BIO_puts(out, "\n") <= 0)
        return 0;
    return 1;
}

static int i2r_pqc_octet_common(BIO *out, ASN1_OCTET_STRING *oct, int indent,
                                const char *title)
{
    const unsigned char *p;
    int len;

    if (oct == NULL)
        return 0;
    p = ASN1_STRING_get0_data(oct);
    len = ASN1_STRING_length(oct);
    if (BIO_printf(out, "%*s%s (%d bytes):\n", indent, "", title, len) <= 0)
        return 0;
    return print_hex_full(out, p, len, indent + 4);
}

static int i2r_pqc_subject_pubkey(X509V3_EXT_METHOD *method, void *ext, BIO *out,
                                  int indent)
{
    ASN1_OCTET_STRING *oct = ext;
    const unsigned char *p, *q;
    int len, ok = 1;
    X509_PUBKEY *xp = NULL;
    ASN1_OBJECT *alg = NULL;
    const unsigned char *pk;
    int pklen;

    (void)method;
    if (oct == NULL)
        return 0;
    p = ASN1_STRING_get0_data(oct);
    len = ASN1_STRING_length(oct);
    if (BIO_printf(out, "%*sPQC Subject Public Key (extension 4.1.6, %d bytes):\n",
                   indent, "", len) <= 0)
        return 0;

    q = p;
    xp = d2i_X509_PUBKEY(NULL, &q, len);
    if (xp != NULL) {
        X509_ALGOR *palg = NULL;

        if (X509_PUBKEY_get0_param(NULL, &pk, &pklen, &palg, xp)) {
            if (pklen > 0 && pk[0] == 0) {
                pk++;
                pklen--;
            }
            if (palg != NULL) {
                X509_ALGOR_get0((const ASN1_OBJECT **)&alg, NULL, NULL, palg);
                if (alg != NULL) {
                    if (BIO_printf(out, "%*sAlgorithm: ", indent + 4, "") <= 0
                        || i2a_ASN1_OBJECT(out, alg) <= 0
                        || BIO_puts(out, "\n") <= 0)
                        ok = 0;
                }
            }
            if (ok
                && BIO_printf(out, "%*sRaw public key: %d bytes\n",
                              indent + 4, "", pklen) <= 0)
                ok = 0;
        }
        X509_PUBKEY_free(xp);
        if (ok) {
            if (BIO_printf(out, "%*sExtension OCTET (full DER):\n",
                           indent + 4, "") <= 0)
                return 0;
            return print_hex_full(out, p, len, indent + 8);
        }
    }

    if (BIO_printf(out, "%*s(inner SPKI parse failed, hex dump)\n",
                   indent + 4, "") <= 0)
        return 0;
    return print_hex_full(out, p, len, indent + 4);
}

static int i2r_pqc_sig_algorithm(X509V3_EXT_METHOD *method, void *ext, BIO *out,
                                 int indent)
{
    ASN1_OCTET_STRING *oct = ext;
    const unsigned char *p, *q;
    int len;
    X509_ALGOR *algor = NULL;

    (void)method;
    if (oct == NULL)
        return 0;
    p = ASN1_STRING_get0_data(oct);
    len = ASN1_STRING_length(oct);
    q = p;
    algor = d2i_X509_ALGOR(NULL, &q, len);
    if (algor != NULL) {
        if (BIO_printf(out, "%*sPQC Signature Algorithm (extension 4.1.7):\n",
                       indent, "") <= 0) {
            X509_ALGOR_free(algor);
            return 0;
        }
        if (BIO_printf(out, "%*s", indent + 4, "") <= 0
            || i2a_ASN1_OBJECT(out, algor->algorithm) <= 0
            || BIO_puts(out, "\n") <= 0) {
            X509_ALGOR_free(algor);
            return 0;
        }
        X509_ALGOR_free(algor);
        return 1;
    }
    return i2r_pqc_octet_common(out, oct, indent,
                               "PQC Signature Algorithm (extension 4.1.7)");
}

static int i2r_pqc_signature_value(X509V3_EXT_METHOD *method, void *ext,
                                   BIO *out, int indent)
{
    ASN1_OCTET_STRING *oct = ext;
    const unsigned char *p;
    int len;

    (void)method;
    if (oct == NULL)
        return 0;
    p = ASN1_STRING_get0_data(oct);
    len = ASN1_STRING_length(oct);
    if (BIO_printf(out, "%*sPQC Signature Value (extension 4.1.8, %d bytes",
                   indent, "", len) <= 0)
        return 0;
    if (len == 2420 && BIO_puts(out, ", ML-DSA-44") <= 0)
        return 0;
    if (BIO_puts(out, "):\n") <= 0)
        return 0;
    return print_hex_full(out, p, len, indent + 4);
}

#define PQC_HYBRID_EXT_METHOD(nid, i2r_func) \
    { \
        nid, X509V3_EXT_MULTILINE, \
        NULL, \
        NULL, (X509V3_EXT_FREE)ASN1_OCTET_STRING_free, \
        (X509V3_EXT_D2I)pqc_raw_ext_d2i, NULL, \
        NULL, NULL, NULL, NULL, \
        (X509V3_EXT_I2R)i2r_func, NULL, NULL \
    }

const X509V3_EXT_METHOD ossl_v3_ext_pqc_subject_pubkey =
    PQC_HYBRID_EXT_METHOD(NID_PQC_Subject_Public_Key, i2r_pqc_subject_pubkey);

const X509V3_EXT_METHOD ossl_v3_ext_pqc_sig_algorithm =
    PQC_HYBRID_EXT_METHOD(NID_PQC_Signature_Algorithm, i2r_pqc_sig_algorithm);

const X509V3_EXT_METHOD ossl_v3_ext_pqc_signature_value =
    PQC_HYBRID_EXT_METHOD(NID_PQC_Signature_Value, i2r_pqc_signature_value);
