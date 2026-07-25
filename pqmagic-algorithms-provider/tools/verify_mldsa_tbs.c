/* Test ML-DSA verify: compare raw TBS vs SM3(TBS) as message to pqmagic_ml_dsa_44_std_verify */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <pqmagic_api.h>
/* 与 ASN1_item_verify(X509) 一致：i2d_X509_CINF(&cert_info)，勿用 i2d_re_X509_tbs（会改 enc.modified 并重编码） */
#include "crypto/x509.h"

static void roundtrip_lib(void)
{
    unsigned char pk[ML_DSA_44_PUBLICKEYBYTES], sk[ML_DSA_44_SECRETKEYBYTES];
    unsigned char sig[ML_DSA_44_SIGBYTES];
    size_t slen = sizeof(sig);
    unsigned char msg[32];

    memset(msg, 0x42, sizeof(msg));
    if (pqmagic_ml_dsa_44_std_keypair(pk, sk) != 0) {
        printf("roundtrip: keypair fail\n");
        return;
    }
    if (pqmagic_ml_dsa_44_std_signature(sig, &slen, msg, 32, NULL, 0, sk) != 0) {
        printf("roundtrip: sign fail\n");
        return;
    }
    int v = pqmagic_ml_dsa_44_std_verify(sig, slen, msg, 32, NULL, 0, pk);
    printf("roundtrip keypair->sign(SM3-like 32B)->verify: %d (0=ok)\n", v);
}

static int try_verify(const char *label, X509 *cert, EVP_PKEY *issuer_pk,
                      const unsigned char *m, size_t mlen)
{
    const ASN1_BIT_STRING *sig = NULL;
    X509_get0_signature(&sig, NULL, cert);
    if (!sig) {
        fprintf(stderr, "no signature\n");
        return -1;
    }
    unsigned char pkbuf[4096];
    size_t pklen = 0;
    if (EVP_PKEY_get_octet_string_param(issuer_pk, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        pkbuf, sizeof(pkbuf), &pklen) != 1) {
        fprintf(stderr, "%s: get encoded pk failed\n", label);
        return -1;
    }
    if (pklen != ML_DSA_44_PUBLICKEYBYTES) {
        fprintf(stderr, "%s: pk len %zu\n", label, pklen);
        return -1;
    }
    int r = pqmagic_ml_dsa_44_std_verify(sig->data, (size_t)sig->length, m, mlen,
                                         NULL, 0, pkbuf);
    printf("%s: pqmagic_ml_dsa_44_std_verify -> %d (0=ok)\n", label, r);
    printf("  sig len=%d, mlen=%zu\n", sig->length, mlen);
    return r;
}

int main(int argc, char **argv)
{
    const char *issuer_pem = argc > 1 ? argv[1] : "/home/wang/Desktop/certs/1/root.crt";
    const char *sub_pem = argc > 2 ? argv[2] : "/home/wang/Desktop/certs/1/yunying.crt";

    roundtrip_lib();

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
                            | OPENSSL_INIT_LOAD_CONFIG,
                        NULL);
    if (!OSSL_PROVIDER_load(NULL, "default")) {
        fprintf(stderr, "default provider\n");
        return 1;
    }
    if (!OSSL_PROVIDER_load(NULL, "pqmagic")) {
        fprintf(stderr, "pqmagic provider (set OPENSSL_MODULES to build dir)\n");
        return 1;
    }

    FILE *fp = fopen(issuer_pem, "r");
    X509 *issuer = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = fopen(sub_pem, "r");
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!issuer || !cert) {
        fprintf(stderr, "read pem failed\n");
        return 1;
    }

    EVP_PKEY *issuer_pk = X509_get0_pubkey(issuer);
    if (!issuer_pk) {
        fprintf(stderr, "issuer pubkey\n");
        return 1;
    }

    unsigned char *tbs = NULL;
    struct x509_st *xc = (struct x509_st *)cert;
    int tbslen = i2d_X509_CINF(&xc->cert_info, &tbs);
    if (tbslen <= 0 || !tbs) {
        fprintf(stderr, "i2d_X509_CINF\n");
        return 1;
    }

    unsigned char sm3[32];
    unsigned int sm3l = sizeof(sm3);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sm3(), NULL);
    EVP_DigestUpdate(md, tbs, (size_t)tbslen);
    EVP_DigestFinal_ex(md, sm3, &sm3l);
    EVP_MD_CTX_free(md);

    printf("=== %s signed by %s ===\n", sub_pem, issuer_pem);
    try_verify("raw TBS", cert, issuer_pk, tbs, (size_t)tbslen);
    try_verify("SM3(TBS)", cert, issuer_pk, sm3, 32);

    OPENSSL_free(tbs);
    return 0;
}
