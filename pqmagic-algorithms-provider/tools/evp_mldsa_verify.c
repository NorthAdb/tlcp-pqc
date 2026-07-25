/* EVP 路径应与 ASN1_item_verify / openssl verify 一致 */
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "crypto/x509.h"

int main(void)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    OSSL_PROVIDER_load(NULL, "default");
    if (!OSSL_PROVIDER_load(NULL, "pqmagic")) {
        fprintf(stderr, "load pqmagic (OPENSSL_MODULES=build dir)\n");
        return 1;
    }

    FILE *fp = fopen("/home/wang/Desktop/certs/1/root.crt", "r");
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert)
        return 1;

    EVP_PKEY *pk = X509_get0_pubkey(cert);
    if (!pk) {
        fprintf(stderr, "no pubkey\n");
        return 1;
    }

    unsigned char *tbs = NULL;
    struct x509_st *xc = (struct x509_st *)cert;
    int tbslen = i2d_X509_CINF(&xc->cert_info, &tbs);
    if (tbslen <= 0 || !tbs) {
        fprintf(stderr, "tbs\n");
        return 1;
    }

    const ASN1_BIT_STRING *sig = NULL;
    X509_get0_signature(&sig, NULL, cert);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    /* 与 ASN1_item_verify_ex 一致：mdname + libctx + props + pkey */
    if (!EVP_DigestVerifyInit_ex(ctx, NULL, "SM3", NULL, NULL, pk, NULL)) {
        fprintf(stderr, "DigestVerifyInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int ok1 = EVP_DigestVerifyUpdate(ctx, tbs, (size_t)tbslen);
    int ok2 = EVP_DigestVerifyFinal(ctx, sig->data, (size_t)sig->length);
    printf("Update=%d Final=%d (1=ok each)\n", ok1, ok2);
    if (ok2 != 1)
        ERR_print_errors_fp(stderr);

    int ok3 = EVP_DigestVerify(ctx, sig->data, (size_t)sig->length, tbs, (size_t)tbslen);
    printf("EVP_DigestVerify one-shot: %d (1=ok)\n", ok3);
    if (ok3 != 1)
        ERR_print_errors_fp(stderr);

    EVP_MD_CTX_free(ctx);
    OPENSSL_free(tbs);
    return (ok2 == 1 && ok3 == 1) ? 0 : 2;
}
