#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#ifndef AIGIS_ENC_PROVIDER_SO
#define AIGIS_ENC_PROVIDER_SO "./aigis_enc.so"
#endif

int main(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    size_t ctlen = 0, ss1len = 0, ss2len = 0;
    int ret = 1;

    if (libctx == NULL)
        return 1;

    prov = OSSL_PROVIDER_load(libctx, AIGIS_ENC_PROVIDER_SO);
    if (prov == NULL) {
        fprintf(stderr, "OSSL_PROVIDER_load(%s) failed\n", AIGIS_ENC_PROVIDER_SO);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    pctx = EVP_PKEY_CTX_new_from_name(libctx, "Aigis-Enc-2", "provider=aigis_enc");
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL || EVP_PKEY_encapsulate_init(pctx, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_encapsulate_init failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    if (EVP_PKEY_encapsulate(pctx, NULL, &ctlen, NULL, &ss1len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encapsulate (sizes) failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    ct = OPENSSL_malloc(ctlen);
    ss1 = OPENSSL_malloc(ss1len);
    if (ct == NULL || ss1 == NULL) {
        fprintf(stderr, "malloc failed\n");
        goto end;
    }
    if (EVP_PKEY_encapsulate(pctx, ct, &ctlen, ss1, &ss1len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encapsulate failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL || EVP_PKEY_decapsulate_init(pctx, NULL) <= 0) {
        fprintf(stderr, "EVP_PKEY_decapsulate_init failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    if (EVP_PKEY_decapsulate(pctx, NULL, &ss2len, ct, ctlen) <= 0) {
        fprintf(stderr, "EVP_PKEY_decapsulate (size) failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    ss2 = OPENSSL_malloc(ss2len);
    if (ss2 == NULL) {
        fprintf(stderr, "malloc failed\n");
        goto end;
    }
    if (EVP_PKEY_decapsulate(pctx, ss2, &ss2len, ct, ctlen) <= 0) {
        fprintf(stderr, "EVP_PKEY_decapsulate failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (ss1len != ss2len || memcmp(ss1, ss2, ss1len) != 0) {
        fprintf(stderr, "shared secret mismatch\n");
        goto end;
    }
    printf("OK: Aigis-Enc-2 keygen + KEM round-trip (ss=%zu bytes)\n", ss1len);
    ret = 0;

end:
    OPENSSL_free(ct);
    OPENSSL_free(ss1);
    OPENSSL_free(ss2);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    return ret;
}
