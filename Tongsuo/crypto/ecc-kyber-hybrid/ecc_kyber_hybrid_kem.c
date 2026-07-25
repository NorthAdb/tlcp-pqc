#include "internal/deprecated.h"

#include "crypto/ecc_kyber_hybrid.h"
#include "internal/x509_pqc_hybrid.h"

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "crypto/kyber.h"

static int ecc_hybrid_encode_ecc_keys(EVP_PKEY *ecc_pkey,
                                      uint8_t *pk, size_t pk_len,
                                      uint8_t *sk, size_t sk_len)
{
    EC_KEY *ec_key = NULL;
    const BIGNUM *ec_key_sk;
    const EC_POINT *ec_key_pk;
    const EC_GROUP *group;

    if (pk == NULL || sk == NULL || ecc_pkey == NULL)
        return 0;

    ec_key = EVP_PKEY_get1_EC_KEY(ecc_pkey);
    if (ec_key == NULL)
        return 0;

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
        goto err;

    ec_key_sk = EC_KEY_get0_private_key(ec_key);
    if (ec_key_sk == NULL)
        goto err;
    if (!BN_bn2binpad(ec_key_sk, sk, ECC_SK_SIZE))
        goto err;

    ec_key_pk = EC_KEY_get0_public_key(ec_key);
    if (ec_key_pk == NULL)
        goto err;
    if (EC_POINT_point2oct(group, ec_key_pk, POINT_CONVERSION_UNCOMPRESSED,
                           pk, ECC_PK_SIZE, NULL) != ECC_PK_SIZE)
        goto err;

    EC_KEY_free(ec_key);
    return 1;

err:
    EC_KEY_free(ec_key);
    return 0;
}

static int ecc_kyber512_kem_encaps(OSSL_LIB_CTX *libctx,
                                   uint8_t *ss, size_t ss_len,
                                   uint8_t *ct, size_t ct_len,
                                   const uint8_t *kyber_pk)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t out_ct = ct_len, out_ss = ss_len;
    int ret = 0;

    pkey = ossl_x509_hybrid_mlkem512_from_raw(libctx, NULL,
                                              kyber_pk, KYBER_512_PK_SIZE,
                                              NULL, 0);
    if (pkey == NULL)
        return 0;

    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (pctx == NULL
            || EVP_PKEY_encapsulate_init(pctx, NULL) <= 0
            || EVP_PKEY_encapsulate(pctx, ct, &out_ct, ss, &out_ss) <= 0
            || out_ct != (size_t)ECC_KYBER512_HYBRID_CT_SIZE
            || out_ss != (size_t)KYBER_512_SS_SIZE)
        goto err;
    ret = 1;

err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    if (ret == 0)
        OPENSSL_cleanse(ss, ss_len);
    return ret;
}

static int ecc_kyber512_kem_decaps(OSSL_LIB_CTX *libctx,
                                   uint8_t *ss, size_t ss_len,
                                   const uint8_t *ct, size_t ct_len,
                                   const uint8_t *kyber_sk)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t out_ss = ss_len;
    int ret = 0;

    pkey = ossl_x509_hybrid_mlkem512_from_raw(libctx, NULL,
                                              NULL, 0,
                                              kyber_sk, KYBER_512_SK_SIZE);
    if (pkey == NULL)
        return 0;

    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (pctx == NULL
            || EVP_PKEY_decapsulate_init(pctx, NULL) <= 0
            || EVP_PKEY_decapsulate(pctx, ss, &out_ss, ct, ct_len) <= 0
            || out_ss != (size_t)KYBER_512_SS_SIZE)
        goto err;
    ret = 1;

err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    if (ret == 0)
        OPENSSL_cleanse(ss, ss_len);
    return ret;
}

ecc_kyber_hybrid_key * ecc_kyber_hybrid_key_new(void)
{
    ecc_kyber_hybrid_key * hybrid_key = OPENSSL_malloc(sizeof(ecc_kyber_hybrid_key));
    if(hybrid_key == NULL)
        goto err;
    memset(hybrid_key, 0x00, sizeof(ecc_kyber_hybrid_key));
    
    hybrid_key->pk = OPENSSL_malloc(ECC_KYBER_HYBRID_PK_SIZE);
    if(hybrid_key->pk == NULL)
        goto err;
    memset(hybrid_key->pk, 0x00, ECC_KYBER_HYBRID_PK_SIZE);

    hybrid_key->sk = OPENSSL_malloc(ECC_KYBER_HYBRID_SK_SIZE);
    if(hybrid_key->sk == NULL)
        goto err;
    memset(hybrid_key->sk, 0x00, ECC_KYBER_HYBRID_SK_SIZE);

    hybrid_key->ct = OPENSSL_malloc(ECC_KYBER_HYBRID_CT_SIZE);
    if(hybrid_key->ct == NULL)
        goto err;
    memset(hybrid_key->ct, 0x00, ECC_KYBER_HYBRID_CT_SIZE);

    hybrid_key->ss = OPENSSL_malloc(ECC_KYBER_HYBRID_SS_SIZE);
    if(hybrid_key->ss == NULL)
        goto err;
    memset(hybrid_key->ss, 0x00, ECC_KYBER_HYBRID_SS_SIZE);

    hybrid_key->has_kem_sk = 0;

    return hybrid_key;
err:
    if(hybrid_key) {
        if(hybrid_key->pk)
            OPENSSL_free(hybrid_key->pk);
        if(hybrid_key->sk)
            OPENSSL_free(hybrid_key->sk);
        if(hybrid_key->ct)
            OPENSSL_free(hybrid_key->ct);
        if(hybrid_key->ss)
            OPENSSL_free(hybrid_key->ss);
        OPENSSL_free(hybrid_key);
    }
    return NULL;
}

void ecc_kyber_hybrid_key_free(ecc_kyber_hybrid_key * hybrid_key)
{
    if(hybrid_key == NULL)
        return;
    if(hybrid_key->pk) {
        memset(hybrid_key->pk, 0x00, ECC_KYBER_HYBRID_PK_SIZE);
        OPENSSL_free(hybrid_key->pk);
    }    
    if(hybrid_key->sk) {
        memset(hybrid_key->sk, 0x00, ECC_KYBER_HYBRID_SK_SIZE);
        OPENSSL_free(hybrid_key->sk);
    }
    if(hybrid_key->ct) {
        memset(hybrid_key->ct, 0x00, ECC_KYBER_HYBRID_CT_SIZE);
        OPENSSL_free(hybrid_key->ct); 
    }
    if(hybrid_key->ss) {
        memset(hybrid_key->ss, 0x00, ECC_KYBER_HYBRID_SS_SIZE);
        OPENSSL_free(hybrid_key->ss);
    }
    OPENSSL_free(hybrid_key);
}

int ecc_kyber512_hybrid_keygen(OSSL_LIB_CTX *libctx, EVP_PKEY *ecc_pkey,
                               uint8_t *pk, size_t pk_len,
                               uint8_t *sk, size_t sk_len)
{
    if (pk == NULL || sk == NULL || ecc_pkey == NULL)
        return 0;
    if (pk_len < ECC_KYBER512_HYBRID_PK_SIZE
            || sk_len < ECC_KYBER512_HYBRID_SK_SIZE)
        return 0;

    if (!ecc_hybrid_encode_ecc_keys(ecc_pkey, pk, pk_len, sk, sk_len))
        return 0;

    return ossl_x509_hybrid_mlkem512_keypair(libctx, NULL,
                                             pk + ECC_PK_SIZE, KYBER_512_PK_SIZE,
                                             sk + ECC_SK_SIZE, KYBER_512_SK_SIZE);
}

int ecc_kyber512_hybrid_load(OSSL_LIB_CTX *libctx, EVP_PKEY *ecc_pkey,
                             const uint8_t *kyber_pk, size_t kyber_pk_len,
                             const uint8_t *kyber_sk, size_t kyber_sk_len,
                             uint8_t *pk, size_t pk_len,
                             uint8_t *sk, size_t sk_len)
{
    if (pk == NULL || sk == NULL || ecc_pkey == NULL
            || kyber_pk == NULL || kyber_sk == NULL)
        return 0;
    if (pk_len < ECC_KYBER512_HYBRID_PK_SIZE
            || sk_len < ECC_KYBER512_HYBRID_SK_SIZE
            || kyber_pk_len != KYBER_512_PK_SIZE
            || kyber_sk_len != KYBER_512_SK_SIZE)
        return 0;

    if (!ecc_hybrid_encode_ecc_keys(ecc_pkey, pk, pk_len, sk, sk_len))
        return 0;

    memcpy(pk + ECC_PK_SIZE, kyber_pk, KYBER_512_PK_SIZE);
    memcpy(sk + ECC_SK_SIZE, kyber_sk, KYBER_512_SK_SIZE);
    return 1;
}

int ecc_kyber512_hybrid_encaps(OSSL_LIB_CTX *libctx, uint8_t *ss, size_t ss_len,
                               uint8_t *ct, size_t ct_len,
                               const uint8_t *pk, size_t pk_len)
{
    if (pk == NULL || ct == NULL || ss == NULL)
        return 0;
    if (pk_len != ECC_KYBER512_HYBRID_PK_SIZE
            || ss_len < KYBER_512_SS_SIZE
            || ct_len < ECC_KYBER512_HYBRID_CT_SIZE)
        return 0;

    return ecc_kyber512_kem_encaps(libctx, ss, ss_len, ct, ct_len,
                                   pk + ECC_PK_SIZE);
}

int ecc_kyber512_hybrid_decaps(OSSL_LIB_CTX *libctx, uint8_t *ss, size_t ss_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *sk, size_t sk_len)
{
    if (ss == NULL || ct == NULL || sk == NULL)
        return 0;
    if (ss_len < KYBER_512_SS_SIZE
            || ct_len != ECC_KYBER512_HYBRID_CT_SIZE
            || sk_len != ECC_KYBER512_HYBRID_SK_SIZE)
        return 0;

    return ecc_kyber512_kem_decaps(libctx, ss, ss_len, ct, ct_len,
                                   sk + ECC_SK_SIZE);
}

int ecc_kyber_hybrid_keygen(OSSL_LIB_CTX * libctx, EVP_PKEY *ecc_pkey, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len) {

    if(pk == NULL || sk == NULL || ecc_pkey == NULL) {
        return 0;
    }

    if((pk_len < ECC_KYBER_HYBRID_PK_SIZE) || 
        (sk_len < ECC_KYBER_HYBRID_SK_SIZE)) {
        return 0;
    }

    if (!ecc_hybrid_encode_ecc_keys(ecc_pkey, pk, pk_len, sk, sk_len))
        return 0;
    
    /* Generate Kyber-768 key pair */
    if(pqcrystals_kyber768_ref_keypair(pk + ECC_PK_SIZE, sk + ECC_SK_SIZE) != 0) {
        return 0;
    }
    return 1;
}

int ecc_kyber_hybrid_encaps(OSSL_LIB_CTX * libctx, uint8_t *ss, size_t ss_len, uint8_t *ct, size_t ct_len, const uint8_t *pk, size_t pk_len) {
    int ret = 0;


    if(pk == NULL || ct == NULL || ss == NULL) {
        fprintf(stderr, "[ecc_kyber_hybrid_encaps] invalid input ptr: pk=%p ct=%p ss=%p\n",
                pk, ct, ss);
        return 0;
    }

    if((pk_len != ECC_KYBER_HYBRID_PK_SIZE) || 
        (ss_len < KYBER_768_SS_SIZE) ||
        (ct_len < ECC_KYBER_HYBRID_CT_SIZE)){
        fprintf(stderr, "[ecc_kyber_hybrid_encaps] size check failed: pk_len=%zu(expect=%d) ss_len=%zu(min=%d) ct_len=%zu(min=%d)\n",
                pk_len, ECC_KYBER_HYBRID_PK_SIZE, ss_len, KYBER_768_SS_SIZE,
                ct_len, ECC_KYBER_HYBRID_CT_SIZE);
        return 0;
    }

    if (pqcrystals_kyber768_ref_enc(ct, ss, pk + ECC_PK_SIZE) != 0) {
        fprintf(stderr, "[ecc_kyber_hybrid_encaps] pqcrystals_kyber768_ref_enc failed\n");
        OPENSSL_cleanse(ss, ss_len);
        goto err;
    }
    
    ret = 1;
err:
    return ret;
}

int ecc_kyber_hybrid_decaps(OSSL_LIB_CTX * libctx, uint8_t *ss, size_t ss_len, const uint8_t *ct, size_t ct_len, const uint8_t *sk, size_t sk_len) {
    int ret = 0;


    if(ss == NULL || ct == NULL || sk == NULL) {
        return 0;
    }

    if((ss_len < KYBER_768_SS_SIZE) || 
        (ct_len != ECC_KYBER_HYBRID_CT_SIZE) ||
        (sk_len != ECC_KYBER_HYBRID_SK_SIZE)){
        return 0;
    }

    if (pqcrystals_kyber768_ref_dec(ss, ct, sk + ECC_SK_SIZE) != 0) {
        OPENSSL_cleanse(ss, ss_len);
        goto err;
    }

    ret = 1;
err:    
    return ret;
}
