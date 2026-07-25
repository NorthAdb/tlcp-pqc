/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_ECC_KYBER_HYBRID_H
# define OSSL_CRYPTO_ECC_KYBER_HYBRID_H
# pragma once

# include <openssl/opensslconf.h>

# if !defined(OPENSSL_NO_EC) && !defined(FIPS_MODULE)

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/kyber.h"
#include "crypto/types.h"
#include <openssl/prov_ssl.h>  /* For SSL_MAX_MASTER_KEY_LENGTH */

/* ECC (secp256r1) key sizes */
#define ECC_SK_SIZE    32
#define ECC_SS_SIZE    32
#define ECC_PK_SIZE    65  /* Uncompressed point: 0x04 + 32 bytes x + 32 bytes y */

/* ML-KEM-512 (ECC-KYBER-SM4-GCM-SM3) */
#define KYBER_512_SS_SIZE 32
#define KYBER_512_PK_SIZE pqcrystals_kyber512_PUBLICKEYBYTES
#define KYBER_512_SK_SIZE pqcrystals_kyber512_SECRETKEYBYTES
#define KYBER_512_CT_SIZE pqcrystals_kyber512_CIPHERTEXTBYTES

#define ECC_KYBER512_HYBRID_SS_SIZE (SSL_MAX_MASTER_KEY_LENGTH + KYBER_512_SS_SIZE)
#define ECC_KYBER512_HYBRID_CT_SIZE KYBER_512_CT_SIZE
#define ECC_KYBER512_HYBRID_SK_SIZE (ECC_SK_SIZE + KYBER_512_SK_SIZE)
#define ECC_KYBER512_HYBRID_PK_SIZE (ECC_PK_SIZE + KYBER_512_PK_SIZE)

/* Kyber-768 (ECDHE-KYBER-SM4-GCM-SM3) */
#define KYBER_768_SS_SIZE 32
#define KYBER_768_PK_SIZE pqcrystals_kyber768_PUBLICKEYBYTES
#define KYBER_768_SK_SIZE pqcrystals_kyber768_SECRETKEYBYTES
#define KYBER_768_CT_SIZE pqcrystals_kyber768_CIPHERTEXTBYTES

#define ECC_KYBER_HYBRID_SS_SIZE (SSL_MAX_MASTER_KEY_LENGTH + KYBER_768_SS_SIZE)
#define ECC_KYBER_HYBRID_CT_SIZE KYBER_768_CT_SIZE
#define ECC_KYBER_HYBRID_SK_SIZE (ECC_SK_SIZE + KYBER_768_SK_SIZE)
#define ECC_KYBER_HYBRID_PK_SIZE (ECC_PK_SIZE + KYBER_768_PK_SIZE)

typedef struct ecc_kyber_hybrid_key {
    int has_kem_sk;
    uint8_t * pk;
    uint8_t * sk;
    uint8_t * ct;
    uint8_t * ss;
    OSSL_LIB_CTX * libctx;
} ecc_kyber_hybrid_key;


ecc_kyber_hybrid_key * ecc_kyber_hybrid_key_new(void);
void ecc_kyber_hybrid_key_free(ecc_kyber_hybrid_key * key);

/* ML-KEM-512 + ECC (ECC-KYBER suite) */
int ecc_kyber512_hybrid_keygen(OSSL_LIB_CTX *libctx, EVP_PKEY *ecc_pkey,
                               uint8_t *pk, size_t pk_len,
                               uint8_t *sk, size_t sk_len);

int ecc_kyber512_hybrid_load(OSSL_LIB_CTX *libctx, EVP_PKEY *ecc_pkey,
                             const uint8_t *kyber_pk, size_t kyber_pk_len,
                             const uint8_t *kyber_sk, size_t kyber_sk_len,
                             uint8_t *pk, size_t pk_len,
                             uint8_t *sk, size_t sk_len);

int ecc_kyber512_hybrid_encaps(OSSL_LIB_CTX *libctx, uint8_t *ss, size_t ss_len,
                               uint8_t *ct, size_t ct_len,
                               const uint8_t *pk, size_t pk_len);

int ecc_kyber512_hybrid_decaps(OSSL_LIB_CTX *libctx, uint8_t *ss, size_t ss_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *sk, size_t sk_len);

/* Kyber-768 + ECC (ECDHE-KYBER suite) */
int ecc_kyber_hybrid_keygen(OSSL_LIB_CTX * libctx, EVP_PKEY *ecc_pkey, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len);

int ecc_kyber_hybrid_encaps(OSSL_LIB_CTX * libctx, uint8_t *ss, size_t ss_len, uint8_t *ct, size_t ct_len, const uint8_t *pk, size_t pk_len);

int ecc_kyber_hybrid_decaps(OSSL_LIB_CTX * libctx, uint8_t *ss, size_t ss_len, const uint8_t *ct, size_t ct_len, const uint8_t *sk, size_t sk_len);

# endif

#endif
