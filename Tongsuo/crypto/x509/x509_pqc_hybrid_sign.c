/*
 * ML-DSA-44-SM2 复合 PKCS#10 CSR 生成（certs/2）：
 *   - 公钥：OID 508.1，ML-DSA pk[1312] || SM2 pk[65]
 *   - 签名：OID 506.1，ML-DSA sig[2420] || SM2 sig[DER]
 *   - ML-DSA 签 SM3(CRI)；SM2 签完整 CRI（默认 SM2 ID）
 *
 * 配合 openssl req -key <mldsa.key> -sm2key <sm2.key> 使用。
 */

#include <string.h>

#include "internal/cryptlib.h"
#include "internal/x509_pqc_hybrid.h"
#include "crypto/x509.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#define PQC_SM2_DEFAULT_ID      "1234567812345678"
#define PQC_SM2_DEFAULT_ID_LEN  (sizeof(PQC_SM2_DEFAULT_ID) - 1)

static int pkey_is_mldsa44_spki(const EVP_PKEY *pkey)
{
    return pkey != NULL
        && (EVP_PKEY_is_a(pkey, "ML-DSA-44-SPKI")
            || EVP_PKEY_is_a(pkey, "id-ML-DSA-44-SPKI"));
}

static int pkey_is_sm2(const EVP_PKEY *pkey)
{
    return pkey != NULL && EVP_PKEY_is_a(pkey, "SM2");
}

static int extract_mldsa44_raw_pubkey(const EVP_PKEY *pkey,
                                      unsigned char *out, size_t outlen)
{
    size_t len = outlen;

    if (pkey == NULL || out == NULL || outlen < OSSL_PQC_MLDSA44_PK_LEN)
        return 0;
    if (EVP_PKEY_get_octet_string_param(pkey,
                                        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        out, outlen, &len)
            && len == OSSL_PQC_MLDSA44_PK_LEN)
        return 1;
    return 0;
}

#ifndef OPENSSL_NO_EC
static int extract_sm2_raw_pubkey(OSSL_LIB_CTX *libctx, const EVP_PKEY *pkey,
                                  unsigned char *out, size_t outlen)
{
    OSSL_ENCODER_CTX *ectx = NULL;
    BIO *mem = NULL;
    BUF_MEM *b = NULL;
    int ok = 0;

    if (pkey == NULL || out == NULL || outlen < OSSL_PQC_SM2_HYBRID_PK_LEN)
        return 0;

    ectx = OSSL_ENCODER_CTX_new_for_pkey((EVP_PKEY *)pkey, EVP_PKEY_PUBLIC_KEY,
                                         "DER", "SubjectPublicKeyInfo", NULL);
    mem = BIO_new(BIO_s_mem());
    if (ectx == NULL || mem == NULL)
        goto end;
    if (!OSSL_ENCODER_to_bio(ectx, mem))
        goto end;
    if (BIO_get_mem_ptr(mem, &b) <= 0 || b == NULL
            || b->length < (long)OSSL_PQC_SM2_HYBRID_PK_LEN)
        goto end;
    memcpy(out, b->data + b->length - OSSL_PQC_SM2_HYBRID_PK_LEN,
           OSSL_PQC_SM2_HYBRID_PK_LEN);
    ok = out[0] == 0x04;
end:
    OSSL_ENCODER_CTX_free(ectx);
    BIO_free(mem);
    (void)libctx;
    return ok;
}
#else
static int extract_sm2_raw_pubkey(OSSL_LIB_CTX *libctx, const EVP_PKEY *pkey,
                                  unsigned char *out, size_t outlen)
{
    (void)libctx;
    (void)pkey;
    (void)out;
    (void)outlen;
    return 0;
}
#endif

int ossl_x509_req_set_mldsa44_sm2_pubkey_from_keys(X509_REQ *req,
                                                   EVP_PKEY *mldsa_pkey,
                                                   EVP_PKEY *sm2_pkey)
{
    unsigned char mldsa_pk[OSSL_PQC_MLDSA44_PK_LEN];
    unsigned char sm2_pk[OSSL_PQC_SM2_HYBRID_PK_LEN];
    unsigned char combo[OSSL_PQC_MLDSA44_PK_LEN + OSSL_PQC_SM2_HYBRID_PK_LEN];
    unsigned char *penc = NULL;
    X509_PUBKEY *xpub = NULL;
    int ok = 0;

    if (req == NULL || mldsa_pkey == NULL || sm2_pkey == NULL)
        return 0;
    if (!pkey_is_mldsa44_spki(mldsa_pkey) || !pkey_is_sm2(sm2_pkey))
        return 0;
    if (!ossl_x509_ensure_pqc_providers(NULL))
        return 0;
    if (!extract_mldsa44_raw_pubkey(mldsa_pkey, mldsa_pk, sizeof(mldsa_pk))
            || !extract_sm2_raw_pubkey(NULL, sm2_pkey, sm2_pk, sizeof(sm2_pk)))
        return 0;

    memcpy(combo, mldsa_pk, OSSL_PQC_MLDSA44_PK_LEN);
    memcpy(combo + OSSL_PQC_MLDSA44_PK_LEN, sm2_pk, OSSL_PQC_SM2_HYBRID_PK_LEN);

    penc = OPENSSL_memdup(combo, sizeof(combo));
    xpub = X509_PUBKEY_new();
    if (penc == NULL || xpub == NULL)
        goto end;
    if (!X509_PUBKEY_set0_param(xpub,
                                OBJ_dup(OBJ_nid2obj(NID_ML_DSA_44_SM2)),
                                V_ASN1_UNDEF, NULL, penc,
                                (int)sizeof(combo))) {
        goto end;
    }
    penc = NULL;

    X509_PUBKEY_free(req->req_info.pubkey);
    req->req_info.pubkey = xpub;
    req->req_info.enc.modified = 1;
    xpub = NULL;
    ok = 1;

end:
    OPENSSL_free(penc);
    X509_PUBKEY_free(xpub);
    return ok;
}

int ossl_x509_req_sign_mldsa44_sm2_composite(X509_REQ *req,
                                             EVP_PKEY *mldsa_pkey,
                                             EVP_PKEY *sm2_pkey,
                                             OSSL_LIB_CTX *libctx)
{
    unsigned char *cri = NULL;
    int crilen = 0;
    unsigned char mldsa_sig[OSSL_PQC_MLDSA44_SIG_LEN];
    unsigned char sm2_sig[512];
    unsigned char *combosig = NULL;
    size_t mldsa_siglen = sizeof(mldsa_sig);
    size_t sm2_siglen = sizeof(sm2_sig);
    size_t combosig_len;
    ASN1_BIT_STRING *bs = NULL;
    X509_ALGOR *alg = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;

    if (req == NULL || mldsa_pkey == NULL || sm2_pkey == NULL)
        return 0;
    if (!pkey_is_mldsa44_spki(mldsa_pkey) || !pkey_is_sm2(sm2_pkey))
        return 0;
    if (!ossl_x509_ensure_pqc_providers(libctx))
        return 0;

    crilen = i2d_re_X509_REQ_tbs(req, &cri);
    if (crilen <= 0)
        goto end;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;
    if (!EVP_DigestSignInit_ex(mctx, NULL, "SM3", libctx, NULL, mldsa_pkey,
                                NULL))
        goto end;
    if (!EVP_DigestSign(mctx, mldsa_sig, &mldsa_siglen, cri, (size_t)crilen))
        goto end;
    if (mldsa_siglen != OSSL_PQC_MLDSA44_SIG_LEN)
        goto end;

    EVP_MD_CTX_free(mctx);
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;
    if (!EVP_DigestSignInit_ex(mctx, &pctx, "SM3", libctx, NULL, sm2_pkey,
                                NULL))
        goto end;
    if (EVP_PKEY_is_a(sm2_pkey, "SM2")
            && EVP_PKEY_CTX_set1_id(pctx, PQC_SM2_DEFAULT_ID,
                                    PQC_SM2_DEFAULT_ID_LEN) <= 0)
        goto end;
    if (!EVP_DigestSign(mctx, sm2_sig, &sm2_siglen, cri, (size_t)crilen))
        goto end;
    if (sm2_siglen == 0 || sm2_siglen > sizeof(sm2_sig))
        goto end;

    combosig_len = mldsa_siglen + sm2_siglen;
    combosig = OPENSSL_malloc(combosig_len);
    if (combosig == NULL)
        goto end;
    memcpy(combosig, mldsa_sig, mldsa_siglen);
    memcpy(combosig + mldsa_siglen, sm2_sig, sm2_siglen);

    bs = ASN1_BIT_STRING_new();
    if (bs == NULL
            || !ASN1_BIT_STRING_set(bs, combosig, (int)combosig_len))
        goto end;

    alg = X509_ALGOR_new();
    if (alg == NULL
            || !X509_ALGOR_set0(alg,
                                OBJ_dup(OBJ_nid2obj(NID_ML_DSA_44_SM2_with_SM3)),
                                V_ASN1_UNDEF, NULL)
            || !X509_REQ_set1_signature_algo(req, alg))
        goto end;
    X509_ALGOR_free(alg);
    alg = NULL;
    X509_REQ_set0_signature(req, bs);
    bs = NULL;
    ok = 1;

end:
    X509_ALGOR_free(alg);
    EVP_MD_CTX_free(mctx);
    ASN1_BIT_STRING_free(bs);
    OPENSSL_free(combosig);
    OPENSSL_free(cri);
    return ok;
}

static int pkey_is_aigis_sig1_spki(const EVP_PKEY *pkey)
{
    return pkey != NULL
        && (EVP_PKEY_is_a(pkey, "Aigis-SIG1-SPKI")
            || EVP_PKEY_is_a(pkey, "id-Aigis-SIG1-SPKI"));
}

static int extract_aigis_sig1_raw_pubkey(const EVP_PKEY *pkey,
                                         unsigned char *out, size_t outlen)
{
    size_t len = outlen;

    if (pkey == NULL || out == NULL || outlen < OSSL_PQC_AIGIS_SIG1_PK_LEN)
        return 0;
    if (EVP_PKEY_get_octet_string_param(pkey,
                                        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        out, outlen, &len)
            && len == OSSL_PQC_AIGIS_SIG1_PK_LEN)
        return 1;
    return 0;
}

int ossl_x509_req_set_aigis_sig1_sm2_pubkey_from_keys(X509_REQ *req,
                                                      EVP_PKEY *aigis_pkey,
                                                      EVP_PKEY *sm2_pkey)
{
    unsigned char aigis_pk[OSSL_PQC_AIGIS_SIG1_PK_LEN];
    unsigned char sm2_pk[OSSL_PQC_SM2_HYBRID_PK_LEN];
    unsigned char combo[OSSL_PQC_AIGIS_SIG1_PK_LEN + OSSL_PQC_SM2_HYBRID_PK_LEN];
    unsigned char *penc = NULL;
    X509_PUBKEY *xpub = NULL;
    ASN1_OBJECT *oid = NULL;
    int ok = 0;

    if (req == NULL || aigis_pkey == NULL || sm2_pkey == NULL)
        return 0;
    if (!pkey_is_aigis_sig1_spki(aigis_pkey) || !pkey_is_sm2(sm2_pkey))
        return 0;
    if (!ossl_x509_ensure_pqc_providers(NULL))
        return 0;
    if (!extract_aigis_sig1_raw_pubkey(aigis_pkey, aigis_pk, sizeof(aigis_pk))
            || !extract_sm2_raw_pubkey(NULL, sm2_pkey, sm2_pk, sizeof(sm2_pk)))
        return 0;

    memcpy(combo, aigis_pk, OSSL_PQC_AIGIS_SIG1_PK_LEN);
    memcpy(combo + OSSL_PQC_AIGIS_SIG1_PK_LEN, sm2_pk,
           OSSL_PQC_SM2_HYBRID_PK_LEN);

    penc = OPENSSL_memdup(combo, sizeof(combo));
    xpub = X509_PUBKEY_new();
    oid = OBJ_txt2obj(OSSL_AIGIS_OID_SIG1_SM2_SPKI, 1);
    if (penc == NULL || xpub == NULL || oid == NULL)
        goto end;
    if (!X509_PUBKEY_set0_param(xpub, oid, V_ASN1_NULL, NULL, penc,
                                (int)sizeof(combo)))
        goto end;
    oid = NULL;
    penc = NULL;

    X509_PUBKEY_free(req->req_info.pubkey);
    req->req_info.pubkey = xpub;
    req->req_info.enc.modified = 1;
    xpub = NULL;
    ok = 1;

end:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(penc);
    X509_PUBKEY_free(xpub);
    return ok;
}

int ossl_x509_req_sign_aigis_sig1_sm2_composite(X509_REQ *req,
                                                EVP_PKEY *aigis_pkey,
                                                EVP_PKEY *sm2_pkey,
                                                OSSL_LIB_CTX *libctx)
{
    unsigned char *cri = NULL;
    int crilen = 0;
    unsigned char aigis_sig[OSSL_PQC_AIGIS_SIG1_SIG_LEN];
    unsigned char sm2_sig[512];
    unsigned char *combosig = NULL;
    size_t aigis_siglen = sizeof(aigis_sig);
    size_t sm2_siglen = sizeof(sm2_sig);
    size_t combosig_len;
    ASN1_BIT_STRING *bs = NULL;
    X509_ALGOR *alg = NULL;
    ASN1_OBJECT *sigoid = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;

    if (req == NULL || aigis_pkey == NULL || sm2_pkey == NULL)
        return 0;
    if (!pkey_is_aigis_sig1_spki(aigis_pkey) || !pkey_is_sm2(sm2_pkey))
        return 0;
    if (!ossl_x509_ensure_pqc_providers(libctx))
        return 0;

    crilen = i2d_re_X509_REQ_tbs(req, &cri);
    if (crilen <= 0)
        goto end;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;
    if (!EVP_DigestSignInit_ex(mctx, NULL, "SM3", libctx, NULL, aigis_pkey,
                               NULL))
        goto end;
    if (!EVP_DigestSign(mctx, aigis_sig, &aigis_siglen, cri, (size_t)crilen))
        goto end;
    if (aigis_siglen != OSSL_PQC_AIGIS_SIG1_SIG_LEN)
        goto end;

    EVP_MD_CTX_free(mctx);
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;
    if (!EVP_DigestSignInit_ex(mctx, &pctx, "SM3", libctx, NULL, sm2_pkey,
                               NULL))
        goto end;
    if (EVP_PKEY_is_a(sm2_pkey, "SM2")
            && EVP_PKEY_CTX_set1_id(pctx, PQC_SM2_DEFAULT_ID,
                                    PQC_SM2_DEFAULT_ID_LEN) <= 0)
        goto end;
    if (!EVP_DigestSign(mctx, sm2_sig, &sm2_siglen, cri, (size_t)crilen))
        goto end;
    if (sm2_siglen == 0 || sm2_siglen > sizeof(sm2_sig))
        goto end;

    combosig_len = aigis_siglen + sm2_siglen;
    combosig = OPENSSL_malloc(combosig_len);
    if (combosig == NULL)
        goto end;
    memcpy(combosig, aigis_sig, aigis_siglen);
    memcpy(combosig + aigis_siglen, sm2_sig, sm2_siglen);

    bs = ASN1_BIT_STRING_new();
    if (bs == NULL
            || !ASN1_BIT_STRING_set(bs, combosig, (int)combosig_len))
        goto end;

    sigoid = OBJ_txt2obj(OSSL_AIGIS_OID_SIG1_SM2_WITH_SM3, 1);
    alg = X509_ALGOR_new();
    if (sigoid == NULL || alg == NULL
            || !X509_ALGOR_set0(alg, sigoid, V_ASN1_UNDEF, NULL))
        goto end;
    sigoid = NULL;
    if (!X509_REQ_set1_signature_algo(req, alg))
        goto end;
    X509_ALGOR_free(alg);
    alg = NULL;
    X509_REQ_set0_signature(req, bs);
    bs = NULL;
    ok = 1;

end:
    ASN1_OBJECT_free(sigoid);
    X509_ALGOR_free(alg);
    EVP_MD_CTX_free(mctx);
    ASN1_BIT_STRING_free(bs);
    OPENSSL_free(combosig);
    OPENSSL_free(cri);
    return ok;
}
