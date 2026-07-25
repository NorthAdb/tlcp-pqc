/*
 * OpenSSL 3 provider: 解析国密证书 SubjectPublicKeyInfo 中未在默认库注册的 OID：
 * - 1.2.156.10197.1.304.1  裸 ML-DSA-44 公钥 (1312 字节)
 * - 1.2.156.10197.1.303.1  ML-KEM-512 密钥封装算法（抗量子），公钥长度 ML_KEM_512_PUBLICKEYBYTES
 * 依赖 PQMagic (libpqmagic_std)：ML-DSA 建议以 -DUSE_SHAKE=ON 构建，内部用 SHAKE；
 * 证书侧先 SM3(原始 TBSCertificate) 再调 pqmagic_ml_dsa_44_std_*，在本文中实现。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pqmagic_api.h>

/* 与 Tongsuo/证书中 OBJ_obj2txt 数字形式一致 */
#define OID_MLDSA44_SPKI "1.2.156.10197.1.304.1"
/* 国密 sm-scheme 303.1：ML-KEM-512 密钥封装算法（抗量子），长度取自 PQMagic ML_KEM_512_PUBLICKEYBYTES */
#define OID_MLKEM512_SPKI "1.2.156.10197.1.303.1"
/* PKCS#8 attribute：附带裸 ML-DSA-44 公钥，解码仅含 sk 的 PrivateKeyInfo 时补全 pk */
#define OID_MLDSA44_PKCS8_PUB "1.2.156.10197.1.304.1.1"

#define MLDSA44_PK_LEN ML_DSA_44_PUBLICKEYBYTES
#define MLDSA44_SK_LEN ML_DSA_44_SECRETKEYBYTES
#define MLDSA44_SIG_LEN ML_DSA_44_SIGBYTES
#define MLKEM512_PK_LEN ML_KEM_512_PUBLICKEYBYTES

#define PQMAGIC_PK_MAX 1312

struct pqmagic_raw_key {
    unsigned char pk[PQMAGIC_PK_MAX];
    size_t pk_len;
    unsigned char sk[MLDSA44_SK_LEN];
    size_t sk_len;
    char oid_text[256];
};

struct pqmagic_sig_ctx {
    OSSL_LIB_CTX *libctx;
    struct pqmagic_raw_key *key;
    unsigned char *acc;
    size_t acc_len;
    size_t acc_cap;
    unsigned char aid_buf[128];
    size_t aid_len;
};

struct spki_dec_ctx {
    int selection;
    OSSL_LIB_CTX *libctx;
};

static int pqmagic_pkcs8_get_embedded_pubkey(const PKCS8_PRIV_KEY_INFO *p8,
                                           unsigned char *pk, size_t pk_cap,
                                           size_t *pk_len);
static int pqmagic_sig_build_aid(struct pqmagic_sig_ctx *ctx);

static void *pqmagic_km_new(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(struct pqmagic_raw_key));
}

static void pqmagic_km_free(void *keydata)
{
    struct pqmagic_raw_key *k = keydata;

    if (k == NULL)
        return;
    OPENSSL_cleanse(k->sk, sizeof(k->sk));
    OPENSSL_free(k);
}

static void *pqmagic_km_load(const void *reference, size_t reference_sz)
{
    struct pqmagic_raw_key *key;

    if (reference_sz != sizeof(void *))
        return NULL;
    key = *(struct pqmagic_raw_key **)reference;
    *(struct pqmagic_raw_key **)reference = NULL;
    return key;
}

static const OSSL_PARAM pqmagic_km_import_type_list[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM pqmagic_mldsa_import_types_pub[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM pqmagic_mldsa_import_types_priv[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

/* 仅 ML-KEM 现用 pqmagic_mlkem_km_import_types；保留供将来 SPKI 路径复用 */
#if 0
static const OSSL_PARAM *pqmagic_km_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return pqmagic_km_import_type_list;
    return NULL;
}
#endif

static const OSSL_PARAM *pqmagic_mldsa_km_import_types(int selection)
{
    /*
     * For X.509/SPKI decode paths selection may include multiple bits even when
     * only public key material is present. Advertise public import types whenever
     * PUBLIC is requested to avoid hard dependency on PRIV_KEY presence.
     */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return pqmagic_mldsa_import_types_pub;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return pqmagic_mldsa_import_types_priv;
    return NULL;
}

static const OSSL_PARAM pqmagic_mlkem_priv_import_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqmagic_mlkem_km_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return pqmagic_km_import_type_list;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return pqmagic_mlkem_priv_import_types;
    return NULL;
}

static const OSSL_PARAM pqmagic_km_export_type_list[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqmagic_km_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return pqmagic_km_export_type_list;
    return NULL;
}

static int pqmagic_km_has(const void *keydata, int selection)
{
    const struct pqmagic_raw_key *k = keydata;

    if (k == NULL || (k->pk_len == 0 && k->sk_len == 0))
        return 0;
    /*
     * No separate domain parameters; public key is self-contained.
     * Must report DOMAIN_PARAMETERS as present so EVP_PKEY_missing_parameters
     * is false and X509_get_pubkey_parameters does not fail (see openssl#x509_vfy).
     */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0
        || (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        return 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return (k->pk_len == MLDSA44_PK_LEN || k->pk_len == MLKEM512_PK_LEN);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (strcmp(k->oid_text, OID_MLDSA44_SPKI) == 0)
            return (k->sk_len == MLDSA44_SK_LEN);
        if (strcmp(k->oid_text, OID_MLKEM512_SPKI) == 0)
            return (k->sk_len == ML_KEM_512_SECRETKEYBYTES);
        return 0;
    }
    return 1;
}

static int pqmagic_km_import(void *keydata, int selection,
                             const OSSL_PARAM params[])
{
    struct pqmagic_raw_key *k = keydata;
    const OSSL_PARAM *p;
    int got = 0;

    (void)selection;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        {
            void *vp = k->pk;
            size_t plen = 0;

            if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(k->pk), &plen))
                return 0;
            if (plen == MLDSA44_PK_LEN)
                snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_MLDSA44_SPKI);
            else if (plen == MLKEM512_PK_LEN)
                snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_MLKEM512_SPKI);
            else
                return 0;
            k->pk_len = plen;
            got = 1;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        {
            void *vp = k->sk;
            size_t plen = 0;

            if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(k->sk), &plen))
                return 0;
            if (plen == MLDSA44_SK_LEN) {
                snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_MLDSA44_SPKI);
            } else if (plen == ML_KEM_512_SECRETKEYBYTES) {
                snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_MLKEM512_SPKI);
            } else {
                return 0;
            }
            k->sk_len = plen;
            got = 1;
        }
    }
    return got;
}

static int pqmagic_km_export(void *keydata, int selection,
                             OSSL_CALLBACK *param_cb, void *cbarg)
{
    struct pqmagic_raw_key *k = keydata;
    OSSL_PARAM params[3];

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0 || k->pk_len == 0)
        return 0;
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, k->pk, k->pk_len);
    params[1] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM pqmagic_km_gettable[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqmagic_km_gettable_params(void *provctx)
{
    (void)provctx;
    return pqmagic_km_gettable;
}

static int pqmagic_km_get_params(void *keydata, OSSL_PARAM params[])
{
    struct pqmagic_raw_key *k = keydata;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        char desc[384];

        if (strcmp(k->oid_text, OID_MLDSA44_SPKI) == 0)
            snprintf(desc, sizeof(desc), "ML-DSA-44 (PQMagic, OID %s)",
                     OID_MLDSA44_SPKI);
        else if (strcmp(k->oid_text, OID_MLKEM512_SPKI) == 0)
            snprintf(desc, sizeof(desc),
                     "ML-KEM-512 KEM public key / 抗量子 (OID %s)", OID_MLKEM512_SPKI);
        else
            snprintf(desc, sizeof(desc), "PQMagic raw public key (OID %s)",
                     k->oid_text);
        if (!OSSL_PARAM_set_utf8_string(p, desc))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, k->pk, k->pk_len))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SM3"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SM3"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL) {
        int bits = (int)(k->pk_len * 8);
        if (!OSSL_PARAM_set_int(p, bits))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        /* 供 ssl_security_cert / EVP_PKEY_get_security_bits，避免 -1 触发 ee key too small */
        if (!OSSL_PARAM_set_int(p, 256))
            return 0;
    }
    return 1;
}

static const char *pqmagic_mldsa_km_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
        return "ML-DSA-44-with-SM3";
    return NULL;
}

struct mldsa_gen_ctx {
    int selection;
};

static void *mldsa_gen_init(void *provctx, int selection,
                            const OSSL_PARAM params[])
{
    struct mldsa_gen_ctx *gctx;

    (void)provctx;
    (void)params;
    if ((selection & (OSSL_KEYMGMT_SELECT_KEYPAIR
                       | OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                       | OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) == 0)
        return NULL;
    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx != NULL)
        gctx->selection = selection;
    return gctx;
}

static void mldsa_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static void *mldsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct mldsa_gen_ctx *gctx = genctx;
    struct pqmagic_raw_key *key;

    (void)osslcb;
    (void)cbarg;
    if (gctx == NULL)
        return NULL;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    if (pqmagic_ml_dsa_44_std_keypair(key->pk, key->sk) != 0) {
        pqmagic_km_free(key);
        return NULL;
    }
    key->pk_len = MLDSA44_PK_LEN;
    key->sk_len = MLDSA44_SK_LEN;
    snprintf(key->oid_text, sizeof(key->oid_text), "%s", OID_MLDSA44_SPKI);
    return key;
}

static const char *pqmagic_mlkem_km_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_KEM)
        return "id-ML-KEM-512-SPKI";
    return NULL;
}

static void *pqmagic_sig_newctx(void *provctx)
{
    struct pqmagic_sig_ctx *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->libctx = provctx;
    return ctx;
}

static void pqmagic_sig_freectx(void *vctx)
{
    struct pqmagic_sig_ctx *ctx = vctx;

    if (ctx == NULL)
        return;
    OPENSSL_free(ctx->acc);
    OPENSSL_free(ctx);
}

static void *pqmagic_sig_dupctx(void *vctx)
{
    struct pqmagic_sig_ctx *src = vctx;
    struct pqmagic_sig_ctx *dst;

    if (src == NULL)
        return NULL;
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;
    dst->libctx = src->libctx;
    dst->key = src->key;
    if (src->acc_len > 0 && src->acc != NULL) {
        dst->acc = OPENSSL_memdup(src->acc, src->acc_len);
        if (dst->acc == NULL)
            goto err;
        dst->acc_len = src->acc_len;
        dst->acc_cap = src->acc_len;
    }
    return dst;
err:
    OPENSSL_free(dst);
    return NULL;
}

static int pqmagic_sig_acc_append(struct pqmagic_sig_ctx *ctx,
                                  const unsigned char *data, size_t datalen)
{
    size_t need, ncap;

    if (ctx == NULL)
        return 0;
    if (datalen == 0)
        return 1;
    need = ctx->acc_len + datalen;
    if (need < ctx->acc_len)
        return 0;
    if (need > ctx->acc_cap) {
        ncap = ctx->acc_cap ? ctx->acc_cap : 4096;
        while (ncap < need) {
            if (ncap > SIZE_MAX / 2)
                return 0;
            ncap *= 2;
        }
        ctx->acc = OPENSSL_realloc(ctx->acc, ncap);
        if (ctx->acc == NULL)
            return 0;
        ctx->acc_cap = ncap;
    }
    memcpy(ctx->acc + ctx->acc_len, data, datalen);
    ctx->acc_len = need;
    return 1;
}

static int pqmagic_sig_digest_verify_init(void *vctx, const char *mdname,
                                          void *provkey,
                                          const OSSL_PARAM *params)
{
    struct pqmagic_sig_ctx *ctx = vctx;
    struct pqmagic_raw_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL || k->pk_len != MLDSA44_PK_LEN)
        return 0;
    if (strcmp(k->oid_text, OID_MLDSA44_SPKI) != 0)
        return 0;
    /* req 默认配置常为 sha256；ML-DSA-44-with-SM3 在 final 中固定 SM3 */
    (void)mdname;

    ctx->key = k;
    ctx->acc_len = 0;
    OPENSSL_free(ctx->acc);
    ctx->acc = NULL;
    ctx->acc_cap = 0;
    return pqmagic_sig_build_aid(ctx);
}

static int pqmagic_sig_digest_verify_update(void *vctx,
                                            const unsigned char *data,
                                            size_t datalen)
{
    struct pqmagic_sig_ctx *ctx = vctx;

    if (ctx == NULL)
        return 0;
    return pqmagic_sig_acc_append(ctx, data, datalen);
}

static int pqmagic_sig_digest_verify_final(void *vctx,
                                           const unsigned char *sig,
                                           size_t siglen)
{
    struct pqmagic_sig_ctx *ctx = vctx;
    unsigned char sm3[32];
    unsigned int sm3_len = sizeof(sm3);
    EVP_MD_CTX *mdc = NULL;
    int r;

    if (ctx == NULL || ctx->key == NULL || ctx->acc == NULL || ctx->acc_len == 0)
        return 0;

    /*
     * 外层：对原始数据（如 TBSCertificate DER，与 ASN1_item_verify 一致）做 SM3，
     * 得到 32 字节作为 ML-DSA 的「消息」m。
     * 内层：PQMagic 以 USE_SHAKE=ON 构建时，pqmagic_ml_dsa_44_std_verify 内部使用
     * SHAKE256 等（FIPS 204）处理 tr‖m_extended；与 USE_SM3 构建的库不兼容，需与
     * 链接的 libpqmagic 一致。
     */
    mdc = EVP_MD_CTX_new();
    if (mdc == NULL)
        return 0;
    if (!EVP_DigestInit_ex(mdc, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(mdc, ctx->acc, ctx->acc_len)
        || !EVP_DigestFinal_ex(mdc, sm3, &sm3_len)) {
        EVP_MD_CTX_free(mdc);
        return 0;
    }
    EVP_MD_CTX_free(mdc);
    if (sm3_len != 32)
        return 0;
    r = pqmagic_ml_dsa_44_std_verify(sig, siglen, sm3, 32, NULL, 0,
                                     ctx->key->pk);
    return (r == 0) ? 1 : 0;
}

static int pqmagic_pkcs8_get_embedded_pubkey(const PKCS8_PRIV_KEY_INFO *p8,
                                           unsigned char *pk, size_t pk_cap,
                                           size_t *pk_len);

static int pqmagic_sig_build_aid(struct pqmagic_sig_ctx *ctx)
{
    X509_ALGOR *algor = NULL;
    unsigned char *der = NULL;
    int len;

    if (ctx == NULL)
        return 0;
    ctx->aid_len = 0;
    algor = X509_ALGOR_new();
    if (algor == NULL)
        return 1;
    if (!X509_ALGOR_set0(algor, OBJ_nid2obj(NID_ML_DSA_44_with_SM3),
                         V_ASN1_UNDEF, NULL))
        goto end;
    len = i2d_X509_ALGOR(algor, &der);
    if (len <= 0 || (size_t)len > sizeof(ctx->aid_buf))
        goto end;
    memcpy(ctx->aid_buf, der, (size_t)len);
    ctx->aid_len = (size_t)len;

end:
    OPENSSL_free(der);
    X509_ALGOR_free(algor);
    return 1;
}

static const OSSL_PARAM pqmagic_sig_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqmagic_sig_gettable_ctx_params_fn(void *vctx,
                                                            void *provctx)
{
    (void)vctx;
    (void)provctx;
    return pqmagic_sig_gettable_ctx_params;
}

static int pqmagic_sig_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    struct pqmagic_sig_ctx *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p,
                                        ctx->aid_len == 0 ? NULL : ctx->aid_buf,
                                        ctx->aid_len))
        return 0;
    return 1;
}

static int pqmagic_sig_digest_sign_init(void *vctx, const char *mdname,
                                        void *provkey, const OSSL_PARAM *params)
{
    struct pqmagic_sig_ctx *ctx = vctx;
    struct pqmagic_raw_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL || k->sk_len != MLDSA44_SK_LEN)
        return 0;
    if (strcmp(k->oid_text, OID_MLDSA44_SPKI) != 0)
        return 0;
    /* req 默认配置常为 sha256；ML-DSA-44-with-SM3 在 final 中固定 SM3 */
    (void)mdname;

    ctx->key = k;
    ctx->acc_len = 0;
    OPENSSL_free(ctx->acc);
    ctx->acc = NULL;
    ctx->acc_cap = 0;
    return pqmagic_sig_build_aid(ctx);
}

static int pqmagic_sig_digest_sign_update(void *vctx,
                                          const unsigned char *data,
                                          size_t datalen)
{
    struct pqmagic_sig_ctx *ctx = vctx;

    if (ctx == NULL)
        return 0;
    return pqmagic_sig_acc_append(ctx, data, datalen);
}

static int pqmagic_sig_sm3_mldsa_sign(const struct pqmagic_raw_key *key,
                                      const unsigned char *data, size_t datalen,
                                      unsigned char *sig, size_t *siglen,
                                      size_t sigsize)
{
    unsigned char sm3[32];
    unsigned int sm3_len = sizeof(sm3);
    EVP_MD_CTX *mdc = NULL;
    size_t need = MLDSA44_SIG_LEN;
    size_t slen;
    int r;

    if (key == NULL || key->sk_len != MLDSA44_SK_LEN || data == NULL)
        return 0;

    if (sig == NULL) {
        *siglen = need;
        return 1;
    }
    if (sigsize < need)
        return 0;

    mdc = EVP_MD_CTX_new();
    if (mdc == NULL)
        return 0;
    if (!EVP_DigestInit_ex(mdc, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(mdc, data, datalen)
        || !EVP_DigestFinal_ex(mdc, sm3, &sm3_len)) {
        EVP_MD_CTX_free(mdc);
        return 0;
    }
    EVP_MD_CTX_free(mdc);
    if (sm3_len != 32)
        return 0;

    slen = need;
    r = pqmagic_ml_dsa_44_std_signature(sig, &slen, sm3, 32, NULL, 0, key->sk);
    if (r != 0 || slen != need)
        return 0;
    *siglen = slen;
    return 1;
}

static int pqmagic_sig_digest_sign(void *vctx, unsigned char *sig, size_t *siglen,
                                   size_t sigsize, const unsigned char *data,
                                   size_t datalen)
{
    struct pqmagic_sig_ctx *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL)
        return 0;
    return pqmagic_sig_sm3_mldsa_sign(ctx->key, data, datalen, sig, siglen,
                                      sigsize);
}

static int pqmagic_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                         size_t *siglen, size_t sigsize)
{
    struct pqmagic_sig_ctx *ctx = vctx;
    size_t need = MLDSA44_SIG_LEN;

    if (ctx == NULL || ctx->key == NULL)
        return 0;
    if (ctx->key->sk_len != MLDSA44_SK_LEN)
        return 0;

    /* EVP_DigestSign(NULL,…) 仅查询长度时不走 update */
    if (sig == NULL) {
        *siglen = need;
        return 1;
    }
    if (ctx->acc == NULL || ctx->acc_len == 0)
        return 0;

    return pqmagic_sig_sm3_mldsa_sign(ctx->key, ctx->acc, ctx->acc_len, sig,
                                      siglen, sigsize);
}

static const OSSL_DISPATCH pqmagic_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))pqmagic_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))pqmagic_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))pqmagic_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))pqmagic_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))pqmagic_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))pqmagic_sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))pqmagic_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))pqmagic_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))pqmagic_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))pqmagic_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))pqmagic_sig_gettable_ctx_params_fn },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
      (void (*)(void))pqmagic_sig_get_ctx_params },
    { 0, NULL }
};

static const OSSL_DISPATCH pqmagic_mldsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))pqmagic_km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pqmagic_km_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))mldsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))mldsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))mldsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))pqmagic_km_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pqmagic_km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))pqmagic_km_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pqmagic_km_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pqmagic_km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))pqmagic_mldsa_km_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pqmagic_km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))pqmagic_km_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))pqmagic_mldsa_km_query_operation_name },
    { 0, NULL }
};

static const OSSL_DISPATCH pqmagic_mlkem_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))pqmagic_km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pqmagic_km_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))pqmagic_km_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pqmagic_km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))pqmagic_km_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pqmagic_km_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pqmagic_km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))pqmagic_mlkem_km_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pqmagic_km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))pqmagic_km_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))pqmagic_mlkem_km_query_operation_name },
    { 0, NULL }
};

struct pqmagic_kem_ctx {
    struct pqmagic_raw_key *key;
};

static void *pqmagic_kem_newctx(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(struct pqmagic_kem_ctx));
}

static void pqmagic_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static void *pqmagic_kem_dupctx(void *vctx)
{
    struct pqmagic_kem_ctx *src = vctx;
    struct pqmagic_kem_ctx *dst;

    if (src == NULL)
        return NULL;
    dst = OPENSSL_malloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;
    *dst = *src;
    return dst;
}

static int pqmagic_kem_encapsulate_init(void *vctx, void *provkey,
                                        const OSSL_PARAM *params)
{
    struct pqmagic_kem_ctx *ctx = vctx;
    struct pqmagic_raw_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL)
        return 0;
    if (strcmp(k->oid_text, OID_MLKEM512_SPKI) != 0 || k->pk_len != MLKEM512_PK_LEN)
        return 0;
    ctx->key = k;
    return 1;
}

static int pqmagic_kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                                   unsigned char *secret, size_t *secretlen)
{
    struct pqmagic_kem_ctx *ctx = vctx;
    struct pqmagic_raw_key *k;

    if (ctx == NULL)
        return 0;
    k = ctx->key;
    if (k == NULL || strcmp(k->oid_text, OID_MLKEM512_SPKI) != 0
        || k->pk_len != MLKEM512_PK_LEN)
        return 0;
    if (out == NULL && secret == NULL) {
        if (outlen != NULL)
            *outlen = ML_KEM_512_CIPHERTEXTBYTES;
        if (secretlen != NULL)
            *secretlen = ML_KEM_512_SSBYTES;
        return 1;
    }
    if (out == NULL || secret == NULL)
        return 0;
    if (pqmagic_ml_kem_512_std_enc(out, secret, k->pk) != 0)
        return 0;
    if (outlen != NULL)
        *outlen = ML_KEM_512_CIPHERTEXTBYTES;
    if (secretlen != NULL)
        *secretlen = ML_KEM_512_SSBYTES;
    return 1;
}

static int pqmagic_kem_decapsulate_init(void *vctx, void *provkey,
                                        const OSSL_PARAM *params)
{
    struct pqmagic_kem_ctx *ctx = vctx;
    struct pqmagic_raw_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL)
        return 0;
    if (strcmp(k->oid_text, OID_MLKEM512_SPKI) != 0
        || k->sk_len != ML_KEM_512_SECRETKEYBYTES)
        return 0;
    ctx->key = k;
    return 1;
}

static int pqmagic_kem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                                   const unsigned char *in, size_t inlen)
{
    struct pqmagic_kem_ctx *ctx = vctx;
    struct pqmagic_raw_key *k;

    if (ctx == NULL)
        return 0;
    k = ctx->key;
    if (k == NULL || strcmp(k->oid_text, OID_MLKEM512_SPKI) != 0
        || k->sk_len != ML_KEM_512_SECRETKEYBYTES)
        return 0;
    if (out == NULL) {
        if (outlen != NULL)
            *outlen = ML_KEM_512_SSBYTES;
        return 1;
    }
    if (inlen != ML_KEM_512_CIPHERTEXTBYTES)
        return 0;
    if (pqmagic_ml_kem_512_std_dec(out, in, k->sk) != 0)
        return 0;
    if (outlen != NULL)
        *outlen = ML_KEM_512_SSBYTES;
    return 1;
}

static const OSSL_DISPATCH pqmagic_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))pqmagic_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))pqmagic_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))pqmagic_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))pqmagic_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))pqmagic_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))pqmagic_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))pqmagic_kem_dupctx },
    { 0, NULL }
};

static int read_core_bio(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *cin,
                         unsigned char **out, long *olen)
{
    BIO *bio = BIO_new_from_core_bio(libctx, cin);
    unsigned char tmp[4096];
    unsigned char *buf = NULL;
    size_t total = 0, cap = 0;
    int n;

    if (bio == NULL)
        return 0;
    while ((n = BIO_read(bio, tmp, sizeof(tmp))) > 0) {
        if (total + (size_t)n > cap) {
            size_t ncap = cap ? cap * 2 : 8192;
            while (ncap < total + (size_t)n)
                ncap *= 2;
            buf = OPENSSL_realloc(buf, ncap);
            if (buf == NULL) {
                BIO_free(bio);
                return 0;
            }
            cap = ncap;
        }
        memcpy(buf + total, tmp, (size_t)n);
        total += (size_t)n;
    }
    BIO_free(bio);
    *out = buf;
    *olen = (long)total;
    return 1;
}

/*
 * 手动解析 SubjectPublicKeyInfo，禁止调用 d2i_X509_PUBKEY（会再次进入
 * x509_pubkey_ex_d2i_ex → OSSL_DECODER，导致无限递归）。
 */
static int parse_spki_oid_and_bits(const unsigned char *der, long der_len,
                                   ASN1_OBJECT **oid_out,
                                   unsigned char **pk_out, int *pk_len)
{
    const unsigned char *p = der;
    long len = der_len;
    long seq_len;
    int tag, xclass;
    int inf;
    X509_ALGOR *algor = NULL;
    ASN1_BIT_STRING *bs = NULL;
    const unsigned char *q;
    long inner_left;

    inf = ASN1_get_object(&p, &seq_len, &tag, &xclass, len);
    if (inf & 0x80)
        return 0;
    /* ASN1_get_object 的 tag 为类型号，SEQUENCE 为 V_ASN1_SEQUENCE(16)，非 0x30 */
    if (tag != V_ASN1_SEQUENCE)
        return 0;
    if (seq_len < 0 || (p - der) + seq_len > der_len)
        return 0;

    q = p;
    inner_left = seq_len;
    algor = d2i_X509_ALGOR(NULL, &q, inner_left);
    if (algor == NULL)
        return 0;
    inner_left -= (long)(q - p);
    bs = d2i_ASN1_BIT_STRING(NULL, &q, inner_left);
    if (bs == NULL) {
        X509_ALGOR_free(algor);
        return 0;
    }
    *oid_out = OBJ_dup(algor->algorithm);
    *pk_out = OPENSSL_memdup(bs->data, bs->length);
    *pk_len = bs->length;
    X509_ALGOR_free(algor);
    ASN1_BIT_STRING_free(bs);
    if (*pk_out == NULL) {
        ASN1_OBJECT_free(*oid_out);
        *oid_out = NULL;
        return 0;
    }
    return *oid_out != NULL;
}

static void *spki_dec_newctx(void *provctx)
{
    struct spki_dec_ctx *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ctx->libctx = provctx;
    return ctx;
}

static void spki_dec_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int spki_dec_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int spki_dec_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                           OSSL_CALLBACK *data_cb, void *data_cbarg,
                           OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct spki_dec_ctx *ctx = vctx;
    OSSL_LIB_CTX *libctx = ctx != NULL ? ctx->libctx
                                       : OSSL_LIB_CTX_get0_global_default();
    unsigned char *der = NULL;
    long der_len = 0;
    ASN1_OBJECT *got_oid = NULL;
    ASN1_OBJECT *o304 = NULL;
    ASN1_OBJECT *o303 = NULL;
    unsigned char *pk_dup = NULL;
    int pk_len = 0;
    const unsigned char *pk_bits = NULL;
    struct pqmagic_raw_key *key = NULL;
    void *keyptr = NULL;
    int ok = 0;
    OSSL_PARAM params[4];
    int objtype = OSSL_OBJECT_PKEY;
    char data_type[256];
    int expect_len = 0;

    (void)pw_cb;
    (void)pw_cbarg;

    if (ctx != NULL)
        ctx->selection = selection;

    if (selection != 0
        && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 1;

    if (!read_core_bio(libctx, cin, &der, &der_len) || der_len <= 0)
        return 1;

    if (!parse_spki_oid_and_bits(der, der_len, &got_oid, &pk_dup, &pk_len))
        goto end;

    o304 = OBJ_txt2obj(OID_MLDSA44_SPKI, 1);
    o303 = OBJ_txt2obj(OID_MLKEM512_SPKI, 1);
    if (o304 == NULL || o303 == NULL)
        goto end;
    if (OBJ_cmp(got_oid, o304) == 0)
        expect_len = MLDSA44_PK_LEN;
    else if (OBJ_cmp(got_oid, o303) == 0)
        expect_len = MLKEM512_PK_LEN;
    else
        goto end;

    pk_bits = pk_dup;
    /* BIT STRING：首字节为 unused bits 计数，常为 0 */
    if (pk_len == expect_len + 1 && pk_bits[0] == 0) {
        pk_bits++;
        pk_len--;
    }
    if (pk_len != expect_len)
        goto end;

    /* 使用数字 OID，与 km_import / 验签中的 strcmp 一致（避免 OBJ 注册名与数字串混用） */
    if (OBJ_obj2txt(data_type, sizeof(data_type), got_oid, 1) <= 0)
        goto end;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto end;
    memcpy(key->pk, pk_bits, (size_t)expect_len);
    key->pk_len = (size_t)expect_len;
    snprintf(key->oid_text, sizeof(key->oid_text), "%s", data_type);

    keyptr = key;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objtype);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 data_type, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &keyptr, sizeof(keyptr));
    params[3] = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);
    if (ok)
        key = NULL;

end:
    pqmagic_km_free(key);
    OPENSSL_free(pk_dup);
    ASN1_OBJECT_free(got_oid);
    ASN1_OBJECT_free(o304);
    ASN1_OBJECT_free(o303);
    OPENSSL_free(der);
    return 1;
}

static int spki_dec_export_object(void *vctx, const void *reference,
                                  size_t reference_sz,
                                  OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    struct spki_dec_ctx *ctx = vctx;

    if (reference_sz != sizeof(void *))
        return 0;
    return pqmagic_km_export(*(void **)reference,
                             ctx != NULL ? ctx->selection
                                         : OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                             export_cb, export_cbarg);
}

static int pkcs8_dec_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int pkcs8_dec_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                            OSSL_CALLBACK *data_cb, void *data_cbarg,
                            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct spki_dec_ctx *ctx = vctx;
    OSSL_LIB_CTX *libctx = ctx != NULL ? ctx->libctx
                                       : OSSL_LIB_CTX_get0_global_default();
    unsigned char *der = NULL;
    long der_len = 0;
    const unsigned char *p = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const ASN1_OBJECT *algoid = NULL;
    const unsigned char *pkey = NULL;
    int pkeylen = 0;
    struct pqmagic_raw_key *key = NULL;
    void *keyptr = NULL;
    int ok = 0;
    OSSL_PARAM params[4];
    int objtype = OSSL_OBJECT_PKEY;
    char data_type[256];

    (void)pw_cb;
    (void)pw_cbarg;

    if (selection != 0
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        return 1;

    if (!read_core_bio(libctx, cin, &der, &der_len) || der_len <= 0)
        return 1;

    p = der;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, der_len);
    if (p8 == NULL)
        goto end;

    if (!PKCS8_pkey_get0(&algoid, &pkey, &pkeylen, NULL, p8))
        goto end;

    if (OBJ_obj2txt(data_type, sizeof(data_type), algoid, 1) <= 0)
        goto end;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto end;

    if (strcmp(data_type, OID_MLKEM512_SPKI) == 0) {
        if (pkeylen != ML_KEM_512_SECRETKEYBYTES)
            goto end;
        memcpy(key->sk, pkey, (size_t)pkeylen);
        key->sk_len = (size_t)pkeylen;
        snprintf(key->oid_text, sizeof(key->oid_text), "%s", OID_MLKEM512_SPKI);
    } else if (strcmp(data_type, OID_MLDSA44_SPKI) == 0) {
        if (pkeylen != MLDSA44_SK_LEN)
            goto end;
        memcpy(key->sk, pkey, (size_t)pkeylen);
        key->sk_len = (size_t)pkeylen;
        snprintf(key->oid_text, sizeof(key->oid_text), "%s", OID_MLDSA44_SPKI);
        if (!pqmagic_pkcs8_get_embedded_pubkey(p8, key->pk, sizeof(key->pk),
                                               &key->pk_len))
            key->pk_len = 0;
    } else {
        goto end;
    }

    keyptr = key;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objtype);
    /* 与 keymgmt 算法首名一致，便于 OSSL_DECODER 导入 EVP_PKEY */
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_OBJECT_PARAM_DATA_TYPE,
        strcmp(key->oid_text, OID_MLKEM512_SPKI) == 0
            ? "id-ML-KEM-512-SPKI"
            : "id-ML-DSA-44-SPKI",
        0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                &keyptr, sizeof(keyptr));
    params[3] = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);
    if (ok)
        key = NULL;

end:
    pqmagic_km_free(key);
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_free(der);
    return 1;
}

static const OSSL_DISPATCH pqmagic_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))spki_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))spki_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))spki_dec_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))spki_dec_decode },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,
      (void (*)(void))spki_dec_export_object },
    { 0, NULL }
};

static const OSSL_DISPATCH pqmagic_pkcs8_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))spki_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))spki_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))pkcs8_dec_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))pkcs8_dec_decode },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,
      (void (*)(void))spki_dec_export_object },
    { 0, NULL }
};

/* ---------- TEXT encoder：供 EVP_PKEY_print_public / openssl x509 -text 显示公钥 ---------- */

#define LABELED_BUF_PRINT_WIDTH 15

static int print_labeled_buf(BIO *out, const char *label,
                             const unsigned char *buf, size_t buflen)
{
    size_t i;

    if (BIO_printf(out, "%s\n", label) <= 0)
        return 0;
    for (i = 0; i < buflen; i++) {
        if ((i % LABELED_BUF_PRINT_WIDTH) == 0) {
            if (i > 0 && BIO_printf(out, "\n") <= 0)
                return 0;
            if (BIO_printf(out, "    ") <= 0)
                return 0;
        }
        if (BIO_printf(out, "%02x%s", buf[i], (i == buflen - 1) ? "" : ":") <= 0)
            return 0;
    }
    return BIO_printf(out, "\n") > 0;
}

static int pqmagic_pubkey_to_text(BIO *out, const void *key, int selection)
{
    const struct pqmagic_raw_key *k = key;

    if (k == NULL || k->pk_len == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    if (strcmp(k->oid_text, OID_MLDSA44_SPKI) == 0) {
        if (BIO_printf(out,
                       "ML-DSA-44 Public-Key (%u bytes, OID %s, PQMagic):\n",
                       (unsigned)k->pk_len, OID_MLDSA44_SPKI) <= 0)
            return 0;
    } else if (strcmp(k->oid_text, OID_MLKEM512_SPKI) == 0) {
        if (BIO_printf(out,
                       "ML-KEM-512 KEM Public-Key (%u bytes, OID %s, post-quantum / 抗量子, PQMagic):\n",
                       (unsigned)k->pk_len, OID_MLKEM512_SPKI) <= 0)
            return 0;
    } else {
        if (BIO_printf(out, "Public-Key (%u bytes, OID %s):\n",
                       (unsigned)k->pk_len, k->oid_text) <= 0)
            return 0;
    }
    return print_labeled_buf(out, "pub:", k->pk, k->pk_len);
}

static void *pqmagic2text_import_object(void *ctx, int selection,
                                        const OSSL_PARAM params[])
{
    void *key = pqmagic_km_new(ctx);

    if (key == NULL)
        return NULL;
    if (!pqmagic_km_import(key, selection, params)) {
        pqmagic_km_free(key);
        return NULL;
    }
    return key;
}

static void pqmagic2text_free_object(void *key)
{
    pqmagic_km_free(key);
}

static void *pqmagic2text_newctx(void *provctx)
{
    return provctx;
}

static void pqmagic2text_freectx(void *vctx)
{
    (void)vctx;
}

static int pqmagic2text_encode(void *vctx, OSSL_CORE_BIO *cout, const void *key,
                               const OSSL_PARAM *key_abstract, int selection,
                               OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *bout;
    int ret;

    (void)cb;
    (void)cbarg;
    if (key_abstract != NULL)
        return 0;
    bout = BIO_new_from_core_bio(vctx, cout);
    if (bout == NULL)
        return 0;
    ret = pqmagic_pubkey_to_text(bout, key, selection);
    BIO_free(bout);
    return ret;
}

static const OSSL_DISPATCH pqmagic_text_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))pqmagic2text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))pqmagic2text_freectx },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,
      (void (*)(void))pqmagic2text_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))pqmagic2text_free_object },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))pqmagic2text_encode },
    { 0, NULL }
};

/* ---------- DER encoder：供 X509_PUBKEY_set / openssl req -new 编码 SPKI ---------- */

static int pqmagic_pubkey_to_spki_der(const struct pqmagic_raw_key *k,
                                      unsigned char **out, size_t *outlen)
{
    ASN1_OBJECT *oid = NULL;
    X509_PUBKEY *xpub = NULL;
    unsigned char *penc = NULL;
    unsigned char *der = NULL;
    int len;

    if (k == NULL || k->pk_len == 0 || out == NULL || outlen == NULL)
        return 0;

    oid = OBJ_txt2obj(k->oid_text, 1);
    if (oid == NULL)
        return 0;

    xpub = X509_PUBKEY_new();
    penc = OPENSSL_memdup(k->pk, k->pk_len);
    if (xpub == NULL || penc == NULL)
        goto err;

    if (!X509_PUBKEY_set0_param(xpub, oid, V_ASN1_UNDEF, NULL, penc,
                                (int)k->pk_len))
        goto err;
    oid = NULL;
    penc = NULL;

    len = i2d_X509_PUBKEY(xpub, &der);
    if (len <= 0)
        goto err;

    *out = der;
    *outlen = (size_t)len;
    X509_PUBKEY_free(xpub);
    return 1;

err:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(penc);
    OPENSSL_free(der);
    X509_PUBKEY_free(xpub);
    return 0;
}

static int pqmagic2der_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int pqmagic2der_encode(void *vctx, OSSL_CORE_BIO *cout, const void *key,
                              const OSSL_PARAM *key_abstract, int selection,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *bout;
    const struct pqmagic_raw_key *k = key;
    unsigned char *der = NULL;
    size_t derlen = 0;
    int ret = 0;

    (void)cb;
    (void)cbarg;
    if (key_abstract != NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    if (!pqmagic_pubkey_to_spki_der(k, &der, &derlen))
        return 0;

    bout = BIO_new_from_core_bio(vctx, cout);
    if (bout == NULL)
        goto end;
    ret = BIO_write(bout, der, (int)derlen) == (int)derlen;
    BIO_free(bout);

end:
    OPENSSL_free(der);
    return ret;
}

static const OSSL_DISPATCH pqmagic_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))pqmagic2text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))pqmagic2text_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))pqmagic2der_does_selection },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,
      (void (*)(void))pqmagic2text_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))pqmagic2text_free_object },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))pqmagic2der_encode },
    { 0, NULL }
};

static int pqmagic_pkcs8_get_embedded_pubkey(const PKCS8_PRIV_KEY_INFO *p8,
                                           unsigned char *pk, size_t pk_cap,
                                           size_t *pk_len)
{
    const STACK_OF(X509_ATTRIBUTE) *attrs;
    ASN1_OBJECT *want = NULL;
    int i, n, ok = 0;

    if (p8 == NULL || pk == NULL || pk_len == NULL)
        return 0;

    want = OBJ_txt2obj(OID_MLDSA44_PKCS8_PUB, 1);
    if (want == NULL)
        return 0;

    attrs = PKCS8_pkey_get0_attrs(p8);
    if (attrs == NULL)
        goto end;

    n = sk_X509_ATTRIBUTE_num(attrs);
    for (i = 0; i < n; i++) {
        X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value(attrs, i);
        ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(attr);
        ASN1_TYPE *at;
        const unsigned char *data;
        int len;

        if (obj == NULL || OBJ_cmp(obj, want) != 0)
            continue;
        if (X509_ATTRIBUTE_count(attr) != 1)
            continue;
        at = X509_ATTRIBUTE_get0_type(attr, 0);
        if (at == NULL || at->type != V_ASN1_OCTET_STRING)
            continue;
        data = at->value.octet_string->data;
        len = at->value.octet_string->length;
        if (len != MLDSA44_PK_LEN || (size_t)len > pk_cap)
            goto end;
        memcpy(pk, data, (size_t)len);
        *pk_len = (size_t)len;
        ok = 1;
        break;
    }

end:
    ASN1_OBJECT_free(want);
    return ok;
}

static int pqmagic_sk_to_pkcs8_der(const struct pqmagic_raw_key *k,
                                   unsigned char **out, size_t *outlen)
{
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *skdup = NULL;
    unsigned char *der = NULL;
    int len;

    if (k == NULL || k->sk_len == 0 || out == NULL || outlen == NULL)
        return 0;

    oid = OBJ_txt2obj(k->oid_text, 1);
    skdup = OPENSSL_memdup(k->sk, k->sk_len);
    p8 = PKCS8_PRIV_KEY_INFO_new();
    if (oid == NULL || skdup == NULL || p8 == NULL)
        goto err;

    if (!PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, skdup, (int)k->sk_len))
        goto err;
    oid = NULL;
    skdup = NULL;

    if (k->pk_len == MLDSA44_PK_LEN) {
        ASN1_OBJECT *pub_attr = OBJ_txt2obj(OID_MLDSA44_PKCS8_PUB, 1);

        if (pub_attr != NULL) {
            if (!PKCS8_pkey_add1_attr_by_OBJ(p8, pub_attr, V_ASN1_OCTET_STRING,
                                             k->pk, (int)k->pk_len)) {
                ASN1_OBJECT_free(pub_attr);
                goto err;
            }
            ASN1_OBJECT_free(pub_attr);
        }
    }

    len = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
    if (len <= 0)
        goto err;

    *out = der;
    *outlen = (size_t)len;
    PKCS8_PRIV_KEY_INFO_free(p8);
    return 1;

err:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(skdup);
    OPENSSL_free(der);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return 0;
}

static int pqmagic2der_pkcs8_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int pqmagic2der_pkcs8_encode(void *vctx, OSSL_CORE_BIO *cout,
                                    const void *key,
                                    const OSSL_PARAM *key_abstract,
                                    int selection,
                                    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *bout;
    const struct pqmagic_raw_key *k = key;
    unsigned char *der = NULL;
    size_t derlen = 0;
    int ret = 0;

    (void)cb;
    (void)cbarg;
    if (key_abstract != NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        return 0;
    if (!pqmagic_sk_to_pkcs8_der(k, &der, &derlen))
        return 0;

    bout = BIO_new_from_core_bio(vctx, cout);
    if (bout == NULL)
        goto end;
    ret = BIO_write(bout, der, (int)derlen) == (int)derlen;
    BIO_free(bout);

end:
    OPENSSL_free(der);
    return ret;
}

static const OSSL_DISPATCH pqmagic_pkcs8_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))pqmagic2text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))pqmagic2text_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))pqmagic2der_pkcs8_does_selection },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,
      (void (*)(void))pqmagic2text_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))pqmagic2text_free_object },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))pqmagic2der_pkcs8_encode },
    { 0, NULL }
};

static int pqmagic2pem_pkcs8_encode(void *vctx, OSSL_CORE_BIO *cout,
                                    const void *key,
                                    const OSSL_PARAM *key_abstract,
                                    int selection,
                                    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *bout;
    const struct pqmagic_raw_key *k = key;
    unsigned char *der = NULL;
    size_t derlen = 0;
    int ret = 0;

    (void)cb;
    (void)cbarg;
    if (key_abstract != NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        return 0;
    if (!pqmagic_sk_to_pkcs8_der(k, &der, &derlen))
        return 0;

    bout = BIO_new_from_core_bio(vctx, cout);
    if (bout == NULL)
        goto end;
    {
        const unsigned char *p = der;
        PKCS8_PRIV_KEY_INFO *p8 =
            d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)derlen);

        if (p8 == NULL)
            goto end;
        ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bout, p8);
        PKCS8_PRIV_KEY_INFO_free(p8);
    }
    BIO_free(bout);

end:
    OPENSSL_free(der);
    return ret;
}

static const OSSL_DISPATCH pqmagic_pkcs8_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))pqmagic2text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))pqmagic2text_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))pqmagic2der_pkcs8_does_selection },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,
      (void (*)(void))pqmagic2text_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))pqmagic2text_free_object },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))pqmagic2pem_pkcs8_encode },
    { 0, NULL }
};

static void provider_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(provctx);
}

static const OSSL_PARAM provider_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *provider_gettable_params(void *provctx)
{
    (void)provctx;
    return provider_param_types;
}

static int provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "pqmagic"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM pqmagic_keymgmt[] = {
    { "id-ML-DSA-44-SPKI:ML-DSA-44-SPKI:" OID_MLDSA44_SPKI,
      "provider=pqmagic", pqmagic_mldsa_keymgmt_functions },
    { "id-ML-KEM-512-SPKI:ML-KEM-512-SPKI:" OID_MLKEM512_SPKI,
      "provider=pqmagic", pqmagic_mlkem_keymgmt_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pqmagic_signatures[] = {
    { "ML-DSA-44-with-SM3", "provider=pqmagic", pqmagic_signature_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pqmagic_kem_algs[] = {
    { "id-ML-KEM-512-SPKI", "provider=pqmagic", pqmagic_kem_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pqmagic_decoders[] = {
    { OID_MLDSA44_SPKI,
      "provider=pqmagic,input=der,structure=SubjectPublicKeyInfo",
      pqmagic_decoder_functions },
    { OID_MLKEM512_SPKI,
      "provider=pqmagic,input=der,structure=SubjectPublicKeyInfo",
      pqmagic_decoder_functions },
    { OID_MLDSA44_SPKI,
      "provider=pqmagic,input=der,structure=PrivateKeyInfo",
      pqmagic_pkcs8_decoder_functions },
    { OID_MLKEM512_SPKI,
      "provider=pqmagic,input=der,structure=PrivateKeyInfo",
      pqmagic_pkcs8_decoder_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pqmagic_encoders[] = {
    { "id-ML-DSA-44-SPKI:ML-DSA-44-SPKI:" OID_MLDSA44_SPKI,
      "provider=pqmagic,output=der,structure=SubjectPublicKeyInfo",
      pqmagic_der_encoder_functions },
    { "id-ML-DSA-44-SPKI:ML-DSA-44-SPKI:" OID_MLDSA44_SPKI,
      "provider=pqmagic,output=der,structure=PrivateKeyInfo",
      pqmagic_pkcs8_der_encoder_functions },
    { "id-ML-DSA-44-SPKI:ML-DSA-44-SPKI:" OID_MLDSA44_SPKI,
      "provider=pqmagic,output=pem,structure=PrivateKeyInfo",
      pqmagic_pkcs8_pem_encoder_functions },
    { "id-ML-KEM-512-SPKI:ML-KEM-512-SPKI:" OID_MLKEM512_SPKI,
      "provider=pqmagic,output=der,structure=SubjectPublicKeyInfo",
      pqmagic_der_encoder_functions },
    { "id-ML-DSA-44-SPKI:ML-DSA-44-SPKI:" OID_MLDSA44_SPKI,
      "provider=pqmagic,output=text", pqmagic_text_encoder_functions },
    { "id-ML-KEM-512-SPKI:ML-KEM-512-SPKI:" OID_MLKEM512_SPKI,
      "provider=pqmagic,output=text", pqmagic_text_encoder_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *provider_query(void *provctx, int operation_id,
                                            int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return pqmagic_keymgmt;
    case OSSL_OP_DECODER:
        return pqmagic_decoders;
    case OSSL_OP_ENCODER:
        return pqmagic_encoders;
    case OSSL_OP_SIGNATURE:
        return pqmagic_signatures;
    case OSSL_OP_KEM:
        return pqmagic_kem_algs;
    default:
        return NULL;
    }
}

static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provider_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);

    if (libctx == NULL)
        return 0;
    *provctx = libctx;
    *out = provider_functions;
    return 1;
}
