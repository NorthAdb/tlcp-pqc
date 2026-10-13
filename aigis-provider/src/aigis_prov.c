/*
 * OpenSSL 3 provider: Aigis-SIG1 / Aigis-Enc-1
 * - 裸 SPKI 解码与公钥打印（305.1 / 306.1）
 * - 串联 SPKI 解码与打印（511.1 / 512.1 = PQC‖SM2）
 * - 签名 Aigis-SIG1-with-SM3（SM3(TBS) → PQMagic verify）
 * - KEM Aigis-Enc-1
 * 依赖 PQMagic libpqmagic_std
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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include <pqmagic_api.h>

#include "aigis_cert.h"

#define OID_SIG1   AIGIS_OID_SIG1_SPKI
#define OID_ENC1   AIGIS_OID_ENC1_SPKI
#define OID_SIG1H  AIGIS_OID_SIG1_SM2_SPKI
#define OID_ENC1H  AIGIS_OID_ENC1_SM2_SPKI
#define OID_SIG1_WITH_SM3 AIGIS_OID_SIG1_WITH_SM3
#define AIGIS_SIG1_SK_PK_LEN (AIGIS_SIG1_SK_LEN + AIGIS_SIG1_PK_LEN)

#define PK_MAX (AIGIS_SIG1_PK_LEN + AIGIS_SM2_PK_LEN)

struct aigis_key {
    unsigned char pk[PK_MAX];
    size_t pk_len;       /* 裸或串联总长 */
    size_t aigis_len;    /* 前段 Aigis 长度 */
    unsigned char sk[AIGIS_SIG1_SK_LEN];
    size_t sk_len;
    char oid_text[64];
    int is_sig;
    int is_hybrid;
};

struct aigis_sig_ctx {
    OSSL_LIB_CTX *libctx;
    struct aigis_key *key;
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

static void aigis_register_oids(void)
{
    aigis_cert_register_oids();
}

static void *aigis_km_new(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(struct aigis_key));
}

static void aigis_km_free(void *keydata)
{
    struct aigis_key *k = keydata;

    if (k == NULL)
        return;
    OPENSSL_cleanse(k->sk, sizeof(k->sk));
    OPENSSL_free(k);
}

static void *aigis_km_load(const void *reference, size_t reference_sz)
{
    struct aigis_key *key;

    if (reference_sz != sizeof(key))
        return NULL;
    key = *(struct aigis_key *const *)reference;
    *(struct aigis_key **)reference = NULL;
    return key;
}

static int aigis_km_has(const void *keydata, int selection)
{
    const struct aigis_key *k = keydata;

    if (k == NULL || (k->pk_len == 0 && k->sk_len == 0))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0
        || (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        return 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return k->pk_len > 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return k->sk_len > 0;
    return 1;
}

static const OSSL_PARAM aigis_import_pub[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM aigis_import_priv[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

/* 私钥导出同时带上公钥，供 PKCS#8 写成 SK‖PK，解码后 req -new 能还原 SPKI */
static const OSSL_PARAM aigis_export_keypair[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *aigis_km_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return aigis_import_pub;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return aigis_import_priv;
    return NULL;
}

static int aigis_km_import(void *keydata, int selection,
                           const OSSL_PARAM params[])
{
    struct aigis_key *k = keydata;
    const OSSL_PARAM *p;
    int got = 0;

    (void)selection;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        void *vp = k->pk;
        size_t plen = 0;

        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(k->pk), &plen))
            return 0;
        if (plen == AIGIS_SIG1_PK_LEN) {
            snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_SIG1);
            k->is_sig = 1;
            k->is_hybrid = 0;
            k->aigis_len = plen;
        } else if (plen == AIGIS_ENC1_PK_LEN) {
            snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_ENC1);
            k->is_sig = 0;
            k->is_hybrid = 0;
            k->aigis_len = plen;
        } else if (plen == AIGIS_SIG1_PK_LEN + AIGIS_SM2_PK_LEN) {
            snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_SIG1H);
            k->is_sig = 1;
            k->is_hybrid = 1;
            k->aigis_len = AIGIS_SIG1_PK_LEN;
        } else if (plen == AIGIS_ENC1_PK_LEN + AIGIS_SM2_PK_LEN) {
            snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_ENC1H);
            k->is_sig = 0;
            k->is_hybrid = 1;
            k->aigis_len = AIGIS_ENC1_PK_LEN;
        } else {
            return 0;
        }
        k->pk_len = plen;
        got = 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        unsigned char tmp[AIGIS_SIG1_SK_PK_LEN];
        void *vp = tmp;
        size_t plen = 0;

        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(tmp), &plen))
            return 0;
        if (plen == AIGIS_SIG1_SK_LEN) {
            snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_SIG1);
            k->is_sig = 1;
            memcpy(k->sk, tmp, plen);
            k->sk_len = plen;
        } else if (plen == AIGIS_SIG1_SK_PK_LEN) {
            /* 样证 PEM：SK(2448)‖PK(1056) */
            snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_SIG1);
            k->is_sig = 1;
            memcpy(k->sk, tmp, AIGIS_SIG1_SK_LEN);
            k->sk_len = AIGIS_SIG1_SK_LEN;
            memcpy(k->pk, tmp + AIGIS_SIG1_SK_LEN, AIGIS_SIG1_PK_LEN);
            k->pk_len = AIGIS_SIG1_PK_LEN;
            k->aigis_len = AIGIS_SIG1_PK_LEN;
        } else if (plen == AIGIS_ENC1_SK_LEN) {
            snprintf(k->oid_text, sizeof(k->oid_text), "%s", OID_ENC1);
            k->is_sig = 0;
            memcpy(k->sk, tmp, plen);
            k->sk_len = plen;
        } else {
            return 0;
        }
        got = 1;
    }
    return got;
}

static int aigis_km_export(void *keydata, int selection,
                           OSSL_CALLBACK *param_cb, void *cbarg)
{
    struct aigis_key *k = keydata;
    OSSL_PARAM params[3];
    unsigned char priv[AIGIS_SIG1_SK_PK_LEN];
    size_t priv_len = 0;
    int n = 0;

    if (k == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && k->sk_len > 0) {
        if (k->is_sig && !k->is_hybrid
            && k->sk_len == AIGIS_SIG1_SK_LEN
            && k->pk_len == AIGIS_SIG1_PK_LEN) {
            memcpy(priv, k->sk, AIGIS_SIG1_SK_LEN);
            memcpy(priv + AIGIS_SIG1_SK_LEN, k->pk, AIGIS_SIG1_PK_LEN);
            priv_len = AIGIS_SIG1_SK_PK_LEN;
        } else if (k->sk_len <= sizeof(priv)) {
            memcpy(priv, k->sk, k->sk_len);
            priv_len = k->sk_len;
        } else {
            return 0;
        }
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && k->pk_len > 0) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, (void *)k->pk, k->pk_len);
    }
    if (n == 0)
        return 0;
    params[n] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM *aigis_sig_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return aigis_export_keypair;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return aigis_import_pub;
    return NULL;
}

static const OSSL_PARAM aigis_gettable[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *aigis_km_gettable_params(void *provctx)
{
    (void)provctx;
    return aigis_gettable;
}

static int aigis_km_get_params(void *keydata, OSSL_PARAM params[])
{
    struct aigis_key *k = keydata;
    OSSL_PARAM *p;
    char desc[256];

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        if (k->is_hybrid)
            snprintf(desc, sizeof(desc), "Aigis-%s-SM2 hybrid (OID %s)",
                     k->is_sig ? "SIG1" : "Enc-1", k->oid_text);
        else
            snprintf(desc, sizeof(desc), "Aigis-%s (OID %s)",
                     k->is_sig ? "SIG1" : "Enc-1", k->oid_text);
        if (!OSSL_PARAM_set_utf8_string(p, desc))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, k->pk, k->pk_len))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, (int)(k->aigis_len * 8)))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) {
        int mx = k->is_sig ? (int)AIGIS_SIG1_SIG_LEN : (int)AIGIS_ENC1_CT_LEN;

        if (!OSSL_PARAM_set_int(p, mx))
            return 0;
    }
    return 1;
}

static const char *aigis_sig_km_query(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
        return "Aigis-SIG1-with-SM3";
    return NULL;
}

static const char *aigis_kem_km_query(int operation_id)
{
    if (operation_id == OSSL_OP_KEM)
        return "Aigis-Enc-1";
    return NULL;
}

/* ---------- signature ---------- */

static void *aigis_sig_newctx(void *provctx, const char *propq)
{
    struct aigis_sig_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));

    (void)propq;
    if (ctx != NULL)
        ctx->libctx = provctx;
    return ctx;
}

static void aigis_sig_freectx(void *vctx)
{
    struct aigis_sig_ctx *ctx = vctx;

    if (ctx == NULL)
        return;
    OPENSSL_free(ctx->acc);
    OPENSSL_free(ctx);
}

static void *aigis_sig_dupctx(void *vctx)
{
    struct aigis_sig_ctx *src = vctx, *dst;

    if (src == NULL)
        return NULL;
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;
    *dst = *src;
    dst->acc = NULL;
    dst->acc_len = dst->acc_cap = 0;
    if (src->acc_len > 0) {
        dst->acc = OPENSSL_memdup(src->acc, src->acc_len);
        if (dst->acc == NULL) {
            OPENSSL_free(dst);
            return NULL;
        }
        dst->acc_len = dst->acc_cap = src->acc_len;
    }
    return dst;
}

static int acc_append(struct aigis_sig_ctx *ctx, const unsigned char *data,
                      size_t datalen)
{
    size_t need, ncap;

    if (datalen == 0)
        return 1;
    need = ctx->acc_len + datalen;
    if (need > ctx->acc_cap) {
        ncap = ctx->acc_cap ? ctx->acc_cap : 4096;
        while (ncap < need)
            ncap *= 2;
        ctx->acc = OPENSSL_realloc(ctx->acc, ncap);
        if (ctx->acc == NULL)
            return 0;
        ctx->acc_cap = ncap;
    }
    memcpy(ctx->acc + ctx->acc_len, data, datalen);
    ctx->acc_len = need;
    return 1;
}

static int aigis_sig_verify_init(void *vctx, const char *mdname, void *provkey,
                                 const OSSL_PARAM *params)
{
    struct aigis_sig_ctx *ctx = vctx;
    struct aigis_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL || !k->is_sig)
        return 0;
    if (k->aigis_len != AIGIS_SIG1_PK_LEN && k->pk_len < AIGIS_SIG1_PK_LEN)
        return 0;
    if (mdname != NULL && OPENSSL_strcasecmp(mdname, "sm3") != 0)
        return 0;
    ctx->key = k;
    ctx->acc_len = 0;
    OPENSSL_free(ctx->acc);
    ctx->acc = NULL;
    ctx->acc_cap = 0;
    return 1;
}

static int aigis_sig_verify_update(void *vctx, const unsigned char *data,
                                   size_t datalen)
{
    return acc_append(vctx, data, datalen);
}

static int aigis_sig_verify_final(void *vctx, const unsigned char *sig,
                                  size_t siglen)
{
    struct aigis_sig_ctx *ctx = vctx;
    unsigned char sm3[32];
    unsigned int sm3_len = sizeof(sm3);
    EVP_MD_CTX *mdc;
    int r;
    const unsigned char *pk;

    if (ctx == NULL || ctx->key == NULL || ctx->acc == NULL || ctx->acc_len == 0)
        return 0;
    if (siglen != AIGIS_SIG1_SIG_LEN)
        return 0;
    pk = ctx->key->pk;
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
    /* 与国密样证一致：internal 验签，消息为 SM3(累积数据) */
    r = pqmagic_aigis_sig1_std_verify_internal(sig, siglen, sm3, 32, pk);
    return r == 0;
}

static int aigis_sig_build_aid(struct aigis_sig_ctx *ctx)
{
    X509_ALGOR *algor = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *der = NULL;
    int len;

    if (ctx == NULL)
        return 0;
    ctx->aid_len = 0;
    oid = OBJ_txt2obj(OID_SIG1_WITH_SM3, 1);
    algor = X509_ALGOR_new();
    if (oid == NULL || algor == NULL)
        goto end;
    if (!X509_ALGOR_set0(algor, oid, V_ASN1_UNDEF, NULL))
        goto end;
    oid = NULL;
    len = i2d_X509_ALGOR(algor, &der);
    if (len <= 0 || (size_t)len > sizeof(ctx->aid_buf))
        goto end;
    memcpy(ctx->aid_buf, der, (size_t)len);
    ctx->aid_len = (size_t)len;
end:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(der);
    X509_ALGOR_free(algor);
    return ctx->aid_len > 0;
}

static const OSSL_PARAM aigis_sig_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *aigis_sig_gettable_ctx_params_fn(void *vctx,
                                                         void *provctx)
{
    (void)vctx;
    (void)provctx;
    return aigis_sig_gettable_ctx_params;
}

static int aigis_sig_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    struct aigis_sig_ctx *ctx = vctx;
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

static int aigis_sig_sign_init(void *vctx, const char *mdname, void *provkey,
                               const OSSL_PARAM *params)
{
    struct aigis_sig_ctx *ctx = vctx;
    struct aigis_key *k = provkey;

    (void)params;
    /* req -new 常传入默认摘要名；签名在 final 里固定对原文做 SM3 */
    (void)mdname;
    if (ctx == NULL || k == NULL || k->sk_len != AIGIS_SIG1_SK_LEN)
        return 0;
    ctx->key = k;
    ctx->acc_len = 0;
    OPENSSL_free(ctx->acc);
    ctx->acc = NULL;
    ctx->acc_cap = 0;
    return aigis_sig_build_aid(ctx);
}

static int aigis_sig_sign_update(void *vctx, const unsigned char *data,
                                 size_t datalen)
{
    return acc_append(vctx, data, datalen);
}

static int aigis_sig_sign_final(void *vctx, unsigned char *sig, size_t *siglen,
                                size_t sigsize)
{
    struct aigis_sig_ctx *ctx = vctx;
    unsigned char sm3[32];
    unsigned int sm3_len = sizeof(sm3);
    EVP_MD_CTX *mdc;
    size_t slen = AIGIS_SIG1_SIG_LEN;
    int r;

    if (ctx == NULL || ctx->key == NULL || ctx->acc == NULL)
        return 0;
    if (sig == NULL) {
        *siglen = AIGIS_SIG1_SIG_LEN;
        return 1;
    }
    if (sigsize < AIGIS_SIG1_SIG_LEN)
        return 0;
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
    r = pqmagic_aigis_sig1_std_signature_internal(sig, &slen, sm3, 32,
                                                  ctx->key->sk);
    if (r != 0 || slen != AIGIS_SIG1_SIG_LEN)
        return 0;
    *siglen = slen;
    return 1;
}

static int aigis_sig_digest_sign(void *vctx, unsigned char *sig, size_t *siglen,
                                 size_t sigsize, const unsigned char *data,
                                 size_t datalen)
{
    struct aigis_sig_ctx *ctx = vctx;
    unsigned char sm3[32];
    unsigned int sm3_len = sizeof(sm3);
    EVP_MD_CTX *mdc;
    size_t slen = AIGIS_SIG1_SIG_LEN;
    int r;

    if (ctx == NULL || ctx->key == NULL || data == NULL)
        return 0;
    if (sig == NULL) {
        *siglen = AIGIS_SIG1_SIG_LEN;
        return 1;
    }
    if (sigsize < AIGIS_SIG1_SIG_LEN)
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
    r = pqmagic_aigis_sig1_std_signature_internal(sig, &slen, sm3, 32,
                                                  ctx->key->sk);
    if (r != 0 || slen != AIGIS_SIG1_SIG_LEN)
        return 0;
    *siglen = slen;
    return 1;
}

/* ---------- KEM Enc-1 ---------- */

struct aigis_kem_ctx {
    struct aigis_key *key;
};

static void *aigis_kem_newctx(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(struct aigis_kem_ctx));
}

static void aigis_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int aigis_kem_encapsulate_init(void *vctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    struct aigis_kem_ctx *ctx = vctx;
    struct aigis_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL || k->is_sig)
        return 0;
    if (k->aigis_len != AIGIS_ENC1_PK_LEN && k->pk_len < AIGIS_ENC1_PK_LEN)
        return 0;
    ctx->key = k;
    return 1;
}

static int aigis_kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                                 unsigned char *secret, size_t *secretlen)
{
    struct aigis_kem_ctx *ctx = vctx;
    int r;

    if (ctx == NULL || ctx->key == NULL)
        return 0;
    if (out == NULL && secret == NULL) {
        if (outlen != NULL)
            *outlen = AIGIS_ENC1_CT_LEN;
        if (secretlen != NULL)
            *secretlen = AIGIS_ENC1_SS_LEN;
        return 1;
    }
    if (out == NULL || secret == NULL)
        return 0;
    r = pqmagic_aigis_enc_1_std_enc(out, secret, ctx->key->pk);
    if (r != 0)
        return 0;
    if (outlen != NULL)
        *outlen = AIGIS_ENC1_CT_LEN;
    if (secretlen != NULL)
        *secretlen = AIGIS_ENC1_SS_LEN;
    return 1;
}

static int aigis_kem_decapsulate_init(void *vctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    struct aigis_kem_ctx *ctx = vctx;
    struct aigis_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL || k->sk_len != AIGIS_ENC1_SK_LEN)
        return 0;
    ctx->key = k;
    return 1;
}

static int aigis_kem_decapsulate(void *vctx, unsigned char *secret,
                                 size_t *secretlen, const unsigned char *in,
                                 size_t inlen)
{
    struct aigis_kem_ctx *ctx = vctx;
    int r;

    if (ctx == NULL || ctx->key == NULL)
        return 0;
    if (secret == NULL) {
        if (secretlen != NULL)
            *secretlen = AIGIS_ENC1_SS_LEN;
        return 1;
    }
    if (in == NULL || inlen != AIGIS_ENC1_CT_LEN)
        return 0;
    r = pqmagic_aigis_enc_1_std_dec(secret, in, ctx->key->sk);
    if (r != 0)
        return 0;
    if (secretlen != NULL)
        *secretlen = AIGIS_ENC1_SS_LEN;
    return 1;
}

/* ---------- SPKI decoder ---------- */

static int read_core_bio(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *cin,
                         unsigned char **out, long *outlen)
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
    *outlen = (long)total;
    return 1;
}

static int parse_spki_oid_and_bits(const unsigned char *der, long der_len,
                                   ASN1_OBJECT **oid_out,
                                   unsigned char **bits_out, int *bits_len)
{
    const unsigned char *p = der;
    long len = der_len;
    int tag, xclass;
    long seqlen;
    const unsigned char *q;
    long left;
    X509_ALGOR *algor = NULL;
    ASN1_BIT_STRING *bs = NULL;
    int ok = 0;

    if (ASN1_get_object(&p, &seqlen, &tag, &xclass, len) & 0x80)
        return 0;
    if (tag != V_ASN1_SEQUENCE)
        return 0;
    q = p;
    left = seqlen;
    algor = d2i_X509_ALGOR(NULL, &q, left);
    if (algor == NULL)
        return 0;
    *oid_out = OBJ_dup(algor->algorithm);
    left -= (long)(q - p);
    p = q;
    bs = d2i_ASN1_BIT_STRING(NULL, &q, left);
    if (bs == NULL || *oid_out == NULL)
        goto end;
    *bits_len = ASN1_STRING_length(bs);
    *bits_out = OPENSSL_memdup(ASN1_STRING_get0_data(bs), (size_t)*bits_len);
    ok = (*bits_out != NULL);
end:
    X509_ALGOR_free(algor);
    ASN1_BIT_STRING_free(bs);
    if (!ok) {
        ASN1_OBJECT_free(*oid_out);
        *oid_out = NULL;
    }
    return ok;
}

static void *spki_dec_newctx(void *provctx)
{
    struct spki_dec_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));

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

static int match_oid(ASN1_OBJECT *got, const char *oid_txt, int expect_len,
                     int *is_sig, int *is_hybrid, size_t *aigis_len)
{
    ASN1_OBJECT *o = OBJ_txt2obj(oid_txt, 1);
    int eq;

    if (o == NULL)
        return 0;
    eq = (OBJ_cmp(got, o) == 0);
    ASN1_OBJECT_free(o);
    if (!eq)
        return 0;
    if (strcmp(oid_txt, OID_SIG1) == 0) {
        *is_sig = 1;
        *is_hybrid = 0;
        *aigis_len = AIGIS_SIG1_PK_LEN;
    } else if (strcmp(oid_txt, OID_ENC1) == 0) {
        *is_sig = 0;
        *is_hybrid = 0;
        *aigis_len = AIGIS_ENC1_PK_LEN;
    } else if (strcmp(oid_txt, OID_SIG1H) == 0) {
        *is_sig = 1;
        *is_hybrid = 1;
        *aigis_len = AIGIS_SIG1_PK_LEN;
    } else if (strcmp(oid_txt, OID_ENC1H) == 0) {
        *is_sig = 0;
        *is_hybrid = 1;
        *aigis_len = AIGIS_ENC1_PK_LEN;
    }
    (void)expect_len;
    return 1;
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
    unsigned char *pk_dup = NULL;
    int pk_len = 0;
    const unsigned char *pk_bits;
    struct aigis_key *key = NULL;
    void *keyptr = NULL;
    int ok = 0;
    OSSL_PARAM params[4];
    int objtype = OSSL_OBJECT_PKEY;
    char data_type[64];
    int is_sig = 0, is_hybrid = 0;
    size_t aigis_len = 0;
    int expect_len = 0;
    const char *names[] = { OID_SIG1, OID_ENC1, OID_SIG1H, OID_ENC1H };
    int i;

    (void)pw_cb;
    (void)pw_cbarg;
    if (selection != 0
        && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 1;
    if (!read_core_bio(libctx, cin, &der, &der_len) || der_len <= 0)
        return 1;
    if (!parse_spki_oid_and_bits(der, der_len, &got_oid, &pk_dup, &pk_len))
        goto end;

    for (i = 0; i < 4; i++) {
        if (match_oid(got_oid, names[i], 0, &is_sig, &is_hybrid, &aigis_len)) {
            expect_len = (int)(is_hybrid ? aigis_len + AIGIS_SM2_PK_LEN
                                         : aigis_len);
            snprintf(data_type, sizeof(data_type), "%s", names[i]);
            break;
        }
    }
    if (expect_len == 0)
        goto end;

    pk_bits = pk_dup;
    if (pk_len == expect_len + 1 && pk_bits[0] == 0) {
        pk_bits++;
        pk_len--;
    }
    if (pk_len != expect_len)
        goto end;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto end;
    memcpy(key->pk, pk_bits, (size_t)expect_len);
    key->pk_len = (size_t)expect_len;
    key->aigis_len = aigis_len;
    key->is_sig = is_sig;
    key->is_hybrid = is_hybrid;
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
    aigis_km_free(key);
    OPENSSL_free(pk_dup);
    ASN1_OBJECT_free(got_oid);
    OPENSSL_free(der);
    return 1;
}

static int spki_dec_export_object(void *vctx, const void *reference,
                                  size_t reference_sz, OSSL_CALLBACK *export_cb,
                                  void *export_cbarg)
{
    struct spki_dec_ctx *ctx = vctx;

    if (reference_sz != sizeof(void *))
        return 0;
    return aigis_km_export(*(void **)reference,
                           ctx != NULL ? ctx->selection
                                       : OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                           export_cb, export_cbarg);
}

/* ---------- text encoder ---------- */

static int print_hex(BIO *out, const char *label, const unsigned char *buf,
                     size_t len)
{
    size_t i;

    if (BIO_printf(out, "%s (%zu bytes):\n", label, len) <= 0)
        return 0;
    for (i = 0; i < len; i++) {
        if ((i % 15) == 0) {
            if (i && BIO_printf(out, "\n") <= 0)
                return 0;
            if (BIO_printf(out, "    ") <= 0)
                return 0;
        }
        if (BIO_printf(out, "%02x%s", buf[i], i + 1 == len ? "" : ":") <= 0)
            return 0;
    }
    return BIO_printf(out, "\n") > 0;
}

static int aigis_pubkey_to_text(BIO *out, const void *key, int selection)
{
    const struct aigis_key *k = key;

    if (k == NULL || k->pk_len == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    if (BIO_printf(out, "Aigis %s%s Public-Key (OID %s):\n",
                   k->is_sig ? "SIG1" : "Enc-1",
                   k->is_hybrid ? "-SM2 hybrid" : "", k->oid_text) <= 0)
        return 0;
    if (!print_hex(out, "aigis-pub", k->pk, k->aigis_len))
        return 0;
    if (k->is_hybrid)
        return print_hex(out, "sm2-pub", k->pk + k->aigis_len, AIGIS_SM2_PK_LEN);
    return 1;
}

static void *text_import_object(void *ctx, int selection,
                                const OSSL_PARAM params[])
{
    void *key = aigis_km_new(ctx);

    if (key == NULL)
        return NULL;
    if (!aigis_km_import(key, selection, params)) {
        aigis_km_free(key);
        return NULL;
    }
    return key;
}

static int text_encode(void *vctx, OSSL_CORE_BIO *cout, const void *key,
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
    ret = aigis_pubkey_to_text(bout, key, selection);
    BIO_free(bout);
    return ret;
}

/* ---------- dispatch tables ---------- */

struct aigis_gen_ctx {
    int selection;
};

static void *aigis_gen_init(void *provctx, int selection,
                            const OSSL_PARAM params[])
{
    struct aigis_gen_ctx *gctx;

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

static void aigis_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static void *aigis_sig_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct aigis_gen_ctx *gctx = genctx;
    struct aigis_key *key;

    (void)osslcb;
    (void)cbarg;
    if (gctx == NULL)
        return NULL;
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    if (pqmagic_aigis_sig1_std_keypair(key->pk, key->sk) != 0) {
        aigis_km_free(key);
        return NULL;
    }
    key->pk_len = AIGIS_SIG1_PK_LEN;
    key->aigis_len = AIGIS_SIG1_PK_LEN;
    key->sk_len = AIGIS_SIG1_SK_LEN;
    key->is_sig = 1;
    key->is_hybrid = 0;
    snprintf(key->oid_text, sizeof(key->oid_text), "%s", OID_SIG1);
    return key;
}

static const OSSL_DISPATCH aigis_sig_keymgmt[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))aigis_km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))aigis_km_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))aigis_km_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))aigis_km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))aigis_km_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))aigis_km_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))aigis_km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))aigis_km_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))aigis_km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))aigis_sig_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))aigis_sig_km_query },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))aigis_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))aigis_sig_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))aigis_gen_cleanup },
    { 0, NULL }
};

/* 串联公钥只解码，不在这一把密钥上 genpkey（复合 CSR 用纯 Aigis + SM2 两把钥匙） */
static const OSSL_DISPATCH aigis_sig_hybrid_keymgmt[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))aigis_km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))aigis_km_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))aigis_km_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))aigis_km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))aigis_km_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))aigis_km_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))aigis_km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))aigis_km_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))aigis_km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))aigis_sig_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))aigis_sig_km_query },
    { 0, NULL }
};

static const OSSL_PARAM aigis_export_pub[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *aigis_km_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return aigis_export_pub;
    return NULL;
}

static const OSSL_DISPATCH aigis_enc_keymgmt[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))aigis_km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))aigis_km_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))aigis_km_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))aigis_km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))aigis_km_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))aigis_km_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))aigis_km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))aigis_km_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))aigis_km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))aigis_km_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))aigis_kem_km_query },
    { 0, NULL }
};

static const OSSL_DISPATCH aigis_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))aigis_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))aigis_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))aigis_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))aigis_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))aigis_sig_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))aigis_sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))aigis_sig_sign_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
      (void (*)(void))aigis_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))aigis_sig_gettable_ctx_params_fn },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))aigis_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))aigis_sig_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))aigis_sig_verify_final },
    { 0, NULL }
};

static const OSSL_DISPATCH aigis_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))aigis_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))aigis_kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))aigis_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))aigis_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))aigis_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))aigis_kem_decapsulate },
    { 0, NULL }
};

static const OSSL_DISPATCH aigis_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))spki_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))spki_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))spki_dec_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))spki_dec_decode },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,
      (void (*)(void))spki_dec_export_object },
    { 0, NULL }
};

static int pkcs8_dec_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int aigis_fill_key_from_priv(struct aigis_key *key,
                                    const unsigned char *pkey, int pkeylen,
                                    const char *oid_txt)
{
    if (strcmp(oid_txt, OID_SIG1) == 0) {
        if (pkeylen == AIGIS_SIG1_SK_LEN) {
            memcpy(key->sk, pkey, (size_t)pkeylen);
            key->sk_len = (size_t)pkeylen;
        } else if (pkeylen == AIGIS_SIG1_SK_PK_LEN) {
            memcpy(key->sk, pkey, AIGIS_SIG1_SK_LEN);
            key->sk_len = AIGIS_SIG1_SK_LEN;
            memcpy(key->pk, pkey + AIGIS_SIG1_SK_LEN, AIGIS_SIG1_PK_LEN);
            key->pk_len = AIGIS_SIG1_PK_LEN;
            key->aigis_len = AIGIS_SIG1_PK_LEN;
        } else {
            return 0;
        }
        key->is_sig = 1;
        key->is_hybrid = 0;
        snprintf(key->oid_text, sizeof(key->oid_text), "%s", OID_SIG1);
        return 1;
    }
    if (strcmp(oid_txt, OID_ENC1) == 0) {
        if (pkeylen != AIGIS_ENC1_SK_LEN)
            return 0;
        memcpy(key->sk, pkey, (size_t)pkeylen);
        key->sk_len = (size_t)pkeylen;
        key->is_sig = 0;
        key->is_hybrid = 0;
        snprintf(key->oid_text, sizeof(key->oid_text), "%s", OID_ENC1);
        return 1;
    }
    return 0;
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
    struct aigis_key *key = NULL;
    void *keyptr = NULL;
    int ok = 0;
    OSSL_PARAM params[4];
    int objtype = OSSL_OBJECT_PKEY;
    char oid_txt[64];
    const char *data_type;

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

    if (OBJ_obj2txt(oid_txt, sizeof(oid_txt), algoid, 1) <= 0)
        goto end;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto end;

    if (!aigis_fill_key_from_priv(key, pkey, pkeylen, oid_txt))
        goto end;

    data_type = key->is_sig ? "id-Aigis-SIG1-SPKI" : "id-Aigis-Enc-1-SPKI";
    keyptr = key;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objtype);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &keyptr, sizeof(keyptr));
    params[3] = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);
    if (ok)
        key = NULL;

end:
    aigis_km_free(key);
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_free(der);
    return 1;
}

static const OSSL_DISPATCH aigis_pkcs8_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))spki_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))spki_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))pkcs8_dec_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))pkcs8_dec_decode },
    { 0, NULL }
};

static void *text_newctx(void *provctx)
{
    return provctx;
}

static void text_freectx(void *vctx)
{
    (void)vctx;
}

static const OSSL_DISPATCH aigis_text_encoder[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))text_freectx },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))text_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))aigis_km_free },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))text_encode },
    { 0, NULL }
};

static int aigis_pubkey_to_spki_der(const struct aigis_key *k,
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
    /* 与样例 CSR 一致：算法参数为 NULL */
    if (!X509_PUBKEY_set0_param(xpub, oid, V_ASN1_NULL, NULL, penc,
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

static int aigis_spki_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int aigis_spki_der_encode(void *vctx, OSSL_CORE_BIO *cout,
                                 const void *key,
                                 const OSSL_PARAM *key_abstract, int selection,
                                 OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *bout;
    const struct aigis_key *k = key;
    unsigned char *der = NULL;
    size_t derlen = 0;
    int ret = 0;

    (void)cb;
    (void)cbarg;
    if (key_abstract != NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    if (!aigis_pubkey_to_spki_der(k, &der, &derlen))
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

static const OSSL_DISPATCH aigis_spki_der_encoder[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))text_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))aigis_spki_does_selection },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))text_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))aigis_km_free },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))aigis_spki_der_encode },
    { 0, NULL }
};

static int aigis_sk_to_pkcs8_der(const struct aigis_key *k,
                                 unsigned char **out, size_t *outlen)
{
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *raw = NULL;
    unsigned char *der = NULL;
    size_t raw_len;
    int len;

    if (k == NULL || k->sk_len != AIGIS_SIG1_SK_LEN
        || k->pk_len != AIGIS_SIG1_PK_LEN || k->is_hybrid
        || out == NULL || outlen == NULL)
        return 0;
    raw_len = AIGIS_SIG1_SK_PK_LEN;
    raw = OPENSSL_malloc(raw_len);
    oid = OBJ_txt2obj(k->oid_text, 1);
    p8 = PKCS8_PRIV_KEY_INFO_new();
    if (raw == NULL || oid == NULL || p8 == NULL)
        goto err;
    memcpy(raw, k->sk, AIGIS_SIG1_SK_LEN);
    memcpy(raw + AIGIS_SIG1_SK_LEN, k->pk, AIGIS_SIG1_PK_LEN);
    if (!PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, raw, (int)raw_len))
        goto err;
    oid = NULL;
    raw = NULL;
    len = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
    if (len <= 0)
        goto err;
    *out = der;
    *outlen = (size_t)len;
    PKCS8_PRIV_KEY_INFO_free(p8);
    return 1;
err:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(raw);
    OPENSSL_free(der);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return 0;
}

static int aigis_pkcs8_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int aigis_pkcs8_der_encode(void *vctx, OSSL_CORE_BIO *cout,
                                  const void *key,
                                  const OSSL_PARAM *key_abstract, int selection,
                                  OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *bout;
    const struct aigis_key *k = key;
    unsigned char *der = NULL;
    size_t derlen = 0;
    int ret = 0;

    (void)cb;
    (void)cbarg;
    if (key_abstract != NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        return 0;
    if (!aigis_sk_to_pkcs8_der(k, &der, &derlen))
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

static int aigis_pkcs8_pem_encode(void *vctx, OSSL_CORE_BIO *cout,
                                  const void *key,
                                  const OSSL_PARAM *key_abstract, int selection,
                                  OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *bout;
    const struct aigis_key *k = key;
    unsigned char *der = NULL;
    size_t derlen = 0;
    const unsigned char *p;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    int ret = 0;

    (void)cb;
    (void)cbarg;
    if (key_abstract != NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        return 0;
    if (!aigis_sk_to_pkcs8_der(k, &der, &derlen))
        return 0;
    bout = BIO_new_from_core_bio(vctx, cout);
    if (bout == NULL)
        goto end;
    p = der;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)derlen);
    if (p8 == NULL)
        goto end;
    ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bout, p8);
    PKCS8_PRIV_KEY_INFO_free(p8);
    BIO_free(bout);
    bout = NULL;
end:
    BIO_free(bout);
    OPENSSL_free(der);
    return ret;
}

static const OSSL_DISPATCH aigis_pkcs8_der_encoder[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))text_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))aigis_pkcs8_does_selection },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))text_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))aigis_km_free },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))aigis_pkcs8_der_encode },
    { 0, NULL }
};

static const OSSL_DISPATCH aigis_pkcs8_pem_encoder[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))text_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))text_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))aigis_pkcs8_does_selection },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))text_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))aigis_km_free },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))aigis_pkcs8_pem_encode },
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
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "aigis"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM aigis_keymgmt[] = {
    { "id-Aigis-SIG1-SPKI:Aigis-SIG1-SPKI:" OID_SIG1,
      "provider=aigis", aigis_sig_keymgmt },
    { "id-Aigis-Enc-1-SPKI:Aigis-Enc-1-SPKI:" OID_ENC1,
      "provider=aigis", aigis_enc_keymgmt },
    { "id-Aigis-SIG1-SM2:Aigis-SIG1-SM2:" OID_SIG1H,
      "provider=aigis", aigis_sig_hybrid_keymgmt },
    { "id-Aigis-Enc-1-SM2:Aigis-Enc-1-SM2:" OID_ENC1H,
      "provider=aigis", aigis_enc_keymgmt },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM aigis_signatures[] = {
    { "Aigis-SIG1-with-SM3:" OID_SIG1_WITH_SM3,
      "provider=aigis", aigis_signature_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM aigis_kems[] = {
    { "Aigis-Enc-1", "provider=aigis", aigis_kem_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM aigis_decoders[] = {
    { OID_SIG1, "provider=aigis,input=der,structure=SubjectPublicKeyInfo",
      aigis_decoder_functions },
    { OID_ENC1, "provider=aigis,input=der,structure=SubjectPublicKeyInfo",
      aigis_decoder_functions },
    { OID_SIG1H, "provider=aigis,input=der,structure=SubjectPublicKeyInfo",
      aigis_decoder_functions },
    { OID_ENC1H, "provider=aigis,input=der,structure=SubjectPublicKeyInfo",
      aigis_decoder_functions },
    { OID_SIG1, "provider=aigis,input=der,structure=PrivateKeyInfo",
      aigis_pkcs8_decoder_functions },
    { OID_ENC1, "provider=aigis,input=der,structure=PrivateKeyInfo",
      aigis_pkcs8_decoder_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM aigis_encoders[] = {
    { "id-Aigis-SIG1-SPKI:Aigis-SIG1-SPKI:" OID_SIG1,
      "provider=aigis,output=der,structure=SubjectPublicKeyInfo",
      aigis_spki_der_encoder },
    { "id-Aigis-SIG1-SPKI:Aigis-SIG1-SPKI:" OID_SIG1,
      "provider=aigis,output=der,structure=PrivateKeyInfo",
      aigis_pkcs8_der_encoder },
    { "id-Aigis-SIG1-SPKI:Aigis-SIG1-SPKI:" OID_SIG1,
      "provider=aigis,output=pem,structure=PrivateKeyInfo",
      aigis_pkcs8_pem_encoder },
    { "id-Aigis-SIG1-SPKI:Aigis-SIG1-SPKI:" OID_SIG1,
      "provider=aigis,output=text", aigis_text_encoder },
    { "id-Aigis-Enc-1-SPKI:Aigis-Enc-1-SPKI:" OID_ENC1,
      "provider=aigis,output=text", aigis_text_encoder },
    { "id-Aigis-SIG1-SM2:Aigis-SIG1-SM2:" OID_SIG1H,
      "provider=aigis,output=text", aigis_text_encoder },
    { "id-Aigis-Enc-1-SM2:Aigis-Enc-1-SM2:" OID_ENC1H,
      "provider=aigis,output=text", aigis_text_encoder },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *provider_query(void *provctx, int operation_id,
                                            int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return aigis_keymgmt;
    case OSSL_OP_DECODER:
        return aigis_decoders;
    case OSSL_OP_ENCODER:
        return aigis_encoders;
    case OSSL_OP_SIGNATURE:
        return aigis_signatures;
    case OSSL_OP_KEM:
        return aigis_kems;
    default:
        return NULL;
    }
}

static const OSSL_DISPATCH provider_dispatch[] = {
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
    OSSL_LIB_CTX *libctx;

    aigis_register_oids();
    /* 必须用 from_dispatch，否则 BIO_new_from_core_bio 读不到 DER，x509 -text 无法出公钥 */
    libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
    if (libctx == NULL)
        return 0;
    *out = provider_dispatch;
    *provctx = libctx;
    return 1;
}
