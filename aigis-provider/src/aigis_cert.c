/*
 * Aigis 三类证书：公钥提取与验签
 * 算法调用 PQMagic：aigis_sig1 / 外层 SM2 走 Tongsuo EVP
 */

#include "aigis_cert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pqmagic_api.h>

static int g_trace = -1;

void aigis_cert_set_trace(int enable)
{
    g_trace = enable ? 1 : 0;
}

static int trace_on(void)
{
    if (g_trace < 0) {
        const char *e = getenv("AIGIS_CERT_TRACE");
        g_trace = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0;
    }
    return g_trace;
}

#define TR(fmt, ...) \
    do { \
        if (trace_on()) \
            printf("[aigis_cert] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

static ASN1_OBJECT *obj_ext_pub, *obj_ext_sigalg, *obj_ext_sig;

void aigis_cert_register_oids(void)
{
    static int once;

    if (once)
        return;
    once = 1;
    OBJ_create(AIGIS_OID_ENC1_SPKI, "Aigis-Enc-1-SPKI", "Aigis-Enc-1-SPKI");
    OBJ_create(AIGIS_OID_SIG1_SPKI, "Aigis-SIG1-SPKI", "Aigis-SIG1-SPKI");
    OBJ_create(AIGIS_OID_SIG1_WITH_SM3, "Aigis-SIG1-with-SM3",
               "Aigis-SIG1-with-SM3");
    OBJ_create(AIGIS_OID_SIG1_SM2_WITH_SM3, "Aigis-SIG1-SM2-with-SM3",
               "Aigis-SIG1-SM2-with-SM3");
    OBJ_create(AIGIS_OID_ENC1_SM2_SPKI, "Aigis-Enc-1-SM2", "Aigis-Enc-1-SM2");
    OBJ_create(AIGIS_OID_SIG1_SM2_SPKI, "Aigis-SIG1-SM2", "Aigis-SIG1-SM2");
    OBJ_create(AIGIS_OID_EXT_PQC_PUB, "PQC-Subject-Public-Key",
               "PQC-Subject-Public-Key");
    OBJ_create(AIGIS_OID_EXT_PQC_SIGALG, "PQC-Signature-Algorithm",
               "PQC-Signature-Algorithm");
    OBJ_create(AIGIS_OID_EXT_PQC_SIG, "PQC-Signature-Value",
               "PQC-Signature-Value");
    ERR_clear_error();
    obj_ext_pub = OBJ_txt2obj(AIGIS_OID_EXT_PQC_PUB, 1);
    obj_ext_sigalg = OBJ_txt2obj(AIGIS_OID_EXT_PQC_SIGALG, 1);
    obj_ext_sig = OBJ_txt2obj(AIGIS_OID_EXT_PQC_SIG, 1);
    {
        int sign_nid = OBJ_txt2nid(AIGIS_OID_SIG1_WITH_SM3);
        int pkey_nid = OBJ_txt2nid(AIGIS_OID_SIG1_SPKI);

        /* 供 ASN1_item_verify / X509_verify：签名 OID → SM3 + Aigis-SIG1 公钥 */
        if (sign_nid != NID_undef && pkey_nid != NID_undef)
            OBJ_add_sigid(sign_nid, NID_sm3, pkey_nid);
        sign_nid = OBJ_txt2nid(AIGIS_OID_SIG1_SM2_WITH_SM3);
        pkey_nid = OBJ_txt2nid(AIGIS_OID_SIG1_SM2_SPKI);
        if (sign_nid != NID_undef && pkey_nid != NID_undef)
            OBJ_add_sigid(sign_nid, NID_sm3, pkey_nid);
        ERR_clear_error();
    }
}

static int oid_eq(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

static int has_ext(X509 *cert, ASN1_OBJECT *obj)
{
    return obj != NULL && X509_get_ext_by_OBJ(cert, obj, -1) >= 0;
}

static int spki_raw(X509 *cert, unsigned char *pk_out, size_t pk_max,
                    size_t *pk_len, char *oid_text, size_t oid_sz)
{
    X509_PUBKEY *xp = X509_get_X509_PUBKEY(cert);
    const unsigned char *pk = NULL;
    int pklen = 0;
    X509_ALGOR *algor = NULL;
    const ASN1_OBJECT *oid = NULL;

    if (xp == NULL || !X509_PUBKEY_get0_param(NULL, &pk, &pklen, &algor, xp))
        return 0;
    X509_ALGOR_get0(&oid, NULL, NULL, algor);
    if (oid == NULL || OBJ_obj2txt(oid_text, (int)oid_sz, oid, 1) <= 0)
        return 0;
    if (pklen > 0 && pk[0] == 0) {
        pk++;
        pklen--;
    }
    if ((size_t)pklen > pk_max)
        return 0;
    memcpy(pk_out, pk, (size_t)pklen);
    *pk_len = (size_t)pklen;
    return 1;
}

static int tbs_bytes(X509 *cert, unsigned char **out, int *outlen)
{
    *out = NULL;
    *outlen = i2d_re_X509_tbs(cert, out);
    return *outlen > 0;
}

static void delete_ext(X509 *cert, ASN1_OBJECT *obj)
{
    int idx;

    for (;;) {
        idx = X509_get_ext_by_OBJ(cert, obj, -1);
        if (idx < 0)
            break;
        X509_delete_ext(cert, idx);
    }
}

static unsigned char *build_tbs_drop_sig_exts(X509 *cert, int *outlen)
{
    X509 *tmp;
    unsigned char *out = NULL;

    aigis_cert_register_oids();
    tmp = X509_dup(cert);
    if (tmp == NULL)
        return NULL;
    delete_ext(tmp, obj_ext_sigalg);
    delete_ext(tmp, obj_ext_sig);
    *outlen = i2d_re_X509_tbs(tmp, &out);
    X509_free(tmp);
    return *outlen > 0 ? out : NULL;
}

static const unsigned char *ext_octet(X509 *cert, ASN1_OBJECT *obj, int *len)
{
    int idx;
    X509_EXTENSION *ex;
    ASN1_OCTET_STRING *os;

    idx = X509_get_ext_by_OBJ(cert, obj, -1);
    if (idx < 0)
        return NULL;
    ex = X509_get_ext(cert, idx);
    os = ex != NULL ? X509_EXTENSION_get_data(ex) : NULL;
    if (os == NULL)
        return NULL;
    *len = ASN1_STRING_length(os);
    return ASN1_STRING_get0_data(os);
}

static int parse_inner_spki(const unsigned char *der, int der_len,
                            char *alg_oid, size_t alg_sz,
                            unsigned char *pk, size_t pk_max, size_t *pk_len)
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
    if (OBJ_obj2txt(alg_oid, (int)alg_sz, algor->algorithm, 1) <= 0)
        goto done;
    left -= (long)(q - p);
    p = q;
    bs = d2i_ASN1_BIT_STRING(NULL, &q, left);
    if (bs == NULL)
        goto done;
    {
        const unsigned char *raw = ASN1_STRING_get0_data(bs);
        int rlen = ASN1_STRING_length(bs);

        if (rlen > 0 && raw[0] == 0) {
            raw++;
            rlen--;
        }
        if ((size_t)rlen > pk_max)
            goto done;
        memcpy(pk, raw, (size_t)rlen);
        *pk_len = (size_t)rlen;
        ok = 1;
    }
done:
    X509_ALGOR_free(algor);
    ASN1_BIT_STRING_free(bs);
    return ok;
}

static int get_ext_sig(X509 *cert, unsigned char *sig, size_t sig_max,
                       size_t *sig_len)
{
    const unsigned char *der;
    int der_len = 0;

    aigis_cert_register_oids();
    der = ext_octet(cert, obj_ext_sig, &der_len);
    if (der == NULL || der_len <= 0)
        return 0;
    if ((size_t)der_len == AIGIS_SIG1_SIG_LEN) {
        memcpy(sig, der, (size_t)der_len);
        *sig_len = (size_t)der_len;
        return 1;
    }
    if ((size_t)der_len > 2 && der[0] == 0x04) {
        int sl = der[1];
        const unsigned char *p = der + 2;

        if (sl & 0x80) {
            int n = sl & 0x7f;

            sl = 0;
            for (int i = 0; i < n; i++)
                sl = (sl << 8) | p[i];
            p += n;
        }
        if ((size_t)sl <= sig_max) {
            memcpy(sig, p, (size_t)sl);
            *sig_len = (size_t)sl;
            return 1;
        }
    }
    if ((size_t)der_len <= sig_max) {
        memcpy(sig, der, (size_t)der_len);
        *sig_len = (size_t)der_len;
        return 1;
    }
    return 0;
}

static int aigis_sig1_sm3_verify(const unsigned char *pk, size_t pklen,
                                 const unsigned char *msg, size_t msglen,
                                 const unsigned char *sig, size_t siglen)
{
    unsigned char sm3[32];
    unsigned int sm3_len = sizeof(sm3);
    EVP_MD_CTX *mdc;
    int r;

    if (pklen != AIGIS_SIG1_PK_LEN || siglen != AIGIS_SIG1_SIG_LEN)
        return 0;
    mdc = EVP_MD_CTX_new();
    if (mdc == NULL)
        return 0;
    if (!EVP_DigestInit_ex(mdc, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(mdc, msg, msglen)
        || !EVP_DigestFinal_ex(mdc, sm3, &sm3_len)) {
        EVP_MD_CTX_free(mdc);
        return 0;
    }
    EVP_MD_CTX_free(mdc);
    if (sm3_len != 32)
        return 0;
    /* 样证使用 internal 接口：消息为 SM3(TBS)，无 ctx 封装 */
    r = pqmagic_aigis_sig1_std_verify_internal(sig, siglen, sm3, 32, pk);
    return r == 0;
}

static EC_KEY *sm2_from_raw(const unsigned char *sm2_pk, size_t sm2_len)
{
    EC_KEY *ec = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *pt = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *x = NULL, *y = NULL;
    const unsigned char *p = sm2_pk;

    if (sm2_len == AIGIS_SM2_PK_LEN && p[0] == 0x04) {
        p++;
        sm2_len = 64;
    } else if (sm2_len != 64) {
        return NULL;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        return NULL;
    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    group = EC_GROUP_new_by_curve_name(NID_sm2);
    ec = EC_KEY_new();
    pt = EC_POINT_new(group);
    if (y == NULL || group == NULL || ec == NULL || pt == NULL)
        goto err;
    if (!BN_bin2bn(p, 32, x) || !BN_bin2bn(p + 32, 32, y))
        goto err;
    if (!EC_POINT_set_affine_coordinates(group, pt, x, y, ctx)
        || !EC_KEY_set_group(ec, group)
        || !EC_KEY_set_public_key(ec, pt))
        goto err;
    EC_POINT_free(pt);
    EC_GROUP_free(group);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ec;

err:
    EC_POINT_free(pt);
    EC_KEY_free(ec);
    EC_GROUP_free(group);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return NULL;
}

static int sm2_sm3_verify(OSSL_LIB_CTX *libctx, EC_KEY *ec,
                          const unsigned char *msg, size_t msglen,
                          const unsigned char *sig, size_t siglen)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;

    (void)libctx;
    pkey = EVP_PKEY_new();
    if (pkey == NULL || !EVP_PKEY_assign_EC_KEY(pkey, ec)) {
        EC_KEY_free(ec);
        EVP_PKEY_free(pkey);
        return 0;
    }
    /* ec ownership transferred to pkey */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto end;
    if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, pkey))
        goto end;
    if (!EVP_DigestVerifyUpdate(ctx, msg, msglen))
        goto end;
    ok = EVP_DigestVerifyFinal(ctx, sig, siglen) == 1;
end:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

AIGIS_CERT_MODE aigis_cert_detect_mode(X509 *cert)
{
    char oid[64];
    unsigned char tmp[2048];
    size_t len = 0;

    aigis_cert_register_oids();
    if (has_ext(cert, obj_ext_pub))
        return AIGIS_CERT_MODE_EXT;
    if (!spki_raw(cert, tmp, sizeof(tmp), &len, oid, sizeof(oid)))
        return AIGIS_CERT_MODE_UNKNOWN;
    if (oid_eq(oid, AIGIS_OID_SIG1_SM2_SPKI)
        || oid_eq(oid, AIGIS_OID_ENC1_SM2_SPKI))
        return AIGIS_CERT_MODE_CONCAT;
    if (oid_eq(oid, AIGIS_OID_SIG1_SPKI) || oid_eq(oid, AIGIS_OID_ENC1_SPKI))
        return AIGIS_CERT_MODE_PURE;
    return AIGIS_CERT_MODE_UNKNOWN;
}

int aigis_cert_extract_subject_pubkey(X509 *cert, AIGIS_PUBKEY *out)
{
    unsigned char raw[2048];
    size_t raw_len = 0;
    char oid[64];
    AIGIS_CERT_MODE mode;

    memset(out, 0, sizeof(*out));
    aigis_cert_register_oids();
    mode = aigis_cert_detect_mode(cert);
    out->mode = mode;

    if (mode == AIGIS_CERT_MODE_EXT) {
        const unsigned char *der;
        int der_len = 0;
        EVP_PKEY *sm2;
        unsigned char *sm2der = NULL;
        int sm2len;

        der = ext_octet(cert, obj_ext_pub, &der_len);
        if (der == NULL
            || !parse_inner_spki(der, der_len, out->spki_oid,
                                 sizeof(out->spki_oid), out->aigis_pk,
                                 sizeof(out->aigis_pk), &out->aigis_pk_len))
            return 0;
        out->is_sig = oid_eq(out->spki_oid, AIGIS_OID_SIG1_SPKI);
        sm2 = X509_get0_pubkey(cert);
        if (sm2 != NULL) {
            sm2len = i2d_PublicKey(sm2, &sm2der);
            if (sm2len == AIGIS_SM2_PK_LEN) {
                memcpy(out->sm2_pk, sm2der, (size_t)sm2len);
                out->sm2_pk_len = (size_t)sm2len;
            }
            OPENSSL_free(sm2der);
        }
        return 1;
    }

    if (!spki_raw(cert, raw, sizeof(raw), &raw_len, oid, sizeof(oid)))
        return 0;
    snprintf(out->spki_oid, sizeof(out->spki_oid), "%s", oid);

    if (mode == AIGIS_CERT_MODE_CONCAT) {
        size_t aigis_len;

        if (oid_eq(oid, AIGIS_OID_SIG1_SM2_SPKI)) {
            aigis_len = AIGIS_SIG1_PK_LEN;
            out->is_sig = 1;
        } else if (oid_eq(oid, AIGIS_OID_ENC1_SM2_SPKI)) {
            aigis_len = AIGIS_ENC1_PK_LEN;
            out->is_sig = 0;
        } else {
            return 0;
        }
        if (raw_len < aigis_len + AIGIS_SM2_PK_LEN)
            return 0;
        memcpy(out->aigis_pk, raw, aigis_len);
        out->aigis_pk_len = aigis_len;
        memcpy(out->sm2_pk, raw + aigis_len, AIGIS_SM2_PK_LEN);
        out->sm2_pk_len = AIGIS_SM2_PK_LEN;
        return 1;
    }

    if (mode == AIGIS_CERT_MODE_PURE) {
        if (oid_eq(oid, AIGIS_OID_SIG1_SPKI)
            && raw_len == AIGIS_SIG1_PK_LEN) {
            memcpy(out->aigis_pk, raw, raw_len);
            out->aigis_pk_len = raw_len;
            out->is_sig = 1;
            return 1;
        }
        if (oid_eq(oid, AIGIS_OID_ENC1_SPKI)
            && raw_len == AIGIS_ENC1_PK_LEN) {
            memcpy(out->aigis_pk, raw, raw_len);
            out->aigis_pk_len = raw_len;
            out->is_sig = 0;
            return 1;
        }
    }
    return 0;
}

static int extract_issuer_aigis_sig_pk(X509 *issuer, unsigned char *pk,
                                       size_t *pk_len)
{
    AIGIS_PUBKEY info;

    if (!aigis_cert_extract_subject_pubkey(issuer, &info))
        return 0;
    if (!info.is_sig || info.aigis_pk_len != AIGIS_SIG1_PK_LEN)
        return 0;
    memcpy(pk, info.aigis_pk, AIGIS_SIG1_PK_LEN);
    *pk_len = AIGIS_SIG1_PK_LEN;
    return 1;
}

static int verify_pure(X509 *cert, X509 *issuer, AIGIS_VERIFY_RESULT *res)
{
    unsigned char *tbs = NULL;
    int tbslen = 0;
    unsigned char iss_pk[AIGIS_SIG1_PK_LEN];
    size_t iss_pk_len = 0;
    const ASN1_BIT_STRING *sig = NULL;

    if (!extract_issuer_aigis_sig_pk(issuer, iss_pk, &iss_pk_len)) {
        snprintf(res->err, sizeof(res->err), "无法从签发者提取 Aigis-SIG1 公钥");
        return 0;
    }
    if (!tbs_bytes(cert, &tbs, &tbslen)) {
        snprintf(res->err, sizeof(res->err), "导出 TBS 失败");
        return 0;
    }
    X509_get0_signature(&sig, NULL, cert);
    if (sig == NULL || (size_t)ASN1_STRING_length(sig) != AIGIS_SIG1_SIG_LEN) {
        OPENSSL_free(tbs);
        snprintf(res->err, sizeof(res->err),
                 "外层签名长度应为 %d", AIGIS_SIG1_SIG_LEN);
        return 0;
    }
    res->aigis_ok = aigis_sig1_sm3_verify(iss_pk, iss_pk_len, tbs, (size_t)tbslen,
                                          ASN1_STRING_get0_data(sig),
                                          AIGIS_SIG1_SIG_LEN);
    OPENSSL_free(tbs);
    res->sm2_ok = 1;
    res->ok = res->aigis_ok;
    if (!res->ok)
        snprintf(res->err, sizeof(res->err),
                 "Aigis-SIG1-with-SM3(509.1) 对完整 TBS 验签失败");
    return res->ok;
}

static int verify_concat_tbs(X509 *issuer, OSSL_LIB_CTX *libctx,
                             const unsigned char *tbs, size_t tbslen,
                             const unsigned char *sig, size_t siglen,
                             AIGIS_VERIFY_RESULT *res)
{
    AIGIS_PUBKEY iss;
    size_t sm2_sig_len;
    EC_KEY *ec = NULL;

    if (tbs == NULL || sig == NULL || tbslen == 0) {
        snprintf(res->err, sizeof(res->err), "串联验签材料不足");
        return 0;
    }
    if (!aigis_cert_extract_subject_pubkey(issuer, &iss)
        || !iss.is_sig || iss.sm2_pk_len != AIGIS_SM2_PK_LEN) {
        snprintf(res->err, sizeof(res->err), "签发者不是 Aigis-SIG1-SM2 串联公钥");
        return 0;
    }
    if (siglen <= AIGIS_SIG1_SIG_LEN) {
        snprintf(res->err, sizeof(res->err), "串联外层签名过短");
        return 0;
    }
    sm2_sig_len = siglen - AIGIS_SIG1_SIG_LEN;
    res->aigis_ok = aigis_sig1_sm3_verify(iss.aigis_pk, iss.aigis_pk_len, tbs,
                                          tbslen, sig, AIGIS_SIG1_SIG_LEN);
    TR("concat Aigis verify -> %d", res->aigis_ok);
    ec = sm2_from_raw(iss.sm2_pk, iss.sm2_pk_len);
    if (ec == NULL) {
        snprintf(res->err, sizeof(res->err), "签发者 SM2 公钥解析失败");
        return 0;
    }
    res->sm2_ok = sm2_sm3_verify(libctx, ec, tbs, tbslen,
                                 sig + AIGIS_SIG1_SIG_LEN, sm2_sig_len);
    TR("concat SM2 verify -> %d", res->sm2_ok);
    res->ok = res->aigis_ok && res->sm2_ok;
    if (!res->ok)
        snprintf(res->err, sizeof(res->err),
                 "Aigis-SIG1-SM2-with-SM3(510.1) 验签失败 (aigis=%d sm2=%d)",
                 res->aigis_ok, res->sm2_ok);
    return res->ok;
}

static int verify_concat(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx,
                         AIGIS_VERIFY_RESULT *res)
{
    unsigned char *tbs = NULL;
    int tbslen = 0;
    const ASN1_BIT_STRING *outer = NULL;
    int ok;

    if (!tbs_bytes(cert, &tbs, &tbslen)) {
        snprintf(res->err, sizeof(res->err), "导出 TBS 失败");
        return 0;
    }
    X509_get0_signature(&outer, NULL, cert);
    if (outer == NULL) {
        OPENSSL_free(tbs);
        return 0;
    }
    ok = verify_concat_tbs(issuer, libctx, tbs, (size_t)tbslen,
                           ASN1_STRING_get0_data(outer),
                           (size_t)ASN1_STRING_length(outer), res);
    OPENSSL_free(tbs);
    return ok;
}

static int verify_ext(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx,
                      AIGIS_VERIFY_RESULT *res)
{
    unsigned char iss_pk[AIGIS_SIG1_PK_LEN];
    size_t iss_pk_len = 0;
    unsigned char *tbs_aigis = NULL;
    unsigned char *tbs_full = NULL;
    int tbs_a_len = 0, tbs_f_len = 0;
    unsigned char pqc_sig[AIGIS_SIG1_SIG_LEN + 64];
    size_t sig_len = 0;
    const ASN1_BIT_STRING *outer = NULL;
    EVP_PKEY *iss_sm2;
    EVP_MD_CTX *ctx = NULL;

    if (!extract_issuer_aigis_sig_pk(issuer, iss_pk, &iss_pk_len)) {
        snprintf(res->err, sizeof(res->err),
                 "扩展模式：签发者 4.1.6 中无 Aigis-SIG1 公钥");
        return 0;
    }
    if (!get_ext_sig(cert, pqc_sig, sizeof(pqc_sig), &sig_len)
        || sig_len != AIGIS_SIG1_SIG_LEN) {
        snprintf(res->err, sizeof(res->err), "扩展 4.1.8 签名长度异常");
        return 0;
    }
    tbs_aigis = build_tbs_drop_sig_exts(cert, &tbs_a_len);
    if (tbs_aigis == NULL) {
        snprintf(res->err, sizeof(res->err), "构造 Aigis 待验 TBS 失败");
        return 0;
    }
    res->aigis_ok = aigis_sig1_sm3_verify(iss_pk, iss_pk_len, tbs_aigis,
                                          (size_t)tbs_a_len, pqc_sig, sig_len);
    TR("ext Aigis verify -> %d", res->aigis_ok);
    OPENSSL_free(tbs_aigis);

    if (!tbs_bytes(cert, &tbs_full, &tbs_f_len)) {
        snprintf(res->err, sizeof(res->err), "导出完整 TBS 失败");
        return 0;
    }
    iss_sm2 = X509_get0_pubkey(issuer);
    X509_get0_signature(&outer, NULL, cert);
    if (iss_sm2 == NULL || outer == NULL) {
        OPENSSL_free(tbs_full);
        snprintf(res->err, sizeof(res->err), "SM2 外层验签材料不足");
        return 0;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        OPENSSL_free(tbs_full);
        return 0;
    }
    if (EVP_DigestVerifyInit_ex(ctx, NULL, "SM3", libctx, NULL, iss_sm2, NULL)
        && EVP_DigestVerifyUpdate(ctx, tbs_full, (size_t)tbs_f_len)
        && EVP_DigestVerifyFinal(ctx, ASN1_STRING_get0_data(outer),
                                 (size_t)ASN1_STRING_length(outer)) == 1)
        res->sm2_ok = 1;
    TR("ext SM2 verify -> %d", res->sm2_ok);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(tbs_full);
    res->ok = res->aigis_ok && res->sm2_ok;
    if (!res->ok)
        snprintf(res->err, sizeof(res->err),
                 "混合扩展验签失败 (aigis=%d sm2=%d)", res->aigis_ok, res->sm2_ok);
    return res->ok;
}

int aigis_cert_verify_one(X509 *cert, X509 *issuer, AIGIS_VERIFY_RESULT *res,
                          OSSL_LIB_CTX *libctx)
{
    memset(res, 0, sizeof(*res));
    aigis_cert_register_oids();
    X509_NAME_oneline(X509_get_subject_name(cert), res->subject,
                      sizeof(res->subject));
    X509_NAME_oneline(X509_get_issuer_name(cert), res->issuer,
                      sizeof(res->issuer));
    res->mode = aigis_cert_detect_mode(cert);
    TR("mode=%d subject=%s", (int)res->mode, res->subject);

    switch (res->mode) {
    case AIGIS_CERT_MODE_PURE:
        return verify_pure(cert, issuer, res);
    case AIGIS_CERT_MODE_CONCAT:
        return verify_concat(cert, issuer, libctx, res);
    case AIGIS_CERT_MODE_EXT:
        return verify_ext(cert, issuer, libctx, res);
    default:
        snprintf(res->err, sizeof(res->err), "无法识别证书模式");
        return 0;
    }
}

static X509 *load_pem(const char *path)
{
    BIO *b = BIO_new_file(path, "r");
    X509 *x = NULL;

    if (b == NULL)
        return NULL;
    x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    return x;
}

int aigis_cert_verify_dir(const char *dir, AIGIS_VERIFY_RESULT *results,
                          int *nresults, OSSL_LIB_CTX *libctx)
{
    char path[1024];
    X509 *root = NULL, *yun = NULL, *sig = NULL, *enc = NULL;
    int n = 0;

    *nresults = 0;
    snprintf(path, sizeof(path), "%s/root.crt", dir);
    root = load_pem(path);
    snprintf(path, sizeof(path), "%s/yunying.crt", dir);
    yun = load_pem(path);
    snprintf(path, sizeof(path), "%s/user_sig.crt", dir);
    sig = load_pem(path);
    snprintf(path, sizeof(path), "%s/user_enc.crt", dir);
    enc = load_pem(path);
    if (root == NULL || yun == NULL || sig == NULL) {
        X509_free(root);
        X509_free(yun);
        X509_free(sig);
        X509_free(enc);
        return 0;
    }

    aigis_cert_verify_one(yun, root, &results[n++], libctx);
    aigis_cert_verify_one(sig, yun, &results[n++], libctx);
    if (enc != NULL)
        aigis_cert_verify_one(enc, yun, &results[n++], libctx);

    *nresults = n;
    X509_free(root);
    X509_free(yun);
    X509_free(sig);
    X509_free(enc);
    {
        int i, all = 1;

        for (i = 0; i < n; i++) {
            if (!results[i].ok)
                all = 0;
        }
        return all;
    }
}

int aigis_x509_verify_pair(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx)
{
    AIGIS_VERIFY_RESULT res;

    return aigis_cert_verify_one(cert, issuer, &res, libctx);
}

int aigis_x509_verify_concat_tbs(X509 *issuer, OSSL_LIB_CTX *libctx,
                                    const unsigned char *tbs, size_t tbslen,
                                    const unsigned char *sig, size_t siglen,
                                    int *aigis_ok, int *sm2_ok)
{
    AIGIS_VERIFY_RESULT res;
    int ok;

    memset(&res, 0, sizeof(res));
    ok = verify_concat_tbs(issuer, libctx, tbs, tbslen, sig, siglen, &res);
    if (aigis_ok != NULL)
        *aigis_ok = res.aigis_ok;
    if (sm2_ok != NULL)
        *sm2_ok = res.sm2_ok;
    return ok;
}

int aigis_x509_verify_pair_detail(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx,
                                  int *mode, int *aigis_ok, int *sm2_ok)
{
    AIGIS_VERIFY_RESULT res;
    int ok;

    ok = aigis_cert_verify_one(cert, issuer, &res, libctx);
    if (mode != NULL)
        *mode = (int)res.mode;
    if (aigis_ok != NULL)
        *aigis_ok = res.aigis_ok ? 1 : 0;
    if (sm2_ok != NULL)
        *sm2_ok = res.sm2_ok ? 1 : 0;
    return ok;
}
