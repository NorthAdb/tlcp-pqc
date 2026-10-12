/*
 * certs/3 混合证书结构：
 *   证书 = 完整 TBS + 外层 SM2 算法 + 外层 SM2 签名值
 *   完整 TBS = TBS_mldsa(含4.1.6) + 4.1.7(PQC算法) + 4.1.8(PQC签名)
 *   ML-DSA-44-with-SM3：对 SM3(TBS_mldsa) 签名，TBS_mldsa = 完整 TBS 去掉 4.1.7/4.1.8（保留4.1.6）
 *   SM2-with-SM3：对 SM3(完整 TBS) 签名，结果为证书外层签名
 */

#include "cert_verify.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/decoder.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>

#include "crypto/x509.h"

static int cv_trace = -1;

void cert_verify_set_trace(int enable)
{
    cv_trace = enable ? 1 : 0;
}

int cert_verify_trace_enabled(void)
{
    if (cv_trace < 0) {
        const char *e = getenv("CERT_VERIFY_TRACE");
        cv_trace = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0;
    }
    return cv_trace;
}

#define CV_TRACE(fmt, ...) \
    do { \
        if (cert_verify_trace_enabled()) \
            printf("[cert_verify] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define CV_TRACE_FN(fmt, ...) \
    do { \
        if (cert_verify_trace_enabled()) \
            printf("[cert_verify] %s(): " fmt "\n", __func__, ##__VA_ARGS__); \
    } while (0)

typedef struct {
    const char *oid;
    const char *name;
} CERT_VERIFY_OID_MAP;

static const CERT_VERIFY_OID_MAP oid_map[] = {
    { "1.2.156.10197.1.301", "SM2" },
    { "1.2.156.10197.1.501", "SM2-with-SM3" },
    { "1.2.156.10197.1.303.1", "ML-KEM-512" },
    { "1.2.156.10197.1.304.1", "ML-DSA-44-SPKI" },
    { CERT_VERIFY_OID_MLDSA44_SIGALG, CERT_VERIFY_SIGALG_MLDSA44_SM3 },
    { "1.2.156.10197.1.505.2", "ML-DSA-65-with-SM3" },
    { "1.2.156.10197.1.505.3", "ML-DSA-87-with-SM3" },
    { "1.2.156.10197.1.506.1", "ML-DSA-44-SM2-with-SM3" },
    { "1.2.156.10197.1.506.2", "ML-DSA-65-SM2-with-SM3" },
    { "1.2.156.10197.1.506.3", "ML-DSA-87-SM2-with-SM3" },
    { "1.2.156.10197.1.507.1", "ML-KEM-512-SM2" },
    { "1.2.156.10197.1.507.2", "ML-KEM-768-SM2" },
    { "1.2.156.10197.1.507.3", "ML-KEM-1024-SM2" },
    { "1.2.156.10197.1.508.1", "ML-DSA-44-SM2" },
    { "1.2.156.10197.1.508.2", "ML-DSA-65-SM2" },
    { "1.2.156.10197.1.508.3", "ML-DSA-87-SM2" },
    { CERT_VERIFY_OID_EXT_PQC_PUB, "PQC 主体公钥扩展" },
    { CERT_VERIFY_OID_EXT_PQC_SIGALG, "PQC 签名算法扩展" },
    { CERT_VERIFY_OID_EXT_PQC_SIG, "PQC 签名值扩展" },
    { NULL, NULL },
};

const char *cert_verify_oid_name(const char *oid)
{
    if (oid == NULL || oid[0] == '\0')
        return "-";
    for (int i = 0; oid_map[i].oid != NULL; i++) {
        if (strcmp(oid, oid_map[i].oid) == 0)
            return oid_map[i].name;
    }
    return oid;
}

static OSSL_PROVIDER *cv_prov_default;
static OSSL_PROVIDER *cv_prov_pqmagic;
static OSSL_PROVIDER *cv_prov_mldsa_sm2;

static EVP_PKEY *import_pqc_spki(OSSL_LIB_CTX *libctx,
                                 const unsigned char *der, int der_len);

#ifndef CERT_VERIFY_SM2_DEFAULT_ID
# define CERT_VERIFY_SM2_DEFAULT_ID "1234567812345678"
# define CERT_VERIFY_SM2_DEFAULT_ID_LEN (sizeof(CERT_VERIFY_SM2_DEFAULT_ID) - 1)
#endif

#ifndef DEFAULT_PQMAGIC_PROVIDER
# ifdef _WIN32
#  define DEFAULT_PQMAGIC_PROVIDER \
    "D:\\20240429certificate-verification\\tlcp-pqc\\providers\\pqmagic.dll"
# else
#  define DEFAULT_PQMAGIC_PROVIDER \
    "/home/wang/Desktop/pqmagic-algorithms-provider/build/pqmagic.so"
# endif
#endif
#ifndef DEFAULT_ML_DSA_SM2_PROVIDER
# ifdef _WIN32
#  define DEFAULT_ML_DSA_SM2_PROVIDER \
    "D:\\20240429certificate-verification\\tlcp-pqc\\providers\\libml_dsa_sm2_provider.dll"
# else
#  define DEFAULT_ML_DSA_SM2_PROVIDER \
    "/home/wang/Desktop/x509-hybrid-spki-provider/libml_dsa_sm2_provider.so"
# endif
#endif

static OSSL_PROVIDER *cv_load_provider_path(OSSL_LIB_CTX *libctx,
                                            const char *name,
                                            const char *dso_path)
{
    OSSL_PROVIDER *p = OSSL_PROVIDER_load(libctx, name);

    if (p != NULL)
        return p;
    if (dso_path != NULL && dso_path[0] != '\0')
        p = OSSL_PROVIDER_load(libctx, dso_path);
    return p;
}

int cert_verify_providers_load(OSSL_LIB_CTX *libctx)
{
    const char *pqmagic_path, *mldsa_path;

    CV_TRACE_FN("enter libctx=%p", (void *)libctx);
    pqmagic_path = getenv("PQMAGIC_PROVIDER");
    if (pqmagic_path == NULL || pqmagic_path[0] == '\0')
        pqmagic_path = DEFAULT_PQMAGIC_PROVIDER;
    mldsa_path = getenv("X509_HYBRID_SPKI_PROVIDER");
    if (mldsa_path == NULL || mldsa_path[0] == '\0')
        mldsa_path = getenv("ML_DSA_SM2_PROVIDER");
    if (mldsa_path == NULL || mldsa_path[0] == '\0')
        mldsa_path = DEFAULT_ML_DSA_SM2_PROVIDER;

    cv_prov_default = OSSL_PROVIDER_load(libctx, "default");
    cv_prov_pqmagic = cv_load_provider_path(libctx, "pqmagic", pqmagic_path);
    cv_prov_mldsa_sm2 = cv_load_provider_path(libctx, "ml_dsa_sm2", mldsa_path);
    CV_TRACE("cert_verify_providers_load -> default=%p pqmagic=%p ml_dsa_sm2=%p",
             (void *)cv_prov_default, (void *)cv_prov_pqmagic,
             (void *)cv_prov_mldsa_sm2);
    return cv_prov_default != NULL && cv_prov_pqmagic != NULL
        && cv_prov_mldsa_sm2 != NULL;
}

void cert_verify_providers_unload(OSSL_LIB_CTX *libctx)
{
    CV_TRACE_FN("enter");
    (void)libctx;
    if (cv_prov_mldsa_sm2 != NULL) {
        OSSL_PROVIDER_unload(cv_prov_mldsa_sm2);
        cv_prov_mldsa_sm2 = NULL;
    }
    if (cv_prov_pqmagic != NULL) {
        OSSL_PROVIDER_unload(cv_prov_pqmagic);
        cv_prov_pqmagic = NULL;
    }
    if (cv_prov_default != NULL) {
        OSSL_PROVIDER_unload(cv_prov_default);
        cv_prov_default = NULL;
    }
}

static ASN1_OBJECT *obj_ext_pqc_pub;
static ASN1_OBJECT *obj_ext_pqc_sigalg;
static ASN1_OBJECT *obj_ext_pqc_sig;
static int oids_inited;

static void init_oids(void)
{
    if (oids_inited)
        return;
    obj_ext_pqc_pub = OBJ_txt2obj(CERT_VERIFY_OID_EXT_PQC_PUB, 1);
    obj_ext_pqc_sigalg = OBJ_txt2obj(CERT_VERIFY_OID_EXT_PQC_SIGALG, 1);
    obj_ext_pqc_sig = OBJ_txt2obj(CERT_VERIFY_OID_EXT_PQC_SIG, 1);
    oids_inited = 1;
}

static int is_pqc_ext_oid(const ASN1_OBJECT *obj)
{
    if (obj == NULL)
        return 0;
    if (OBJ_cmp(obj, obj_ext_pqc_pub) == 0)
        return 1;
    if (OBJ_cmp(obj, obj_ext_pqc_sigalg) == 0)
        return 1;
    if (OBJ_cmp(obj, obj_ext_pqc_sig) == 0)
        return 1;
    return 0;
}

static int has_hybrid_ext(X509 *cert)
{
    int idx;

    init_oids();
    idx = X509_get_ext_by_OBJ(cert, obj_ext_pqc_pub, -1);
    CV_TRACE_FN("X509_get_ext_by_OBJ(%s) -> idx=%d => hybrid=%d",
                CERT_VERIFY_OID_EXT_PQC_PUB, idx, idx >= 0);
    return idx >= 0;
}

int cert_verify_is_hybrid_sm2_pqc(X509 *cert)
{
    if (cert == NULL)
        return 0;
    return has_hybrid_ext(cert);
}

int cert_verify_is_mldsa44_sm2(X509 *cert)
{
    if (cert == NULL)
        return 0;
    return X509_get_signature_nid(cert) == NID_ML_DSA_44_SM2_with_SM3;
}

static int parse_mldsa44_sm2_spki_raw_pubkey(X509_PUBKEY *xp,
                                             unsigned char *mldsa_pk,
                                             size_t mldsa_max, size_t *mldsa_len,
                                             unsigned char *sm2_pk, size_t sm2_max,
                                             size_t *sm2_len)
{
    const unsigned char *pk = NULL;
    int pklen = 0;
    const ASN1_OBJECT *oid = NULL;
    X509_ALGOR *algor = NULL;
    int nid;

    if (xp == NULL || !X509_PUBKEY_get0_param(NULL, &pk, &pklen, &algor, xp))
        return 0;
    X509_ALGOR_get0(&oid, NULL, NULL, algor);
    if (oid == NULL)
        return 0;
    nid = OBJ_obj2nid(oid);
    if (nid != NID_ML_DSA_44_SM2)
        return 0;
    if (pklen > 0 && pk[0] == 0) {
        pk++;
        pklen--;
    }
    if (pklen < CERT_VERIFY_MLDSA44_PK_LEN + 65)
        return 0;
    if (mldsa_max < CERT_VERIFY_MLDSA44_PK_LEN || sm2_max < 65)
        return 0;
    memcpy(mldsa_pk, pk, CERT_VERIFY_MLDSA44_PK_LEN);
    *mldsa_len = CERT_VERIFY_MLDSA44_PK_LEN;
    memcpy(sm2_pk, pk + CERT_VERIFY_MLDSA44_PK_LEN, 65);
    *sm2_len = 65;
    return 1;
}

static int parse_mldsa44_sm2_spki_raw(X509 *cert,
                                      unsigned char *mldsa_pk,
                                      size_t mldsa_max, size_t *mldsa_len,
                                      unsigned char *sm2_pk, size_t sm2_max,
                                      size_t *sm2_len)
{
    return parse_mldsa44_sm2_spki_raw_pubkey(X509_get_X509_PUBKEY(cert),
                                             mldsa_pk, mldsa_max, mldsa_len,
                                             sm2_pk, sm2_max, sm2_len);
}

static EVP_PKEY *import_mldsa44_raw_pk(OSSL_LIB_CTX *libctx,
                                       const unsigned char *pk_raw, size_t pklen)
{
    X509_PUBKEY *xp = NULL;
    unsigned char *der = NULL;
    int der_len = 0;
    unsigned char *owned = NULL;
    EVP_PKEY *pkey = NULL;

    if (pklen != CERT_VERIFY_MLDSA44_PK_LEN)
        return NULL;
    owned = OPENSSL_memdup(pk_raw, pklen);
    if (owned == NULL)
        return NULL;
    xp = X509_PUBKEY_new();
    if (xp == NULL)
        goto err;
    if (!X509_PUBKEY_set0_param(xp, OBJ_nid2obj(NID_ML_DSA_44_SPKI),
                                V_ASN1_NULL, NULL, owned, (int)pklen)) {
        OPENSSL_free(owned);
        owned = NULL;
        goto err;
    }
    owned = NULL;
    der_len = i2d_X509_PUBKEY(xp, &der);
    if (der_len <= 0 || der == NULL)
        goto err;
    pkey = import_pqc_spki(libctx, der, der_len);
err:
    OPENSSL_free(owned);
    OPENSSL_free(der);
    X509_PUBKEY_free(xp);
    return pkey;
}

static EC_KEY *sm2_ec_from_raw_pub(const unsigned char *sm2_pub, size_t sm2_len)
{
    EC_GROUP *group = NULL;
    EC_KEY *ec_key = NULL;
    EC_POINT *pub_point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BN_CTX *bn_ctx = NULL;
    const unsigned char *p = sm2_pub;
    int ret = 0;

    if (sm2_len < 64)
        return NULL;
    if (sm2_len == 65 && p[0] == 0x04)
        p++;
    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return NULL;
    BN_CTX_start(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    if (y == NULL)
        goto err;
    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)
        goto err;
    ec_key = EC_KEY_new();
    if (ec_key == NULL || EC_KEY_set_group(ec_key, group) == 0)
        goto err;
    if (BN_bin2bn(p, 32, x) == NULL || BN_bin2bn(p + 32, 32, y) == NULL)
        goto err;
    pub_point = EC_POINT_new(group);
    if (pub_point == NULL
        || EC_POINT_set_affine_coordinates(group, pub_point, x, y, bn_ctx) == 0
        || EC_KEY_set_public_key(ec_key, pub_point) == 0)
        goto err;
    ret = 1;
err:
    EC_POINT_free(pub_point);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    if (!ret) {
        EC_KEY_free(ec_key);
        return NULL;
    }
    return ec_key;
}

static int sm2_with_sm3_verify_ec(OSSL_LIB_CTX *libctx, EC_KEY *ec,
                                  const unsigned char *msg, size_t msglen,
                                  const unsigned char *sig, size_t siglen)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;

    if (ec == NULL || sig == NULL || siglen == 0)
        return 0;
    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        return 0;
#ifndef OPENSSL_NO_EC
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec);
        return 0;
    }
    ec = NULL;
#endif
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto end;
    if (!EVP_DigestVerifyInit_ex(ctx, &pctx, "SM3", libctx, NULL, pkey, NULL))
        goto end;
    if (EVP_PKEY_is_a(pkey, "SM2")
        && EVP_PKEY_CTX_set1_id(pctx, CERT_VERIFY_SM2_DEFAULT_ID,
                                CERT_VERIFY_SM2_DEFAULT_ID_LEN) <= 0)
        goto end;
    if (!EVP_DigestVerifyUpdate(ctx, msg, msglen))
        goto end;
    ok = EVP_DigestVerifyFinal(ctx, sig, siglen) == 1;
end:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec);
    return ok;
}

static int tbs_bytes(X509 *cert, unsigned char **out, int *len)
{
    struct x509_st *xc = (struct x509_st *)cert;

    *out = NULL;
    *len = i2d_X509_CINF(&xc->cert_info, out);
    CV_TRACE_FN("i2d_X509_CINF(完整 CertificateInfo) -> len=%d", *len);
    return *len > 0;
}

static int cri_bytes(X509_REQ *req, unsigned char **out, int *len)
{
    *out = NULL;
    *len = i2d_re_X509_REQ_tbs(req, out);
    CV_TRACE_FN("i2d_re_X509_REQ_tbs(完整 CertificationRequestInfo) -> len=%d",
                *len);
    return *len > 0;
}

/* 从扩展 4.1.6 内层 SPKI DER 导入 ML-DSA-44 公钥（pqmagic provider） */
static EVP_PKEY *import_pqc_spki(OSSL_LIB_CTX *libctx,
                                 const unsigned char *der, int der_len)
{
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    const unsigned char *p = der;
    size_t len = (size_t)der_len;

    if (der == NULL || der_len <= 0)
        return NULL;
    CV_TRACE_FN("OSSL_DECODER 导入签发者 PQC 公钥 (provider=pqmagic), SPKI DER %d 字节",
                der_len);
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "SubjectPublicKeyInfo",
                                         NULL, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                         libctx, "provider=pqmagic");
    if (dctx == NULL)
        return NULL;
    if (!OSSL_DECODER_from_data(dctx, &p, &len))
        pkey = NULL;
    OSSL_DECODER_CTX_free(dctx);
    CV_TRACE_FN("import_pqc_spki -> EVP_PKEY* %p", (void *)pkey);
    return pkey;
}

/*
 * ML-DSA-44-with-SM3（OID 1.2.156.10197.1.505.1）：
 * 经 pqmagic provider 的 EVP_DigestVerify(SM3, ML-DSA-44-SPKI) 验签。
 */
static int mldsa44_with_sm3_verify(OSSL_LIB_CTX *libctx, EVP_PKEY *pqc_issuer,
                                     const unsigned char *msg, size_t msglen,
                                     const unsigned char *sig, size_t siglen)
{
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;

    CV_TRACE_FN("enter libctx=%p pqc_issuer=%p msglen=%zu siglen=%zu",
                (void *)libctx, (void *)pqc_issuer, msglen, siglen);
    if (pqc_issuer == NULL || siglen != CERT_VERIFY_MLDSA44_SIG_LEN) {
        CV_TRACE_FN("参数无效 pqc_issuer=%p siglen=%zu (期望 %d)",
                    (void *)pqc_issuer, siglen, CERT_VERIFY_MLDSA44_SIG_LEN);
        return 0;
    }
    CV_TRACE_FN("ML-DSA-44-with-SM3 验签: msglen=%zu siglen=%zu", msglen, siglen);
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;
    if (!EVP_DigestVerifyInit_ex(ctx, NULL, "SM3", libctx, NULL, pqc_issuer, NULL)) {
        CV_TRACE("  EVP_DigestVerifyInit_ex(SM3, ML-DSA-44-SPKI/pqmagic) -> FAIL");
    } else {
        CV_TRACE("  EVP_DigestVerifyInit_ex(SM3) -> OK");
        if (!EVP_DigestVerifyUpdate(ctx, msg, msglen))
            CV_TRACE("  EVP_DigestVerifyUpdate(%zu bytes) -> FAIL", msglen);
        else if (EVP_DigestVerifyFinal(ctx, sig, siglen) == 1) {
            CV_TRACE("  EVP_DigestVerifyFinal -> OK (验签通过)");
            ok = 1;
        } else {
            CV_TRACE("  EVP_DigestVerifyFinal -> FAIL (验签未通过)");
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

static void delete_ext_by_obj(X509 *cert, ASN1_OBJECT *obj)
{
    int idx;

    for (;;) {
        idx = X509_get_ext_by_OBJ(cert, obj, -1);
        if (idx < 0)
            break;
        X509_delete_ext(cert, idx);
    }
}

unsigned char *cert_verify_build_orig_tbs_hybrid(X509 *cert, int *orig_len)
{
    X509 *tmp;
    unsigned char *out = NULL;

    CV_TRACE_FN("enter cert=%p", (void *)cert);
    init_oids();
    tmp = X509_dup(cert);
    if (tmp == NULL)
        return NULL;
    /*
     * ML-DSA 待验 TBS：在完整 TBS 基础上去掉 4.1.7、4.1.8，保留 4.1.6 与其余扩展。
     * 须 i2d_re_X509_tbs 重编码；i2d_X509_CINF 可能仍返回含 4.1.7/4.1.8 的缓存 DER。
     */
    delete_ext_by_obj(tmp, obj_ext_pqc_sigalg);
    delete_ext_by_obj(tmp, obj_ext_pqc_sig);
    *orig_len = i2d_re_X509_tbs(tmp, &out);
    CV_TRACE_FN("cert_verify_build_orig_tbs_hybrid: 去掉 %s/%s 后 i2d_re_X509_tbs -> %d 字节",
                CERT_VERIFY_OID_EXT_PQC_SIGALG, CERT_VERIFY_OID_EXT_PQC_SIG,
                *orig_len);
    X509_free(tmp);
    return *orig_len > 0 ? out : NULL;
}

static const unsigned char *ext_octet_data(X509 *cert, ASN1_OBJECT *obj,
                                           int *out_len)
{
    int idx = X509_get_ext_by_OBJ(cert, obj, -1);
    X509_EXTENSION *ex;
    ASN1_OCTET_STRING *os;

    if (idx < 0)
        return NULL;
    ex = X509_get_ext(cert, idx);
    os = ex != NULL ? X509_EXTENSION_get_data(ex) : NULL;
    if (os == NULL)
        return NULL;
    *out_len = ASN1_STRING_length(os);
    return ASN1_STRING_get0_data(os);
}

static int parse_pqc_pubkey_ext(const unsigned char *der, int der_len,
                                char *alg_oid, size_t alg_sz,
                                unsigned char *pk, size_t pk_max,
                                size_t *pk_len)
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

int cert_verify_get_ext_pqc_pubkey(X509 *cert, unsigned char *pk, size_t pk_max,
                                   size_t *pk_len, char *alg_oid, size_t alg_sz)
{
    const unsigned char *der;
    int der_len = 0;
    int ok;

    init_oids();
    der = ext_octet_data(cert, obj_ext_pqc_pub, &der_len);
    if (der == NULL || der_len <= 0) {
        CV_TRACE_FN("ext_octet_data(%s) 无数据", CERT_VERIFY_OID_EXT_PQC_PUB);
        return 0;
    }
    ok = parse_pqc_pubkey_ext(der, der_len, alg_oid, alg_sz, pk, pk_max, pk_len);
    CV_TRACE_FN("parse_pqc_pubkey_ext(%s) -> %s, oid=%s, 裸公钥 %zu 字节",
                CERT_VERIFY_OID_EXT_PQC_PUB, ok ? "OK" : "FAIL",
                ok ? alg_oid : "-", ok ? *pk_len : (size_t)0);
    return ok;
}

int cert_verify_get_ext_pqc_signature(X509 *cert, unsigned char *sig,
                                      size_t sig_max, size_t *sig_len)
{
    const unsigned char *der;
    int der_len = 0;

    init_oids();
    der = ext_octet_data(cert, obj_ext_pqc_sig, &der_len);
    if (der == NULL || der_len <= 0)
        return 0;
    if ((size_t)der_len == CERT_VERIFY_MLDSA44_SIG_LEN) {
        memcpy(sig, der, (size_t)der_len);
        *sig_len = (size_t)der_len;
        CV_TRACE_FN("cert_verify_get_ext_pqc_signature(%s) -> %zu 字节 (直接 OCTET)",
                    CERT_VERIFY_OID_EXT_PQC_SIG, *sig_len);
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
        if ((size_t)sl == CERT_VERIFY_MLDSA44_SIG_LEN) {
            memcpy(sig, p, (size_t)sl);
            *sig_len = (size_t)sl;
            CV_TRACE_FN("cert_verify_get_ext_pqc_signature(%s) -> %zu 字节 (嵌套 OCTET)",
                        CERT_VERIFY_OID_EXT_PQC_SIG, *sig_len);
            return 1;
        }
    }
    CV_TRACE_FN("cert_verify_get_ext_pqc_signature(%s) -> FAIL", CERT_VERIFY_OID_EXT_PQC_SIG);
    return 0;
}

int cert_verify_get_issuer_pqc_pubkey(X509 *issuer, unsigned char *pk,
                                     size_t pk_max, size_t *pk_len)
{
    char alg[64];

    return cert_verify_get_ext_pqc_pubkey(issuer, pk, pk_max, pk_len, alg,
                                          sizeof(alg));
}

static void asn1_time_to_str(const ASN1_TIME *t, char *buf, size_t bufsz)
{
    BIO *b;

    if (t == NULL) {
        snprintf(buf, bufsz, "-");
        return;
    }
    b = BIO_new(BIO_s_mem());
    if (b == NULL) {
        snprintf(buf, bufsz, "-");
        return;
    }
    ASN1_TIME_print(b, t);
    {
        char *data = NULL;
        long n = BIO_get_mem_data(b, &data);

        if (n > 0 && data != NULL) {
            snprintf(buf, bufsz, "%.*s", (int)(n < (long)bufsz - 1 ? n : (long)bufsz - 1), data);
        }
    }
    BIO_free(b);
}

static void serial_to_hex(const ASN1_INTEGER *serial, char *hex, size_t hexsz)
{
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    char *s = NULL;

    if (bn == NULL) {
        snprintf(hex, hexsz, "-");
        return;
    }
    s = BN_bn2hex(bn);
    BN_free(bn);
    if (s == NULL) {
        snprintf(hex, hexsz, "-");
        return;
    }
    snprintf(hex, hexsz, "%s", s);
    OPENSSL_free(s);
}

int cert_verify_parse_cert(X509 *cert, CERT_VERIFY_PARSED *info)
{
    const ASN1_BIT_STRING *sig;
    const X509_ALGOR *alg;
    X509_PUBKEY *xp;
    const unsigned char *pk;
    int pklen;

    CV_TRACE_FN("enter cert=%p", (void *)cert);
    memset(info, 0, sizeof(*info));
    if (cert == NULL)
        return 0;

    info->is_hybrid_sm2_pqc = has_hybrid_ext(cert);
    info->version = X509_get_version(cert) + 1;
    serial_to_hex(X509_get_serialNumber(cert), info->serial_hex,
                  sizeof(info->serial_hex));

    {
        const X509_ALGOR *tsig = X509_get0_tbs_sigalg(cert);
        if (tsig != NULL && tsig->algorithm != NULL)
            OBJ_obj2txt(info->sig_alg_tbs, (int)sizeof(info->sig_alg_tbs),
                        tsig->algorithm, 1);
    }
    X509_NAME_oneline(X509_get_issuer_name(cert), info->issuer,
                      (int)sizeof(info->issuer));
    X509_NAME_oneline(X509_get_subject_name(cert), info->subject,
                      (int)sizeof(info->subject));
    asn1_time_to_str(X509_get0_notBefore(cert), info->not_before,
                     sizeof(info->not_before));
    asn1_time_to_str(X509_get0_notAfter(cert), info->not_after,
                     sizeof(info->not_after));

    xp = X509_get_X509_PUBKEY(cert);
    if (xp != NULL && X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, xp)) {
        X509_ALGOR *palg = NULL;
        const ASN1_OBJECT *pub_oid_const = NULL;

        X509_PUBKEY_get0_param(NULL, &pk, &pklen, &palg, xp);
        if (palg != NULL) {
            X509_ALGOR_get0(&pub_oid_const, NULL, NULL, palg);
            if (pub_oid_const != NULL)
                OBJ_obj2txt(info->subject_sm2_oid, (int)sizeof(info->subject_sm2_oid),
                            pub_oid_const, 1);
        }
        if (pklen > 0 && pk[0] == 0) {
            pk++;
            pklen--;
        }
        if ((size_t)pklen <= sizeof(info->subject_sm2_pk)) {
            memcpy(info->subject_sm2_pk, pk, (size_t)pklen);
            info->subject_sm2_pk_len = (size_t)pklen;
        }
    }

    if (info->is_hybrid_sm2_pqc) {
        const unsigned char *oct;
        int oct_len = 0;

        init_oids();
        cert_verify_get_ext_pqc_pubkey(cert, info->ext_pqc_pub,
                                       sizeof(info->ext_pqc_pub),
                                       &info->ext_pqc_pub_len,
                                       info->ext_pqc_pub_oid,
                                       sizeof(info->ext_pqc_pub_oid));
        oct = ext_octet_data(cert, obj_ext_pqc_pub, &oct_len);
        if (oct != NULL && oct_len > 0
            && (size_t)oct_len <= sizeof(info->ext_pqc_pub_octet)) {
            memcpy(info->ext_pqc_pub_octet, oct, (size_t)oct_len);
            info->ext_pqc_pub_octet_len = (size_t)oct_len;
        }
        oct = ext_octet_data(cert, obj_ext_pqc_sigalg, &oct_len);
        if (oct != NULL && oct_len > 0
            && (size_t)oct_len <= sizeof(info->ext_pqc_sigalg_octet)) {
            const unsigned char *p = oct;
            X509_ALGOR *a;

            memcpy(info->ext_pqc_sigalg_octet, oct, (size_t)oct_len);
            info->ext_pqc_sigalg_octet_len = (size_t)oct_len;
            a = d2i_X509_ALGOR(NULL, &p, oct_len);
            if (a != NULL && a->algorithm != NULL) {
                OBJ_obj2txt(info->ext_pqc_sigalg_oid,
                            (int)sizeof(info->ext_pqc_sigalg_oid),
                            a->algorithm, 1);
                snprintf(info->ext_pqc_sigalg_name,
                         sizeof(info->ext_pqc_sigalg_name), "%s",
                         cert_verify_oid_name(info->ext_pqc_sigalg_oid));
                X509_ALGOR_free(a);
            }
        }
        cert_verify_get_ext_pqc_signature(cert, info->ext_pqc_sig,
                                          sizeof(info->ext_pqc_sig),
                                          &info->ext_pqc_sig_len);
    }

    X509_get0_signature(&sig, &alg, cert);
    if (alg != NULL && alg->algorithm != NULL)
        OBJ_obj2txt(info->outer_sig_alg, (int)sizeof(info->outer_sig_alg),
                    alg->algorithm, 1);
    if (sig != NULL)
        info->outer_sig_len = (size_t)ASN1_STRING_length(sig);

    return 1;
}

static void print_hex_lines(const char *indent, const unsigned char *data,
                            size_t len)
{
    size_t i;

    if (data == NULL || len == 0) {
        printf("%s(空)\n", indent);
        return;
    }
    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("%s", indent);
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 || i + 1 == len)
            printf("\n");
        else if ((i + 1) % 8 == 0)
            printf("  ");
        else
            printf(" ");
    }
}

void cert_verify_print_parsed(const char *label, const CERT_VERIFY_PARSED *p)
{
    printf("[%s]\n", label);
    printf("  版本: V%ld\n", p->version);
    printf("  序列号: %s\n", p->serial_hex);
    printf("  TBS 签名算法: %s\n", p->sig_alg_tbs);
    printf("  颁发者: %s\n", p->issuer);
    printf("  有效期: %s  ~  %s\n", p->not_before, p->not_after);
    printf("  主体: %s\n", p->subject);
    printf("  主体公钥算法: %s (%s, %zu 字节)\n", p->subject_sm2_oid,
           cert_verify_oid_name(p->subject_sm2_oid), p->subject_sm2_pk_len);
    if (p->subject_sm2_pk_len > 0) {
        printf("    主体 SM2 公钥(十六进制):\n");
        print_hex_lines("      ", p->subject_sm2_pk, p->subject_sm2_pk_len);
    }
    if (p->is_hybrid_sm2_pqc) {
        printf("  扩展 %s (PQC 公钥，扩展 OCTET 整体 %zu 字节):\n",
               CERT_VERIFY_OID_EXT_PQC_PUB, p->ext_pqc_pub_octet_len);
        printf("    内层 SPKI 算法: %s (%s)\n", p->ext_pqc_pub_oid,
               cert_verify_oid_name(p->ext_pqc_pub_oid));
        printf("    内层 BIT STRING 裸公钥: %zu 字节\n", p->ext_pqc_pub_len);
        if (p->ext_pqc_pub_octet_len > 0) {
            printf("    4.1.6 OCTET 内容(十六进制，验签拼接用此整体):\n");
            print_hex_lines("      ", p->ext_pqc_pub_octet,
                            p->ext_pqc_pub_octet_len);
        }
        printf("  扩展 %s (PQC 签名算法, OCTET %zu 字节): %s (%s)\n",
               CERT_VERIFY_OID_EXT_PQC_SIGALG, p->ext_pqc_sigalg_octet_len,
               p->ext_pqc_sigalg_oid,
               p->ext_pqc_sigalg_name[0] ? p->ext_pqc_sigalg_name
                                         : cert_verify_oid_name(p->ext_pqc_sigalg_oid));
        if (p->ext_pqc_sigalg_octet_len > 0) {
            printf("    4.1.7 OCTET DER(十六进制):\n");
            print_hex_lines("      ", p->ext_pqc_sigalg_octet,
                            p->ext_pqc_sigalg_octet_len);
        }
        printf("  扩展 %s (PQC 签名值): %zu 字节\n", CERT_VERIFY_OID_EXT_PQC_SIG,
               p->ext_pqc_sig_len);
        if (p->ext_pqc_sig_len > 0) {
            printf("    4.1.8 签名(十六进制):\n");
            print_hex_lines("      ", p->ext_pqc_sig, p->ext_pqc_sig_len);
        }
    }
    printf("  外层签名算法: %s (%s, %zu 字节)\n", p->outer_sig_alg,
           cert_verify_oid_name(p->outer_sig_alg), p->outer_sig_len);
    printf("\n");
}

int cert_verify_mldsa_hybrid(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx)
{
    unsigned char *tbs_mldsa = NULL;
    const unsigned char *iss_spki = NULL;
    unsigned char pqc_sig[CERT_VERIFY_MLDSA44_SIG_LEN];
    size_t sig_len = 0;
    int iss_spki_len = 0;
    int tbs_len = 0;
    EVP_PKEY *issuer_pqc = NULL;
    int ok = 0;

    CV_TRACE("--- cert_verify_mldsa_hybrid (混合证 ML-DSA 步) ---");
    init_oids();
    if (!has_hybrid_ext(cert))
        return 0;
    CV_TRACE("  [1] ext_octet_data(签发者, %s) -> import_pqc_spki", CERT_VERIFY_OID_EXT_PQC_PUB);
    iss_spki = ext_octet_data(issuer, obj_ext_pqc_pub, &iss_spki_len);
    if (iss_spki == NULL || iss_spki_len <= 0)
        return 0;
    issuer_pqc = import_pqc_spki(libctx, iss_spki, iss_spki_len);
    if (issuer_pqc == NULL)
        return 0;
    CV_TRACE("  [2] cert_verify_get_ext_pqc_signature(本证, %s)", CERT_VERIFY_OID_EXT_PQC_SIG);
    if (!cert_verify_get_ext_pqc_signature(cert, pqc_sig, sizeof(pqc_sig), &sig_len))
        goto end;
    CV_TRACE("  [3] cert_verify_build_orig_tbs_hybrid(本证) -> 完整TBS去掉4.1.7/4.1.8(含4.1.6)");
    tbs_mldsa = cert_verify_build_orig_tbs_hybrid(cert, &tbs_len);
    if (tbs_mldsa == NULL)
        goto end;
    CV_TRACE("  [4] 待验消息 = TBS(完整TBS减4.1.7/8，含4.1.6) %d 字节", tbs_len);
    CV_TRACE("  [5] mldsa44_with_sm3_verify() 即 EVP DigestVerify(SM3+ML-DSA-44)");
    ok = mldsa44_with_sm3_verify(libctx, issuer_pqc, tbs_mldsa, (size_t)tbs_len,
                                 pqc_sig, sig_len);
    CV_TRACE("  cert_verify_mldsa_hybrid -> %s", ok ? "OK" : "FAIL");

end:
    EVP_PKEY_free(issuer_pqc);
    OPENSSL_free(tbs_mldsa);
    return ok;
}

int cert_verify_sm2_outer(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx)
{
    unsigned char *tbs = NULL;
    int tbslen = 0;
    const ASN1_BIT_STRING *sig = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;

    CV_TRACE("--- cert_verify_sm2_outer (混合证 SM2 外层) ---");
    CV_TRACE("  [1] tbs_bytes() -> i2d_X509_CINF(完整 TBS，含 4.1.6/7/8)");
    if (!tbs_bytes(cert, &tbs, &tbslen))
        return 0;
    CV_TRACE("  [2] X509_get0_pubkey(签发者 SM2 SPKI)");
    pkey = X509_get0_pubkey(issuer);
    if (pkey == NULL) {
        OPENSSL_free(tbs);
        return 0;
    }
    CV_TRACE("  [3] X509_get0_signature(本证外层 BIT STRING)");
    X509_get0_signature(&sig, NULL, cert);
    if (sig == NULL)
        goto end;
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto end;
    CV_TRACE("  [4] EVP_DigestVerifyInit_ex(SM3) + Update(完整TBS %d) + Final(外层签名 %d)",
             tbslen, ASN1_STRING_length(sig));
    if (!EVP_DigestVerifyInit_ex(ctx, NULL, "SM3", libctx, NULL, pkey, NULL))
        goto end;
    if (!EVP_DigestVerifyUpdate(ctx, tbs, (size_t)tbslen))
        goto end;
    ok = EVP_DigestVerifyFinal(ctx, ASN1_STRING_get0_data(sig),
                               (size_t)ASN1_STRING_length(sig)) == 1;
    CV_TRACE("  cert_verify_sm2_outer -> %s", ok ? "OK" : "FAIL");

end:
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(tbs);
    return ok;
}

/* ---------- 纯 PQC SPKI 证书（certs/1）---------- */

unsigned char *cert_verify_strip_extensions(const unsigned char *tbs, int tbs_len,
                                            int *orig_len)
{
    const unsigned char *p = tbs;
    long len = tbs_len;
    int tag, xclass;
    long seqlen;
    const unsigned char *q;
    long left;
    const unsigned char *last_ext = NULL;

    if (tbs == NULL || tbs_len <= 0 || orig_len == NULL)
        return NULL;
    if (ASN1_get_object(&p, &seqlen, &tag, &xclass, len) & 0x80)
        return NULL;
    if (tag != V_ASN1_SEQUENCE)
        return NULL;
    q = p;
    left = seqlen;
    while (left > 0) {
        const unsigned char *el = q;
        long elen;
        int t, xc;

        if (ASN1_get_object(&q, &elen, &t, &xc, left) & 0x80)
            return NULL;
        if (xc == V_ASN1_CONTEXT_SPECIFIC && t == 3)
            last_ext = el;
        left -= (q - el) + elen;
    }
    if (last_ext != NULL) {
        *orig_len = (int)(last_ext - tbs);
        return OPENSSL_memdup(tbs, *orig_len);
    }
    *orig_len = tbs_len;
    return OPENSSL_memdup(tbs, tbs_len);
}

static int spki_raw_octets(X509 *cert, unsigned char *pk_out, size_t pk_out_len,
                           size_t *pk_len, char *oid_text, size_t oid_sz)
{
    X509_PUBKEY *xp = X509_get_X509_PUBKEY(cert);
    const unsigned char *pk = NULL;
    int pklen = 0;
    ASN1_OBJECT *oid = NULL;
    X509_ALGOR *algor = NULL;

    if (xp == NULL || !X509_PUBKEY_get0_param(NULL, &pk, &pklen, &algor, xp))
        return 0;
    X509_ALGOR_get0((const ASN1_OBJECT **)&oid, NULL, NULL, algor);
    if (oid == NULL || OBJ_obj2txt(oid_text, (int)oid_sz, oid, 1) <= 0)
        return 0;
    if (pklen > 0 && pk[0] == 0) {
        pk++;
        pklen--;
    }
    if ((size_t)pklen > pk_out_len)
        return 0;
    memcpy(pk_out, pk, (size_t)pklen);
    *pk_len = (size_t)pklen;
    return 1;
}

int cert_verify_get_subject_pqc_pubkey(X509 *cert, unsigned char *pk_out,
                                     size_t pk_out_len, size_t *pk_len,
                                     char *oid_text, size_t oid_sz)
{
    size_t len = 0;

    if (!spki_raw_octets(cert, pk_out, pk_out_len, &len, oid_text, oid_sz))
        return 0;
    if (strcmp(oid_text, CERT_VERIFY_OID_MLDSA44_SPKI) != 0
        && strcmp(oid_text, CERT_VERIFY_OID_MLKEM512_SPKI) != 0)
        return 0;
    *pk_len = len;
    return 1;
}

int cert_verify_mldsa_tbs_plus_pqc(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx)
{
    unsigned char *tbs = NULL, *orig = NULL, *buf = NULL;
    unsigned char subj_pk[CERT_VERIFY_MLDSA44_PK_LEN];
    unsigned char pqc_sig[CERT_VERIFY_MLDSA44_SIG_LEN];
    size_t subj_len = 0, sig_len = 0;
    char oid[64];
    int tbslen = 0, origlen = 0;
    EVP_PKEY *issuer_pqc = NULL;
    int ok = 0;

    if (has_hybrid_ext(cert))
        return cert_verify_mldsa_hybrid(cert, issuer, libctx);

    issuer_pqc = X509_get0_pubkey(issuer);
    if (issuer_pqc == NULL)
        return 0;
    if (!tbs_bytes(cert, &tbs, &tbslen))
        return 0;
    orig = cert_verify_strip_extensions(tbs, tbslen, &origlen);
    if (orig == NULL)
        goto end;
    if (!cert_verify_get_subject_pqc_pubkey(cert, subj_pk, sizeof(subj_pk), &subj_len,
                                            oid, sizeof(oid)))
        goto end;
    if (!cert_verify_get_ext_pqc_signature(cert, pqc_sig, sizeof(pqc_sig), &sig_len)) {
        const ASN1_BIT_STRING *osig = NULL;
        X509_get0_signature(&osig, NULL, cert);
        if (osig == NULL || (size_t)osig->length != CERT_VERIFY_MLDSA44_SIG_LEN)
            goto end;
        memcpy(pqc_sig, osig->data, CERT_VERIFY_MLDSA44_SIG_LEN);
        sig_len = CERT_VERIFY_MLDSA44_SIG_LEN;
    }
    buf = OPENSSL_malloc((size_t)origlen + subj_len);
    if (buf == NULL)
        goto end;
    memcpy(buf, orig, (size_t)origlen);
    memcpy(buf + origlen, subj_pk, subj_len);
    ok = mldsa44_with_sm3_verify(libctx, issuer_pqc, buf,
                                 (size_t)origlen + subj_len, pqc_sig, sig_len);

end:
    OPENSSL_free(tbs);
    OPENSSL_free(orig);
    OPENSSL_free(buf);
    return ok;
}

int cert_verify_mldsa_full_tbs_standard(X509 *cert, X509 *issuer,
                                        OSSL_LIB_CTX *libctx)
{
    unsigned char *tbs = NULL;
    int tbslen = 0;
    const ASN1_BIT_STRING *sig = NULL;
    EVP_PKEY *issuer_pqc = NULL;
    int ok = 0;

    if (has_hybrid_ext(cert))
        return 0;
    issuer_pqc = X509_get0_pubkey(issuer);
    if (issuer_pqc == NULL)
        return 0;
    if (!tbs_bytes(cert, &tbs, &tbslen))
        return 0;
    X509_get0_signature(&sig, NULL, cert);
    if (sig != NULL)
        ok = mldsa44_with_sm3_verify(libctx, issuer_pqc, tbs, (size_t)tbslen,
                                     sig->data, (size_t)sig->length);
    OPENSSL_free(tbs);
    return ok;
}

int cert_verify_sm2_full_tbs(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx)
{
    if (has_hybrid_ext(cert))
        return cert_verify_sm2_outer(cert, issuer, libctx);
    return cert_verify_sm2_outer(cert, issuer, libctx);
}

int cert_verify_mldsa44_sm2_over_tbs(X509 *issuer,
                                     const unsigned char *tbs, size_t tbslen,
                                     const unsigned char *sig, size_t siglen,
                                     OSSL_LIB_CTX *libctx)
{
    unsigned char mldsa_pk[CERT_VERIFY_MLDSA44_PK_LEN];
    unsigned char sm2_pk[65];
    size_t mldsa_len = 0, sm2_len = 0;
    EVP_PKEY *issuer_mldsa = NULL;
    EC_KEY *issuer_sm2 = NULL;
    size_t sm2_sig_len;
    int ok = 0;

    CV_TRACE("--- cert_verify_mldsa44_sm2_over_tbs ---");
    if (issuer == NULL || tbs == NULL || sig == NULL || tbslen == 0)
        return 0;
    if (!parse_mldsa44_sm2_spki_raw(issuer, mldsa_pk, sizeof(mldsa_pk), &mldsa_len,
                                    sm2_pk, sizeof(sm2_pk), &sm2_len)) {
        CV_TRACE("  解析签发者 ML-DSA-44-SM2 SPKI 失败");
        return 0;
    }
    issuer_mldsa = import_mldsa44_raw_pk(libctx, mldsa_pk, mldsa_len);
    issuer_sm2 = sm2_ec_from_raw_pub(sm2_pk, sm2_len);
    if (issuer_mldsa == NULL || issuer_sm2 == NULL) {
        CV_TRACE("  导入签发者 ML-DSA/SM2 公钥失败");
        goto end;
    }
    if (siglen <= CERT_VERIFY_MLDSA44_SIG_LEN) {
        CV_TRACE("  外层签名长度无效");
        goto end;
    }
    sm2_sig_len = siglen - CERT_VERIFY_MLDSA44_SIG_LEN;
    CV_TRACE("  ML-DSA 段 %d 字节 + SM2 段 %zu 字节，TBS %zu 字节",
             CERT_VERIFY_MLDSA44_SIG_LEN, sm2_sig_len, tbslen);
    ok = mldsa44_with_sm3_verify(libctx, issuer_mldsa, tbs, tbslen,
                                 sig, CERT_VERIFY_MLDSA44_SIG_LEN);
    CV_TRACE("  ML-DSA-44-with-SM3(完整TBS) -> %s", ok ? "OK" : "FAIL");
    if (!ok)
        goto end;
    ok = sm2_with_sm3_verify_ec(libctx, issuer_sm2, tbs, tbslen,
                               sig + CERT_VERIFY_MLDSA44_SIG_LEN,
                               sm2_sig_len);
    issuer_sm2 = NULL;
    CV_TRACE("  SM2-with-SM3(完整TBS) -> %s", ok ? "OK" : "FAIL");

end:
    EVP_PKEY_free(issuer_mldsa);
    EC_KEY_free(issuer_sm2);
    return ok;
}

int cert_verify_mldsa44_sm2_composite(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx)
{
    unsigned char *tbs = NULL;
    int tbslen = 0;
    const ASN1_BIT_STRING *outer_sig = NULL;
    int ok = 0;

    CV_TRACE("--- cert_verify_mldsa44_sm2_composite (certs/2) ---");
    if (!cert_verify_is_mldsa44_sm2(cert))
        return 0;
    if (!tbs_bytes(cert, &tbs, &tbslen))
        return 0;
    X509_get0_signature(&outer_sig, NULL, cert);
    if (outer_sig == NULL) {
        OPENSSL_free(tbs);
        return 0;
    }
    ok = cert_verify_mldsa44_sm2_over_tbs(issuer, tbs, (size_t)tbslen,
                                          ASN1_STRING_get0_data(outer_sig),
                                          (size_t)ASN1_STRING_length(outer_sig),
                                          libctx);
    OPENSSL_free(tbs);
    return ok;
}

int cert_verify_is_mldsa44_sm2_req(X509_REQ *req)
{
    if (req == NULL)
        return 0;
    return X509_REQ_get_signature_nid(req) == NID_ML_DSA_44_SM2_with_SM3;
}

int cert_verify_req_mldsa44_sm2_composite(X509_REQ *req, OSSL_LIB_CTX *libctx)
{
    unsigned char mldsa_pk[CERT_VERIFY_MLDSA44_PK_LEN];
    unsigned char sm2_pk[65];
    size_t mldsa_len = 0, sm2_len = 0;
    unsigned char *cri = NULL;
    int crilen = 0;
    const ASN1_BIT_STRING *sig = NULL;
    EVP_PKEY *mldsa_pub = NULL;
    EC_KEY *sm2_pub = NULL;
    size_t sm2_sig_len;
    int ok = 0;

    CV_TRACE("--- cert_verify_req_mldsa44_sm2_composite (certs/2 CSR) ---");
    if (!cert_verify_is_mldsa44_sm2_req(req))
        return 0;
    if (!parse_mldsa44_sm2_spki_raw_pubkey(X509_REQ_get_X509_PUBKEY(req),
                                           mldsa_pk, sizeof(mldsa_pk), &mldsa_len,
                                           sm2_pk, sizeof(sm2_pk), &sm2_len)) {
        CV_TRACE("  解析 CSR ML-DSA-44-SM2 SPKI 失败");
        return 0;
    }
    mldsa_pub = import_mldsa44_raw_pk(libctx, mldsa_pk, mldsa_len);
    sm2_pub = sm2_ec_from_raw_pub(sm2_pk, sm2_len);
    if (mldsa_pub == NULL || sm2_pub == NULL) {
        CV_TRACE("  导入 CSR ML-DSA/SM2 公钥失败");
        goto end;
    }
    if (!cri_bytes(req, &cri, &crilen))
        goto end;
    X509_REQ_get0_signature(req, &sig, NULL);
    if (sig == NULL
        || (size_t)ASN1_STRING_length(sig) <= CERT_VERIFY_MLDSA44_SIG_LEN) {
        CV_TRACE("  CSR 复合签名长度无效");
        goto end;
    }
    sm2_sig_len = (size_t)ASN1_STRING_length(sig) - CERT_VERIFY_MLDSA44_SIG_LEN;
    CV_TRACE("  ML-DSA 段 %d 字节 + SM2 段 %zu 字节，CRI %d 字节",
             CERT_VERIFY_MLDSA44_SIG_LEN, sm2_sig_len, crilen);
    ok = mldsa44_with_sm3_verify(libctx, mldsa_pub, cri, (size_t)crilen,
                                 ASN1_STRING_get0_data(sig),
                                 CERT_VERIFY_MLDSA44_SIG_LEN);
    CV_TRACE("  ML-DSA-44-with-SM3(完整 CRI) -> %s", ok ? "OK" : "FAIL");
    if (!ok)
        goto end;
    ok = sm2_with_sm3_verify_ec(libctx, sm2_pub, cri, (size_t)crilen,
                                ASN1_STRING_get0_data(sig)
                                    + CERT_VERIFY_MLDSA44_SIG_LEN,
                                sm2_sig_len);
    sm2_pub = NULL;
    CV_TRACE("  SM2-with-SM3(完整 CRI) -> %s", ok ? "OK" : "FAIL");

end:
    EVP_PKEY_free(mldsa_pub);
    EC_KEY_free(sm2_pub);
    OPENSSL_free(cri);
    return ok;
}

static void name_oneline(X509_NAME *nm, char *buf, size_t bufsz)
{
    if (nm == NULL)
        snprintf(buf, bufsz, "(null)");
    else
        X509_NAME_oneline(nm, buf, (int)bufsz);
}

int cert_verify_one(X509 *cert, X509 *issuer, CERT_VERIFY_RESULT *res,
                    OSSL_LIB_CTX *libctx)
{
    int hybrid;

    memset(res, 0, sizeof(*res));
    name_oneline(X509_get_subject_name(cert), res->subject, sizeof(res->subject));
    name_oneline(X509_get_issuer_name(cert), res->issuer, sizeof(res->issuer));

    hybrid = has_hybrid_ext(cert);
    CV_TRACE("======== cert_verify_one ========");
    CV_TRACE("  主体: %s", res->subject);
    CV_TRACE("  签发者: %s", res->issuer);
    CV_TRACE("  has_hybrid_ext() -> %d (扩展 %s)", hybrid, CERT_VERIFY_OID_EXT_PQC_PUB);

    if (cert_verify_is_mldsa44_sm2(cert)) {
        CV_TRACE("  ML-DSA-44-SM2 复合模式 (certs/2)");
        res->mldsa_full_tbs = cert_verify_mldsa44_sm2_composite(cert, issuer, libctx);
        res->ok = res->mldsa_full_tbs;
        if (!res->ok)
            snprintf(res->err, sizeof(res->err),
                     "ML-DSA-44-SM2-with-SM3(506.1) 验签未通过："
                     "请核对 SM3(完整 TBS) 与外层 ML-DSA(2420)+SM2 签名");
        return res->ok;
    }

    if (hybrid) {
        CV_TRACE("  混合模式: 先 ML-DSA 再 SM2");
        res->mldsa_tbs_pqc = cert_verify_mldsa_hybrid(cert, issuer, libctx);
        res->sm2_full_tbs = cert_verify_sm2_outer(cert, issuer, libctx);
        res->ok = res->mldsa_tbs_pqc && res->sm2_full_tbs;
        if (!res->mldsa_tbs_pqc)
            snprintf(res->err, sizeof(res->err),
                     "ML-DSA-44-with-SM3(505.1) 验签未通过："
                     "请核对待验消息是否为完整TBS去掉4.1.7/4.1.8(含4.1.6)，"
                     "签名是否在扩展 4.1.8");
        else if (!res->sm2_full_tbs)
            snprintf(res->err, sizeof(res->err),
                     "SM2-with-SM3(501) 外层验签未通过："
                     "请核对 SM3(完整 TBS) 与证书外层签名");
        CV_TRACE("  结果: ML-DSA=%s SM2=%s 总=%s",
                 res->mldsa_tbs_pqc ? "OK" : "FAIL",
                 res->sm2_full_tbs ? "OK" : "FAIL", res->ok ? "OK" : "FAIL");
        return res->ok;
    }

    CV_TRACE("  纯 PQC SPKI 模式 (certs/1)");
    res->mldsa_tbs_pqc = cert_verify_mldsa_tbs_plus_pqc(cert, issuer, libctx);
    res->mldsa_full_tbs = cert_verify_mldsa_full_tbs_standard(cert, issuer, libctx);
    res->sm2_full_tbs = cert_verify_sm2_full_tbs(cert, issuer, libctx);
    res->ok = res->mldsa_full_tbs;
    if (!res->mldsa_tbs_pqc && res->mldsa_full_tbs)
        snprintf(res->err, sizeof(res->err),
                 "提示：TBS_orig||主体裸公钥 未通过；"
                 "纯 PQC 证以 ML-DSA-44-with-SM3 对完整 TBS 验签为准（已通过）");
    else if (!res->ok)
        snprintf(res->err, sizeof(res->err),
                 "ML-DSA-44-with-SM3(505.1) 验签未通过："
                 "请核对 SM3(完整 TBS) 与证书外层 ML-DSA 签名");
    return res->ok;
}

static X509 *read_pem_cert(const char *path)
{
    BIO *bio = BIO_new_file(path, "r");
    X509 *x = NULL;

    CV_TRACE_FN("PEM_read %s", path);
    if (bio == NULL)
        return NULL;
    x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    CV_TRACE_FN("  -> X509* %p", (void *)x);
    return x;
}

int cert_verify_chain_dir(const char *dir, CERT_VERIFY_RESULT *results,
                          int *nresults, OSSL_LIB_CTX *libctx)
{
    char path[1024];
    X509 *root = NULL, *yunying = NULL, *user_sig = NULL, *user_enc = NULL;
    int n = 0;
    int rc = 0;

    CV_TRACE_FN("enter dir=%s libctx=%p", dir, (void *)libctx);
    snprintf(path, sizeof(path), "%s/root.crt", dir);
    root = read_pem_cert(path);
    snprintf(path, sizeof(path), "%s/yunying.crt", dir);
    yunying = read_pem_cert(path);
    snprintf(path, sizeof(path), "%s/user_sig.crt", dir);
    user_sig = read_pem_cert(path);
    snprintf(path, sizeof(path), "%s/user_enc.crt", dir);
    user_enc = read_pem_cert(path);

    if (root == NULL || yunying == NULL || user_sig == NULL || user_enc == NULL) {
        if (results != NULL && nresults != NULL)
            snprintf(results[0].err, sizeof(results[0].err), "读取证书失败");
        goto end;
    }

    CV_TRACE("######## cert_verify_chain_dir: %s ########", dir);
    CV_TRACE(">>> cert_verify_one(root, root)");
    cert_verify_one(root, root, &results[n], libctx);
    n++;
    CV_TRACE(">>> cert_verify_one(yunying, root)");
    cert_verify_one(yunying, root, &results[n], libctx);
    n++;
    CV_TRACE(">>> cert_verify_one(user_sig, yunying)");
    cert_verify_one(user_sig, yunying, &results[n], libctx);
    n++;
    CV_TRACE(">>> cert_verify_one(user_enc, yunying)");
    cert_verify_one(user_enc, yunying, &results[n], libctx);
    n++;

    *nresults = n;
    rc = 1;
    for (int i = 0; i < n; i++)
        rc = rc && results[i].ok;

end:
    X509_free(root);
    X509_free(yunying);
    X509_free(user_sig);
    X509_free(user_enc);
    return rc;
}
