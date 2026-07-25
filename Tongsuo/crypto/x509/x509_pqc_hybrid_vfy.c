/*
 * openssl verify 与 x509-hybrid-verify-provider 衔接：
 *   - certs/3 混合证（扩展 4.1.6）：标准 SM2 外层通过后 cert_verify_mldsa_hybrid；
 *   - certs/2 复合证（ML-DSA-44-SM2-with-SM3）：跳过标准验签，cert_verify_mldsa44_sm2_composite；
 *   - 其它证：不改变原有 X509 验签路径。
 *
 * 进度输出（默认开启，写入 stdout，与 "xxx.crt: OK" 同屏显示）：
 *   CERT_VERIFY_VERIFY_INFO=0  关闭简要进度
 *   CERT_VERIFY_TRACE=1        同时打开 x509-hybrid-verify-provider 逐步日志
 */

#ifndef _WIN32
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>

#include "internal/cryptlib.h"
#include "internal/x509_pqc_hybrid.h"
#include "crypto/x509.h"
#include "x509_pqc_dso.h"

#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#ifdef _WIN32
# ifndef TLCP_PQC_ROOT
#  define TLCP_PQC_ROOT "D:\\20240429certificate-verification\\tlcp-pqc"
# endif
# ifndef DEFAULT_PQMAGIC_PROVIDER
#  define DEFAULT_PQMAGIC_PROVIDER TLCP_PQC_ROOT "\\providers\\pqmagic.dll"
# endif
# ifndef DEFAULT_ML_DSA_SM2_PROVIDER
#  define DEFAULT_ML_DSA_SM2_PROVIDER \
    TLCP_PQC_ROOT "\\providers\\libml_dsa_sm2_provider.dll"
# endif
# ifndef DEFAULT_PQMAGIC_STD_LIB
#  define DEFAULT_PQMAGIC_STD_LIB TLCP_PQC_ROOT "\\lib\\libpqmagic_std.dll"
# endif
# ifndef DEFAULT_CERT_VERIFY_SO
#  define DEFAULT_CERT_VERIFY_SO TLCP_PQC_ROOT "\\providers\\cert_verify.dll"
# endif
#else
# ifndef DEFAULT_PQMAGIC_PROVIDER
#  define DEFAULT_PQMAGIC_PROVIDER \
    "/home/wang/Desktop/pqmagic-algorithms-provider/build/pqmagic.so"
# endif
# ifndef DEFAULT_ML_DSA_SM2_PROVIDER
#  define DEFAULT_ML_DSA_SM2_PROVIDER \
    "/home/wang/Desktop/x509-hybrid-spki-provider/libml_dsa_sm2_provider.so"
# endif
# ifndef DEFAULT_PQMAGIC_STD_LIB
#  define DEFAULT_PQMAGIC_STD_LIB \
    "/home/wang/Desktop/pqmagic/install/lib/libpqmagic_std.so"
# endif
# ifndef DEFAULT_CERT_VERIFY_SO
#  define DEFAULT_CERT_VERIFY_SO \
    "/home/wang/Desktop/x509-hybrid-verify-provider/cert_verify.so"
# endif
#endif

typedef int (*pqmagic_mlkem512_keypair_fn)(unsigned char *pk, unsigned char *sk);
static pqmagic_mlkem512_keypair_fn pqmagic_mlkem512_keypair_ptr;
static void *pqmagic_std_dso;
static int pqmagic_mlkem512_keypair_tried;

static pqmagic_mlkem512_keypair_fn ossl_x509_pqmagic_mlkem512_keypair(void)
{
    if (pqmagic_mlkem512_keypair_tried)
        return pqmagic_mlkem512_keypair_ptr;
    pqmagic_mlkem512_keypair_tried = 1;

    pqmagic_mlkem512_keypair_ptr =
        (pqmagic_mlkem512_keypair_fn)x509_pqc_dso_default_sym(
            "pqmagic_ml_kem_512_std_keypair");
    if (pqmagic_mlkem512_keypair_ptr != NULL)
        return pqmagic_mlkem512_keypair_ptr;

    {
        const char *libpath = getenv("PQMAGIC_STD_LIB");

        if (libpath == NULL || libpath[0] == '\0')
            libpath = DEFAULT_PQMAGIC_STD_LIB;
        pqmagic_std_dso = x509_pqc_dso_load(libpath);
        if (pqmagic_std_dso != NULL) {
            pqmagic_mlkem512_keypair_ptr =
                (pqmagic_mlkem512_keypair_fn)x509_pqc_dso_sym(
                    pqmagic_std_dso, "pqmagic_ml_kem_512_std_keypair");
        }
    }
    return pqmagic_mlkem512_keypair_ptr;
}

#define CV_OID_EXT_PQC_PUB  "1.2.156.10260.4.1.6"

typedef int (*cv_providers_load_fn)(OSSL_LIB_CTX *libctx);
typedef int (*cv_mldsa_hybrid_fn)(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx);
typedef int (*cv_mldsa44_sm2_fn)(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx);
typedef int (*cv_req_mldsa44_sm2_fn)(X509_REQ *req, OSSL_LIB_CTX *libctx);
typedef void (*cv_set_trace_fn)(int enable);

static ASN1_OBJECT *obj_pqc_pub;
static int pqc_oids_inited;

static void *cv_dso;
static cv_providers_load_fn cv_providers_load;
static cv_mldsa_hybrid_fn cv_mldsa_hybrid;
static cv_mldsa44_sm2_fn cv_mldsa44_sm2;
static cv_req_mldsa44_sm2_fn cv_req_mldsa44_sm2;
static cv_set_trace_fn cv_set_trace;
static int cv_bind_attempted;
static int cv_bind_ok;

static OSSL_PROVIDER *pqc_prov_default;
static OSSL_PROVIDER *pqc_prov_pqmagic;
static OSSL_PROVIDER *pqc_prov_mldsa_sm2;
static OSSL_LIB_CTX *pqc_prov_loaded_libctx;
static int pqc_builtin_providers_done;

static OSSL_PROVIDER *pqc_load_provider_path(OSSL_LIB_CTX *libctx,
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

int ossl_x509_ensure_pqc_providers(OSSL_LIB_CTX *libctx)
{
    const char *pqmagic_path, *mldsa_path;

    /*
     * provider 按 libctx 加载；首次在 NULL（默认 ctx）加载后，
     * apps 的独立 libctx 仍须单独加载 pqmagic / ml_dsa_sm2。
     */
    if (pqc_builtin_providers_done && pqc_prov_loaded_libctx == libctx)
        return pqc_prov_default != NULL;

    /* NULL 表示默认 OSSL_LIB_CTX */

    pqmagic_path = getenv("PQMAGIC_PROVIDER");
    if (pqmagic_path == NULL || pqmagic_path[0] == '\0')
        pqmagic_path = DEFAULT_PQMAGIC_PROVIDER;
    mldsa_path = getenv("X509_HYBRID_SPKI_PROVIDER");
    if (mldsa_path == NULL || mldsa_path[0] == '\0')
        mldsa_path = getenv("ML_DSA_SM2_PROVIDER");
    if (mldsa_path == NULL || mldsa_path[0] == '\0')
        mldsa_path = DEFAULT_ML_DSA_SM2_PROVIDER;

    pqc_prov_default = OSSL_PROVIDER_load(libctx, "default");
    pqc_prov_pqmagic = pqc_load_provider_path(libctx, "pqmagic", pqmagic_path);
    pqc_prov_mldsa_sm2 = pqc_load_provider_path(libctx, "ml_dsa_sm2", mldsa_path);

    if (pqc_prov_default == NULL)
        return 0;
    /*
     * pqmagic：裸 ML-DSA-44-SPKI / ML-KEM-512-SPKI（certs/1）解码与验签；
     * ml_dsa_sm2：ML-DSA-44-SM2 / ML-KEM-512-SM2 复合 SPKI（certs/2）解析。
     */
    pqc_prov_loaded_libctx = libctx;
    pqc_builtin_providers_done = 1;
    return 1;
}

static int pqc_info_enabled(void)
{
    const char *e = getenv("CERT_VERIFY_VERIFY_INFO");

    if (e == NULL || e[0] == '\0')
        return 1;
    return strcmp(e, "0") != 0 && OPENSSL_strcasecmp(e, "false") != 0;
}

static int pqc_trace_enabled(void)
{
    const char *e = getenv("CERT_VERIFY_TRACE");

    if (e == NULL || e[0] == '\0')
        return 0;
    return strcmp(e, "0") != 0 && OPENSSL_strcasecmp(e, "false") != 0;
}

static FILE *pqc_info_stream(void)
{
    /* 与 openssl verify 的 "xxx.crt: OK" 同用 stdout，避免 stderr 在终端里被折叠看不见 */
    return stdout;
}

static void pqc_info_flush(void)
{
    fflush(pqc_info_stream());
}

static void pqc_print_subject_line(const char *prefix, const X509 *cert)
{
    char *subj;
    FILE *out = pqc_info_stream();

    if (!pqc_info_enabled() || cert == NULL)
        return;
    subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (subj != NULL) {
        fprintf(out, "%s%s\n", prefix, subj);
        OPENSSL_free(subj);
        pqc_info_flush();
    }
}

static void pqc_print_req_subject_line(const char *prefix, const X509_REQ *req)
{
    char *subj;
    FILE *out = pqc_info_stream();

    if (!pqc_info_enabled() || req == NULL)
        return;
    subj = X509_NAME_oneline(X509_REQ_get_subject_name(req), NULL, 0);
    if (subj != NULL) {
        fprintf(out, "%s%s\n", prefix, subj);
        OPENSSL_free(subj);
        pqc_info_flush();
    }
}

static void pqc_init_oids(void)
{
    if (pqc_oids_inited)
        return;
    obj_pqc_pub = OBJ_txt2obj(CV_OID_EXT_PQC_PUB, 1);
    pqc_oids_inited = 1;
}

int ossl_x509_is_hybrid_sm2_pqc_cert(const X509 *cert)
{
    pqc_init_oids();
    if (cert == NULL || obj_pqc_pub == NULL)
        return 0;
    if (!ossl_x509v3_cache_extensions((X509 *)cert))
        return 0;
    return X509_get_ext_by_OBJ(cert, obj_pqc_pub, -1) >= 0;
}

static int pqc_try_load_cert_verify_so(const char *path)
{
    void *h;

    if (path == NULL || path[0] == '\0')
        return 0;
    h = x509_pqc_dso_load(path);
    if (h == NULL) {
        if (pqc_info_enabled()) {
            fprintf(pqc_info_stream(),
                    "  [混合证] 无法加载 %s: %s\n",
                    X509_PQC_CERT_VERIFY_MOD, x509_pqc_dso_error());
            pqc_info_flush();
        }
        return 0;
    }

    cv_providers_load =
        (cv_providers_load_fn)x509_pqc_dso_sym(h, "cert_verify_providers_load");
    cv_mldsa_hybrid =
        (cv_mldsa_hybrid_fn)x509_pqc_dso_sym(h, "cert_verify_mldsa_hybrid");
    cv_mldsa44_sm2 =
        (cv_mldsa44_sm2_fn)x509_pqc_dso_sym(h, "cert_verify_mldsa44_sm2_composite");
    cv_req_mldsa44_sm2 =
        (cv_req_mldsa44_sm2_fn)x509_pqc_dso_sym(h,
                                                "cert_verify_req_mldsa44_sm2_composite");
    cv_set_trace = (cv_set_trace_fn)x509_pqc_dso_sym(h, "cert_verify_set_trace");
    if (cv_providers_load == NULL || cv_mldsa_hybrid == NULL
        || cv_mldsa44_sm2 == NULL || cv_req_mldsa44_sm2 == NULL) {
        if (pqc_info_enabled()) {
            fprintf(pqc_info_stream(),
                    "  [cert_verify] %s 缺少必要符号"
                    " (providers_load / mldsa_hybrid / mldsa44_sm2 / req_mldsa44_sm2)\n",
                    X509_PQC_CERT_VERIFY_MOD);
            pqc_info_flush();
        }
        x509_pqc_dso_unload(h);
        return 0;
    }
    cv_dso = h;
    return 1;
}

static int pqc_bind_cert_verify(void)
{
    const char *so_path, *dir;
    char path[1024];

    if (cv_bind_attempted)
        return cv_bind_ok;
    cv_bind_attempted = 1;

    so_path = getenv("CERT_VERIFY_SO");
    if (so_path == NULL || so_path[0] == '\0')
        so_path = getenv("X509_HYBRID_VERIFY_SO");
    if (so_path != NULL && so_path[0] != '\0') {
        cv_bind_ok = pqc_try_load_cert_verify_so(so_path);
        return cv_bind_ok;
    }

    dir = getenv("CERT_VERIFY_PROVIDER_PATH");
    if (dir != NULL && dir[0] != '\0') {
        if (x509_pqc_path_is_module(dir)) {
            cv_bind_ok = pqc_try_load_cert_verify_so(dir);
        } else {
#ifdef _WIN32
            if (snprintf(path, sizeof(path), "%s\\%s", dir,
                         X509_PQC_CERT_VERIFY_MOD) < (int)sizeof(path))
#else
            if (snprintf(path, sizeof(path), "%s/%s", dir,
                         X509_PQC_CERT_VERIFY_MOD) < (int)sizeof(path))
#endif
                cv_bind_ok = pqc_try_load_cert_verify_so(path);
        }
        if (cv_bind_ok)
            return 1;
    }

    cv_bind_ok = pqc_try_load_cert_verify_so(DEFAULT_CERT_VERIFY_SO);
    return cv_bind_ok;
}

static int pqc_ensure_providers(OSSL_LIB_CTX *libctx)
{
    static int providers_ready;

    if (!ossl_x509_ensure_pqc_providers(libctx))
        return 0;
    if (!pqc_bind_cert_verify())
        return 0;
    if (cv_set_trace != NULL && pqc_trace_enabled())
        cv_set_trace(1);
    if (!providers_ready) {
        if (!cv_providers_load(libctx))
            return 0;
        providers_ready = 1;
        if (pqc_info_enabled()) {
            fprintf(pqc_info_stream(),
                    "  [provider] default + pqmagic + ml_dsa_sm2 已加载\n");
            pqc_info_flush();
        }
    }
    return 1;
}

int ossl_x509_verify_mldsa44_sm2_composite(const X509 *cert, const X509 *issuer,
                                           OSSL_LIB_CTX *libctx)
{
    int ok;

    if (cert == NULL || issuer == NULL)
        return 0;
    if (!ossl_x509_is_mldsa44_sm2_cert(cert))
        return 0;

    if (pqc_info_enabled()) {
        FILE *out = pqc_info_stream();
        fprintf(out, "\n[openssl-verify ML-DSA-44-SM2 复合证 双重验签]\n");
        pqc_print_subject_line("  证书主体: ", cert);
        fprintf(out,
                "  [1/2] ML-DSA-44-with-SM3(完整 TBS，签名前 %d 字节): 验签中 ...\n",
                OSSL_PQC_MLDSA44_SIG_LEN);
        pqc_info_flush();
    }

    if (!pqc_ensure_providers(libctx)) {
        if (pqc_info_enabled()) {
            fprintf(pqc_info_stream(),
                    "  [1/2] ML-DSA: FAIL — 未加载 cert_verify.so 或 provider\n");
            pqc_info_flush();
        }
        return 0;
    }

    ok = cv_mldsa44_sm2((X509 *)cert, (X509 *)issuer, libctx) ? 1 : 0;

    if (pqc_info_enabled()) {
        FILE *out = pqc_info_stream();
        if (ok) {
            fprintf(out, "  [1/2] ML-DSA-44-with-SM3: OK\n");
            fprintf(out, "  [2/2] SM2-with-SM3(完整 TBS，签名余下段): OK\n");
            fprintf(out,
                    "  => 双重验签完成: ML-DSA + SM2 均已通过\n\n");
        } else {
            fprintf(out, "  [1/2] ML-DSA-44-with-SM3 或 [2/2] SM2: FAIL\n");
            fprintf(out, "  => 复合验签未完成\n\n");
        }
        pqc_info_flush();
    }
    return ok;
}

int ossl_x509_verify_req_mldsa44_sm2_composite(const X509_REQ *req,
                                               OSSL_LIB_CTX *libctx)
{
    int ok;

    if (req == NULL)
        return 0;
    if (!ossl_x509_is_mldsa44_sm2_req(req))
        return 0;

    if (pqc_info_enabled()) {
        FILE *out = pqc_info_stream();
        fprintf(out, "\n[openssl-req-verify ML-DSA-44-SM2 复合 CSR 双重验签]\n");
        pqc_print_req_subject_line("  CSR 主体: ", req);
        fprintf(out,
                "  [1/2] ML-DSA-44-with-SM3(完整 CRI，签名前 %d 字节): 验签中 ...\n",
                OSSL_PQC_MLDSA44_SIG_LEN);
        pqc_info_flush();
    }

    if (!pqc_ensure_providers(libctx)) {
        if (pqc_info_enabled()) {
            fprintf(pqc_info_stream(),
                    "  [1/2] ML-DSA: FAIL — 未加载 cert_verify 或 provider\n");
            pqc_info_flush();
        }
        return 0;
    }

    ok = cv_req_mldsa44_sm2((X509_REQ *)req, libctx) ? 1 : 0;

    if (pqc_info_enabled()) {
        FILE *out = pqc_info_stream();
        if (ok) {
            fprintf(out, "  [1/2] ML-DSA-44-with-SM3: OK\n");
            fprintf(out, "  [2/2] SM2-with-SM3(完整 CRI，签名余下段): OK\n");
            fprintf(out,
                    "  => 双重验签完成: ML-DSA + SM2 均已通过\n\n");
        } else {
            fprintf(out, "  [1/2] ML-DSA-44-with-SM3 或 [2/2] SM2: FAIL\n");
            fprintf(out, "  => 复合 CSR 验签未完成\n\n");
        }
        pqc_info_flush();
    }
    return ok;
}

int ossl_x509_verify_pqc_hybrid(const X509 *cert, const X509 *issuer,
                                OSSL_LIB_CTX *libctx)
{
    int mldsa_ok;

    if (cert == NULL || issuer == NULL)
        return 0;

    pqc_init_oids();
    if (obj_pqc_pub == NULL)
        return 0;

    if (!ossl_x509v3_cache_extensions((X509 *)issuer))
        return 0;

    if (!ossl_x509_is_hybrid_sm2_pqc_cert(cert))
        return 1;

    if (pqc_info_enabled()) {
        FILE *out = pqc_info_stream();
        fprintf(out, "\n[openssl-verify 国密混合证 双重验签]\n");
        pqc_print_subject_line("  证书主体: ", cert);
        fprintf(out,
                "  [1/2] SM2-with-SM3 外层签名: OK"
                " (openssl 标准 X509_verify，完整 TBS 含 4.1.6/7/8)\n");
        fprintf(out,
                "  [2/2] ML-DSA-44-with-SM3 扩展 4.1.8: 验签中"
                " (x509-hybrid-verify-provider，TBS 去掉 4.1.7/8) ...\n");
        pqc_info_flush();
    }

    if (!pqc_ensure_providers(libctx)) {
        if (pqc_info_enabled()) {
            fprintf(pqc_info_stream(),
                    "  [2/2] ML-DSA: FAIL — 未加载 cert_verify.so 或 provider\n");
            pqc_info_flush();
        }
        return 0;
    }

    mldsa_ok = cv_mldsa_hybrid((X509 *)cert, (X509 *)issuer, libctx) ? 1 : 0;

    if (pqc_info_enabled()) {
        FILE *out = pqc_info_stream();
        if (mldsa_ok) {
            fprintf(out, "  [2/2] ML-DSA-44-with-SM3 扩展 4.1.8: OK\n");
            fprintf(out,
                    "  => 双重验签完成: 外层 SM2 + 内层 ML-DSA 均已通过\n\n");
        } else {
            fprintf(out, "  [2/2] ML-DSA-44-with-SM3 扩展 4.1.8: FAIL\n");
            fprintf(out,
                    "  => 双重验签未完成 (外层 SM2 已通过，内层 ML-DSA 失败)\n\n");
        }
        pqc_info_flush();
    }

    return mldsa_ok;
}

#ifndef OPENSSL_NO_NTLS

# include <openssl/evp.h>
# include <openssl/ec.h>
# include <openssl/bn.h>
# include <openssl/decoder.h>
# include <openssl/pem.h>
# include <openssl/core_names.h>
# include <openssl/params.h>
# include <openssl/buffer.h>
# include "internal/nelem.h"
# include <limits.h>

static int hybrid_x509_pubkey_raw(const X509 *x, const unsigned char **pk,
                                  int *pklen, int *nid_out)
{
    X509_PUBKEY *xp;
    X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *oid = NULL;

    if (x == NULL || pk == NULL || pklen == NULL || nid_out == NULL)
        return 0;
    xp = X509_get_X509_PUBKEY(x);
    if (xp == NULL)
        return 0;
    if (!X509_PUBKEY_get0_param(NULL, pk, pklen, &alg, xp))
        return 0;
    X509_ALGOR_get0(&oid, NULL, NULL, alg);
    *nid_out = OBJ_obj2nid(oid);
    return 1;
}

static EVP_PKEY *hybrid_pqc_fromdata(OSSL_LIB_CTX *libctx, const char *propq,
                                     const char *keytype,
                                     const unsigned char *pub, size_t publen,
                                     const unsigned char *priv, size_t privlen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    int selection = 0;
    int n = 0;

    if (!ossl_x509_ensure_pqc_providers(libctx))
        return NULL;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, keytype, propq);
    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto err;

    if (pub != NULL && publen > 0) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, (void *)pub, publen);
        selection |= EVP_PKEY_PUBLIC_KEY;
    }
    if (priv != NULL && privlen > 0) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, (void *)priv, privlen);
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    }
    if ((selection & EVP_PKEY_PUBLIC_KEY) != 0
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        selection = EVP_PKEY_KEYPAIR;
    params[n] = OSSL_PARAM_construct_end();

    if (selection == 0 || EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0)
        goto err;

err:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *hybrid_sm2_pubkey_from_bytes(const unsigned char *sm2_pub,
                                              size_t sm2_len)
{
    EC_GROUP *group = NULL;
    EC_KEY *ec_key = NULL;
    EC_POINT *pub_point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BN_CTX *bn_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    const unsigned char *p = sm2_pub;

    if (sm2_pub == NULL || sm2_len < 64)
        return NULL;
    if (sm2_len >= 65 && p[0] == 0x04)
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
    ec_key = EC_KEY_new();
    pub_point = EC_POINT_new(group);
    if (group == NULL || ec_key == NULL || pub_point == NULL)
        goto err;
    if (EC_KEY_set_group(ec_key, group) == 0)
        goto err;
    if (BN_bin2bn(p, 32, x) == NULL || BN_bin2bn(p + 32, 32, y) == NULL)
        goto err;
    if (EC_POINT_set_affine_coordinates(group, pub_point, x, y, bn_ctx) == 0)
        goto err;
    if (EC_KEY_set_public_key(ec_key, pub_point) == 0)
        goto err;

    pkey = EVP_PKEY_new();
    if (pkey == NULL || EVP_PKEY_set_type(pkey, EVP_PKEY_SM2) == 0
            || EVP_PKEY_assign_EC_KEY(pkey, ec_key) == 0) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        pkey = NULL;
        goto err;
    }
    ec_key = NULL;

err:
    EC_KEY_free(ec_key);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return pkey;
}

int ossl_x509_hybrid_security_bits(const EVP_PKEY *pkey)
{
    if (ossl_x509_hybrid_is_composite_pkey(pkey))
        return 128;
    return -1;
}

int ossl_x509_hybrid_security_sigbits(const X509 *x)
{
    if (x == NULL)
        return -1;
    if (ossl_x509_is_mldsa44_sm2_cert(x))
        return 128;
    return -1;
}

#define PQC_OID_MLKEM512_SPKI  "1.2.156.10197.1.303.1"
#define PQC_OID_MLDSA44_SPKI   "1.2.156.10197.1.304.1"

static const unsigned char *pqc_ext_octet_data(const X509 *cert, int *out_len)
{
    int idx;
    X509_EXTENSION *ex;
    ASN1_OCTET_STRING *os;

    pqc_init_oids();
    if (cert == NULL || obj_pqc_pub == NULL || out_len == NULL)
        return NULL;
    if (!ossl_x509v3_cache_extensions((X509 *)cert))
        return NULL;
    idx = X509_get_ext_by_OBJ(cert, obj_pqc_pub, -1);
    if (idx < 0)
        return NULL;
    ex = X509_get_ext(cert, idx);
    os = ex != NULL ? X509_EXTENSION_get_data(ex) : NULL;
    if (os == NULL)
        return NULL;
    *out_len = ASN1_STRING_length(os);
    return ASN1_STRING_get0_data(os);
}

static int pqc_parse_pubkey_ext(const unsigned char *der, int der_len,
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

static EVP_PKEY *pqc_pubkey_from_hybrid_ext(OSSL_LIB_CTX *libctx,
                                            const char *propq,
                                            const X509 *x)
{
    const unsigned char *der;
    int der_len = 0;
    char alg_oid[64];
    unsigned char pk_buf[OSSL_PQC_MLDSA44_PK_LEN];
    size_t pk_len = 0;
    const char *keytype = NULL;

    if (!ossl_x509_is_hybrid_sm2_pqc_cert(x))
        return NULL;

    der = pqc_ext_octet_data(x, &der_len);
    if (der == NULL || der_len <= 0)
        return NULL;
    if (!pqc_parse_pubkey_ext(der, der_len, alg_oid, sizeof(alg_oid),
                              pk_buf, sizeof(pk_buf), &pk_len))
        return NULL;

    if (strcmp(alg_oid, PQC_OID_MLKEM512_SPKI) == 0
            || pk_len == OSSL_PQC_MLKEM512_PK_LEN)
        keytype = "ML-KEM-512-SPKI";
    else if (strcmp(alg_oid, PQC_OID_MLDSA44_SPKI) == 0
             || pk_len == OSSL_PQC_MLDSA44_PK_LEN)
        keytype = "ML-DSA-44-SPKI";
    else
        return NULL;

    return hybrid_pqc_fromdata(libctx, propq, keytype, pk_buf, pk_len, NULL, 0);
}

int ossl_x509_hybrid_split_from_x509(OSSL_LIB_CTX *libctx, const char *propq,
                                     const X509 *x,
                                     EVP_PKEY **pqc_out, EVP_PKEY **sm2_out)
{
    const unsigned char *pk = NULL;
    int pklen = 0, nid = NID_undef;
    const unsigned char *pqc_bytes = NULL;
    size_t pqc_len = 0;
    const unsigned char *sm2_bytes = NULL;
    EVP_PKEY *pqc = NULL;
    EVP_PKEY *sm2 = NULL;

    if (x == NULL)
        return 0;
    if (!hybrid_x509_pubkey_raw(x, &pk, &pklen, &nid))
        return 0;

    if (ossl_x509_hybrid_is_mldsa44_sm2(nid)) {
        if (pklen < OSSL_PQC_MLDSA44_PK_LEN + OSSL_PQC_SM2_HYBRID_PK_LEN)
            return 0;
        pqc_bytes = pk;
        pqc_len = OSSL_PQC_MLDSA44_PK_LEN;
        sm2_bytes = pk + OSSL_PQC_MLDSA44_PK_LEN;
    } else if (ossl_x509_hybrid_is_mlkem512_sm2(nid)) {
        if (pklen < OSSL_PQC_MLKEM512_PK_LEN + OSSL_PQC_SM2_HYBRID_PK_LEN)
            return 0;
        pqc_bytes = pk;
        pqc_len = OSSL_PQC_MLKEM512_PK_LEN;
        sm2_bytes = pk + OSSL_PQC_MLKEM512_PK_LEN;
    } else {
        return 0;
    }

    if (pqc_out != NULL) {
        const char *pqc_type = ossl_x509_hybrid_is_mldsa44_sm2(nid)
                               ? "ML-DSA-44-SPKI" : "ML-KEM-512-SPKI";

        pqc = hybrid_pqc_fromdata(libctx, propq, pqc_type,
                                  pqc_bytes, pqc_len, NULL, 0);
        if (pqc == NULL)
            goto err;
        *pqc_out = pqc;
        pqc = NULL;
    }

    if (sm2_out != NULL) {
        sm2 = hybrid_sm2_pubkey_from_bytes(sm2_bytes, OSSL_PQC_SM2_HYBRID_PK_LEN);
        if (sm2 == NULL)
            goto err;
        *sm2_out = sm2;
        sm2 = NULL;
    }
    return 1;

err:
    if (pqc_out != NULL) {
        EVP_PKEY_free(*pqc_out);
        *pqc_out = NULL;
    }
    if (sm2_out != NULL) {
        EVP_PKEY_free(*sm2_out);
        *sm2_out = NULL;
    }
    return 0;
}

int ossl_x509_hybrid_ntls_enc_static_mlkem(const X509 *enc)
{
    const EVP_PKEY *pub;
    EVP_PKEY *pqc = NULL;
    int ret = 0;

    if (enc == NULL)
        return 0;
    pub = X509_get0_pubkey(enc);
    if (pub != NULL && ossl_x509_hybrid_is_composite_pkey(pub))
        return ossl_x509_hybrid_is_mlkem512_sm2(EVP_PKEY_get_id(pub));
    if (!ossl_x509_is_hybrid_sm2_pqc_cert(enc))
        return 0;
    pqc = ossl_x509_hybrid_ntls_pqc_pubkey(NULL, NULL, enc);
    if (pqc != NULL
            && (EVP_PKEY_is_a(pqc, "ML-KEM-512-SPKI")
                || EVP_PKEY_is_a(pqc, "id-ML-KEM-512-SPKI")))
        ret = 1;
    EVP_PKEY_free(pqc);
    return ret;
}

EVP_PKEY *ossl_x509_hybrid_ntls_sm2_pubkey(OSSL_LIB_CTX *libctx,
                                           const char *propq,
                                           const X509 *x)
{
    EVP_PKEY *sm2 = NULL;
    const EVP_PKEY *pub;

    if (x == NULL)
        return NULL;
    pub = X509_get0_pubkey(x);
    if (pub != NULL && ossl_x509_hybrid_is_composite_pkey(pub)) {
        if (!ossl_x509_hybrid_split_from_x509(libctx, propq, x, NULL, &sm2))
            return NULL;
        return sm2;
    }
    if (pub != NULL && EVP_PKEY_is_a(pub, "SM2")) {
        EVP_PKEY_up_ref((EVP_PKEY *)pub);
        return (EVP_PKEY *)pub;
    }
    return NULL;
}

int ossl_x509_hybrid_mlkem512_raw_pk(const EVP_PKEY *pkey,
                                     unsigned char *pk, size_t pklen)
{
    size_t len = pklen;

    if (pkey == NULL || pk == NULL || pklen < OSSL_PQC_MLKEM512_PK_LEN)
        return 0;
    if (EVP_PKEY_get_octet_string_param(pkey,
                                        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        pk, pklen, &len)
            && len == OSSL_PQC_MLKEM512_PK_LEN)
        return 1;
    len = pklen;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pk, pklen, &len))
        return len == OSSL_PQC_MLKEM512_PK_LEN;
    return 0;
}

int ossl_x509_hybrid_mlkem512_raw_sk(const EVP_PKEY *pkey,
                                     unsigned char *sk, size_t sklen)
{
    size_t len = sklen;

    if (pkey == NULL || sk == NULL || sklen < OSSL_PQC_MLKEM512_SK_LEN)
        return 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                         sk, sklen, &len))
        return 0;
    return len == OSSL_PQC_MLKEM512_SK_LEN;
}

EVP_PKEY *ossl_x509_hybrid_mlkem512_from_raw(OSSL_LIB_CTX *libctx,
                                               const char *propq,
                                               const unsigned char *pub,
                                               size_t publen,
                                               const unsigned char *priv,
                                               size_t privlen)
{
    static const char *names[] = {
        "ML-KEM-512-SPKI", "id-ML-KEM-512-SPKI"
    };
    size_t i;

    for (i = 0; i < OSSL_NELEM(names); i++) {
        EVP_PKEY *pkey = hybrid_pqc_fromdata(libctx, propq, names[i],
                                             pub, publen, priv, privlen);
        if (pkey != NULL)
            return pkey;
    }
    return NULL;
}

int ossl_x509_hybrid_mlkem512_keypair(OSSL_LIB_CTX *libctx, const char *propq,
                                      unsigned char *pk, size_t pklen,
                                      unsigned char *sk, size_t sklen)
{
    static const char *names[] = {
        "ML-KEM-512-SPKI", "id-ML-KEM-512-SPKI"
    };
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t i;
    int ok = 0;

    if (pk == NULL || sk == NULL
            || pklen < OSSL_PQC_MLKEM512_PK_LEN
            || sklen < OSSL_PQC_MLKEM512_SK_LEN)
        return 0;

    if (!ossl_x509_ensure_pqc_providers(libctx))
        return 0;

    for (i = 0; i < OSSL_NELEM(names); i++) {
        ctx = EVP_PKEY_CTX_new_from_name(libctx, names[i], propq);
        if (ctx == NULL)
            continue;
        if (EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &pkey) > 0)
            break;
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    if (pkey != NULL) {
        if (ossl_x509_hybrid_mlkem512_raw_pk(pkey, pk, pklen)
                && ossl_x509_hybrid_mlkem512_raw_sk(pkey, sk, sklen))
            ok = 1;
        goto end;
    }

    /*
     * pqmagic provider 仅实现 KEM encaps/decaps，不支持 EVP keygen。
     * 传统证随机 ML-KEM-512 路径改调 libpqmagic_std 直接 keypair。
     */
    {
        pqmagic_mlkem512_keypair_fn kp = ossl_x509_pqmagic_mlkem512_keypair();

        if (kp != NULL && kp(pk, sk) == 0)
            ok = 1;
    }

end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

EVP_PKEY *ossl_x509_hybrid_ntls_pqc_pubkey(OSSL_LIB_CTX *libctx,
                                           const char *propq,
                                           const X509 *x)
{
    EVP_PKEY *pqc = NULL;
    EVP_PKEY *sm2 = NULL;
    const EVP_PKEY *hybrid;
    int nid;

    if (x == NULL)
        return NULL;
    hybrid = X509_get0_pubkey(x);
    if (hybrid != NULL && ossl_x509_hybrid_is_composite_pkey(hybrid)) {
        if (!ossl_x509_hybrid_split_from_x509(libctx, propq, x, &pqc, &sm2))
            return NULL;
        EVP_PKEY_free(sm2);
        return pqc;
    }
    if (hybrid != NULL
        && (EVP_PKEY_is_a(hybrid, "ML-DSA-44-SPKI")
            || EVP_PKEY_is_a(hybrid, "id-ML-DSA-44-SPKI")
            || EVP_PKEY_is_a(hybrid, "ML-KEM-512-SPKI")
            || EVP_PKEY_is_a(hybrid, "id-ML-KEM-512-SPKI"))) {
        EVP_PKEY_up_ref((EVP_PKEY *)hybrid);
        return (EVP_PKEY *)hybrid;
    }
    if (hybrid_x509_pubkey_raw(x, NULL, NULL, &nid)
            && (nid == NID_ML_DSA_44_SPKI || nid == NID_ML_KEM_512_SPKI)) {
        if (!ossl_x509_hybrid_split_from_x509(libctx, propq, x, &pqc, NULL))
            return NULL;
        return pqc;
    }
    /* certs/3：PQC 公钥在扩展 4.1.6（加密证 ML-KEM-512，签名证 ML-DSA-44） */
    pqc = pqc_pubkey_from_hybrid_ext(libctx, propq, x);
    if (pqc != NULL)
        return pqc;
    return NULL;
}

int ossl_x509_hybrid_companion_sm2_key_path(const char *keyfile,
                                            char *out, size_t outlen)
{
    const char *dot;
    size_t prefix_len;

    if (keyfile == NULL || out == NULL || outlen == 0)
        return 0;
    dot = strrchr(keyfile, '.');
    if (dot == NULL || strcmp(dot, ".key") != 0)
        return 0;
    prefix_len = (size_t)(dot - keyfile);
    if (prefix_len + strlen("_sm2.key") + 1 > outlen)
        return 0;
    memcpy(out, keyfile, prefix_len);
    memcpy(out + prefix_len, "_sm2.key", strlen("_sm2.key") + 1);
    return 1;
}

static unsigned char *hybrid_decode_one_pem_block(const char *pem_text,
                                                  const char *begin_label,
                                                  long *outlen)
{
    char marker[80];
    const char *start, *end, *body;
    BIO *b64 = NULL, *chain = NULL;
    unsigned char *der = NULL;
    size_t cap = 0, got = 0;
    unsigned char buf[1024];
    int n;

    if (pem_text == NULL || begin_label == NULL || outlen == NULL)
        return NULL;
    BIO_snprintf(marker, sizeof(marker), "-----BEGIN %s-----", begin_label);
    start = strstr(pem_text, marker);
    if (start == NULL)
        return NULL;
    end = strstr(start, "-----END ");
    if (end == NULL)
        return NULL;
    body = strchr(start, '\n');
    if (body == NULL || body >= end)
        return NULL;
    body++;

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL)
        return NULL;
    chain = BIO_push(b64, BIO_new_mem_buf(body, (int)(end - body)));
    if (chain == NULL) {
        BIO_free(b64);
        return NULL;
    }

    cap = 4096;
    der = OPENSSL_malloc(cap);
    if (der == NULL)
        goto err;
    while ((n = BIO_read(chain, buf, sizeof(buf))) > 0) {
        if (got + (size_t)n > cap) {
            unsigned char *tmp;
            size_t newcap = cap * 2;

            while (got + (size_t)n > newcap)
                newcap *= 2;
            tmp = OPENSSL_realloc(der, newcap);
            if (tmp == NULL)
                goto err;
            der = tmp;
            cap = newcap;
        }
        memcpy(der + got, buf, (size_t)n);
        got += (size_t)n;
    }
    BIO_free_all(chain);
    *outlen = (long)got;
    return der;

err:
    BIO_free_all(chain);
    OPENSSL_free(der);
    return NULL;
}

static int hybrid_read_pq_key_material(BIO *in,
                                       unsigned char **sk_out, size_t *sklen,
                                       unsigned char **pk_out, size_t *pklen)
{
    BUF_MEM *bptr = NULL;
    BIO *mem = NULL;
    unsigned char *sk = NULL, *pk = NULL;
    long skl = 0, pkl = 0;
    unsigned char buf[4096];
    int n;

    if (in == NULL || sk_out == NULL || sklen == NULL)
        return 0;
    *sk_out = NULL;
    *sklen = 0;
    if (pk_out != NULL && pklen != NULL) {
        *pk_out = NULL;
        *pklen = 0;
    }

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL)
        return 0;
    for (;;) {
        n = BIO_read(in, buf, sizeof(buf));
        if (n <= 0)
            break;
        if (BIO_write(mem, buf, n) != n) {
            BIO_free(mem);
            return 0;
        }
    }
    (void)BIO_get_mem_ptr(mem, &bptr);
    if (bptr == NULL || bptr->data == NULL || bptr->length == 0) {
        BIO_free(mem);
        return 0;
    }

    sk = hybrid_decode_one_pem_block(bptr->data, "PRIVATE KEY", &skl);
    if (pk_out != NULL && pklen != NULL)
        pk = hybrid_decode_one_pem_block(bptr->data, "PUBLIC KEY", &pkl);
    BIO_free(mem);

    if (sk == NULL || skl <= 0) {
        OPENSSL_clear_free(sk, (size_t)skl);
        OPENSSL_clear_free(pk, (size_t)pkl);
        return 0;
    }
    *sk_out = sk;
    *sklen = (size_t)skl;
    if (pk_out != NULL && pklen != NULL && pk != NULL && pkl > 0) {
        *pk_out = pk;
        *pklen = (size_t)pkl;
    } else {
        OPENSSL_clear_free(pk, (size_t)pkl);
    }
    return 1;
}

static EVP_PKEY *hybrid_pqc_fromdata_try(OSSL_LIB_CTX *libctx, const char *propq,
                                         const char *const *names, size_t nnames,
                                         const unsigned char *pub, size_t publen,
                                         const unsigned char *priv, size_t privlen)
{
    size_t i;
    EVP_PKEY *pkey = NULL;

    for (i = 0; i < nnames; i++) {
        pkey = hybrid_pqc_fromdata(libctx, propq, names[i], pub, publen,
                                   priv, privlen);
        if (pkey != NULL)
            return pkey;
    }
    return NULL;
}

static int hybrid_guess_cert_path(const char *keyfile, char *out, size_t outsz)
{
    const char *slash;
    const char *dot;
    const char *stem;
    char stembuf[256];
    size_t stemlen;
    size_t dirlen = 0;

    if (keyfile == NULL || out == NULL || outsz < 5)
        return 0;

    slash = strrchr(keyfile, '/');
    if (slash == NULL)
        slash = strrchr(keyfile, '\\');
    dot = strrchr(keyfile, '.');
    if (dot == NULL || dot <= (slash != NULL ? slash + 1 : keyfile))
        return 0;

    stem = (slash != NULL) ? slash + 1 : keyfile;
    stemlen = (size_t)(dot - stem);
    if (stemlen >= sizeof(stembuf))
        return 0;
    memcpy(stembuf, stem, stemlen);
    stembuf[stemlen] = '\0';

    if (stemlen >= 7 && strcmp(stembuf + stemlen - 7, "_pkcs8") == 0)
        stembuf[stemlen - 7] = '\0';

    if (slash != NULL)
        dirlen = (size_t)(slash - keyfile) + 1;
    if (dirlen + strlen(stembuf) + 5 >= outsz)
        return 0;
    if (dirlen > 0) {
        memcpy(out, keyfile, dirlen);
        out[dirlen] = '\0';
        OPENSSL_strlcat(out, stembuf, outsz);
    } else {
        OPENSSL_strlcpy(out, stembuf, outsz);
    }
    OPENSSL_strlcat(out, ".crt", outsz);
    return 1;
}

static int hybrid_pkey_is_mldsa44(const EVP_PKEY *pkey)
{
    const char *name;

    if (pkey == NULL)
        return 0;
    name = EVP_PKEY_get0_type_name(pkey);
    return name != NULL
        && (strcmp(name, "ML-DSA-44-SPKI") == 0
            || strcmp(name, "id-ML-DSA-44-SPKI") == 0);
}

static int hybrid_pkey_has_mldsa44_public_key(const EVP_PKEY *pkey)
{
    size_t publen = 0;

    if (pkey == NULL)
        return 0;
    return EVP_PKEY_get_octet_string_param(pkey,
                                           OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                           NULL, 0, &publen) > 0
        && publen == OSSL_PQC_MLDSA44_PK_LEN;
}

/*
 * PKCS#8 仅含 ML-DSA 私钥时 provider 不携带公钥；从同名证书补全后
 * openssl req -new 才能通过 X509_PUBKEY_set 编码 SPKI。
 */
static EVP_PKEY *hybrid_supplement_mldsa_pubkey(EVP_PKEY *pkey,
                                                  const char *keyfile,
                                                  OSSL_LIB_CTX *libctx,
                                                  const char *propq)
{
    char certpath[1024];
    BIO *cbio = NULL;
    X509 *cert = NULL;
    EVP_PKEY *cert_pub = NULL;
    unsigned char priv[OSSL_PQC_MLDSA44_SK_LEN];
    unsigned char pub[OSSL_PQC_MLDSA44_PK_LEN];
    size_t privlen = sizeof(priv);
    size_t publen = sizeof(pub);
    EVP_PKEY *merged = NULL;

    if (pkey == NULL || keyfile == NULL
            || !hybrid_guess_cert_path(keyfile, certpath, sizeof(certpath)))
        return pkey;

    cbio = BIO_new(BIO_s_file());
    if (cbio == NULL || BIO_read_filename(cbio, certpath) <= 0)
        goto end;

    cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
    if (cert == NULL)
        goto end;

    cert_pub = X509_get_pubkey(cert);
    if (cert_pub == NULL)
        goto end;

    if (EVP_PKEY_get_octet_string_param(cert_pub,
                                        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        pub, sizeof(pub), &publen) <= 0
            || publen != OSSL_PQC_MLDSA44_PK_LEN)
        goto end;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                        priv, sizeof(priv), &privlen) <= 0
            || privlen != OSSL_PQC_MLDSA44_SK_LEN)
        goto end;

    merged = hybrid_pqc_fromdata(libctx, propq, "id-ML-DSA-44-SPKI",
                                 pub, publen, priv, privlen);
    if (merged != NULL) {
        EVP_PKEY_free(pkey);
        pkey = merged;
    }

end:
    EVP_PKEY_free(cert_pub);
    X509_free(cert);
    BIO_free(cbio);
    OPENSSL_cleanse(priv, sizeof(priv));
    return pkey;
}

EVP_PKEY *ossl_x509_hybrid_load_pq_private_key(OSSL_LIB_CTX *libctx,
                                               const char *propq,
                                               const char *file,
                                               pem_password_cb *cb,
                                               void *cbarg)
{
    static const char *mldsa_names[] = {
        "ML-DSA-44-SPKI", "id-ML-DSA-44-SPKI"
    };
    static const char *mlkem_names[] = {
        "ML-KEM-512-SPKI", "id-ML-KEM-512-SPKI"
    };
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *sk = NULL, *pk = NULL;
    size_t sklen = 0, pklen = 0;

    if (file == NULL)
        return NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL)
        return NULL;
    if (BIO_read_filename(in, file) <= 0)
        goto end;

    pkey = PEM_read_bio_PrivateKey_ex(in, NULL, cb, cbarg, libctx, propq);
    if (pkey != NULL) {
        if (hybrid_pkey_is_mldsa44(pkey)
                && !hybrid_pkey_has_mldsa44_public_key(pkey)) {
            unsigned char priv[OSSL_PQC_MLDSA44_SK_LEN];
            size_t privlen = sizeof(priv);
            EVP_PKEY *merged = NULL;

            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                                priv, sizeof(priv),
                                                &privlen) > 0
                    && privlen == OSSL_PQC_MLDSA44_SK_LEN) {
                ERR_clear_error();
                if (BIO_seek(in, 0) == 0) {
                    unsigned char *sk2 = NULL, *pk2 = NULL;
                    size_t sk2len = 0, pk2len = 0;

                    if (hybrid_read_pq_key_material(in, &sk2, &sk2len,
                                                    &pk2, &pk2len)
                            && pk2 != NULL
                            && pk2len == OSSL_PQC_MLDSA44_PK_LEN) {
                        merged = hybrid_pqc_fromdata_try(libctx, propq,
                                                         mldsa_names,
                                                         OSSL_NELEM(mldsa_names),
                                                         pk2, pk2len,
                                                         priv, privlen);
                    }
                    OPENSSL_clear_free(sk2, sk2len);
                    OPENSSL_clear_free(pk2, pk2len);
                }
                if (merged != NULL) {
                    EVP_PKEY_free(pkey);
                    pkey = merged;
                }
            }
            if (!hybrid_pkey_has_mldsa44_public_key(pkey))
                pkey = hybrid_supplement_mldsa_pubkey(pkey, file, libctx,
                                                      propq);
        }
        goto end;
    }

    ERR_clear_error();
    if (BIO_seek(in, 0) < 0)
        goto end;
    if (!hybrid_read_pq_key_material(in, &sk, &sklen, &pk, &pklen))
        goto end;

    if (sklen == OSSL_PQC_MLDSA44_SK_LEN) {
        pkey = hybrid_pqc_fromdata_try(libctx, propq, mldsa_names,
                                       OSSL_NELEM(mldsa_names),
                                       pklen == OSSL_PQC_MLDSA44_PK_LEN ? pk : NULL,
                                       pklen == OSSL_PQC_MLDSA44_PK_LEN ? pklen : 0,
                                       sk, sklen);
    } else if (sklen == OSSL_PQC_MLKEM512_SK_LEN
               && pklen == OSSL_PQC_MLKEM512_PK_LEN) {
        pkey = hybrid_pqc_fromdata_try(libctx, propq, mlkem_names,
                                       OSSL_NELEM(mlkem_names),
                                       pk, pklen, sk, sklen);
    } else if (sklen == OSSL_PQC_MLKEM512_PK_LEN + OSSL_PQC_MLKEM512_SK_LEN) {
        pkey = hybrid_pqc_fromdata_try(libctx, propq, mlkem_names,
                                       OSSL_NELEM(mlkem_names),
                                       sk, OSSL_PQC_MLKEM512_PK_LEN,
                                       sk + OSSL_PQC_MLKEM512_PK_LEN,
                                       OSSL_PQC_MLKEM512_SK_LEN);
    } else if (sklen == OSSL_PQC_MLKEM512_SK_LEN) {
        pkey = hybrid_pqc_fromdata_try(libctx, propq, mlkem_names,
                                       OSSL_NELEM(mlkem_names),
                                       NULL, 0, sk, sklen);
    }

end:
    if (sk != NULL)
        OPENSSL_clear_free(sk, sklen);
    if (pk != NULL)
        OPENSSL_clear_free(pk, pklen);
    BIO_free(in);
    return pkey;
}

EVP_PKEY *ossl_x509_hybrid_load_sm2_private_key_file(const char *file,
                                                     pem_password_cb *cb,
                                                     void *cbarg)
{
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;

    if (file == NULL)
        return NULL;
    in = BIO_new(BIO_s_file());
    if (in == NULL)
        return NULL;
    if (BIO_read_filename(in, file) <= 0)
        goto end;
    pkey = PEM_read_bio_PrivateKey(in, NULL, cb, cbarg);
end:
    BIO_free(in);
    return pkey;
}

#endif /* OPENSSL_NO_NTLS */
