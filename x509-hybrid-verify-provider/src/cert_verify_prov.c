/*
 * OpenSSL 3 provider 入口（cert_verify）
 * 核心验签逻辑在 cert_verify.c / verify_certs_1 工具中。
 * 加载本 provider 后，请同时加载 default 与 pqmagic 以解析 PQC SPKI。
 * Tongsuo openssl verify 对混合证（certs/3）会通过 ossl_x509_verify_pqc_hybrid
 * 动态加载本模块并调用 cert_verify_mldsa_hybrid；需 pqmagic（openssl.cnf）。
 * LD_PRELOAD（openssl_verify.sh）为可选替代方式。
 */

#include "cert_verify.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

typedef struct {
    OSSL_LIB_CTX *libctx;
} CV_PROV_CTX;

static void cv_prov_teardown(void *provctx)
{
    OPENSSL_free(provctx);
}

static const OSSL_PARAM cv_prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *cv_prov_gettable_params(void *provctx)
{
    (void)provctx;
    return cv_prov_param_types;
}

static int cv_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "cert_verify"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM *cv_prov_query(void *provctx, int operation_id,
                                           int *no_cache)
{
    (void)provctx;
    (void)operation_id;
    *no_cache = 0;
    return NULL;
}

static const OSSL_DISPATCH cv_prov_dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))cv_prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))cv_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))cv_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))cv_prov_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    CV_PROV_CTX *ctx;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        if (in->function_id == OSSL_FUNC_CORE_GET_LIBCTX)
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
    }
    if (c_get_libctx == NULL)
        return 0;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;
    ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);
    cert_verify_openssl_interpose_init();
    (void)cert_verify_providers_load(ctx->libctx);
    *provctx = ctx;
    *out = cv_prov_dispatch;
    return 1;
}
