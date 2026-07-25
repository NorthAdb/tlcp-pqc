/*
 * ML-DSA-44-SM2 Provider Entry Point
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include "ml_dsa_sm2_ameth.h"
#include "ml_kem512_sm2_ameth.h"

/* Provider context */
typedef struct {
    OSSL_LIB_CTX *libctx;
} ML_DSA_SM2_PROV_CTX;

/* Provider teardown */
static void ml_dsa_sm2_prov_teardown(void *provctx)
{
    ML_DSA_SM2_PROV_CTX *ctx = provctx;
    /* Don't free libctx - it's owned by the core, not us */
    OPENSSL_free(ctx);
}

/* Provider gettable params */
static const OSSL_PARAM ml_dsa_sm2_prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ml_dsa_sm2_prov_gettable_params(void *provctx)
{
    return ml_dsa_sm2_prov_param_types;
}

static int ml_dsa_sm2_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "ML-DSA/KEM-SM2 hybrid ASN1 Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "ML-DSA-44-SM2 + ML-KEM-512-SM2 ASN1 1.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

/* Provider query operation - no algorithms, just ASN1 method registration */
static const OSSL_ALGORITHM *ml_dsa_sm2_prov_query(void *provctx, int operation_id,
                                                   int *no_cache)
{
    *no_cache = 0;
    return NULL;
}

/* Provider dispatch table */
static const OSSL_DISPATCH ml_dsa_sm2_prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ml_dsa_sm2_prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))ml_dsa_sm2_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (void (*)(void))ml_dsa_sm2_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
      (void (*)(void))ml_dsa_sm2_prov_query },
    { 0, NULL }
};

       /* Provider init function */
       int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                              const OSSL_DISPATCH *in,
                              const OSSL_DISPATCH **out,
                              void **provctx)
       {
           ML_DSA_SM2_PROV_CTX *ctx;
           OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

           /* Get core functions */
           for (; in->function_id != 0; in++) {
               switch (in->function_id) {
               case OSSL_FUNC_CORE_GET_LIBCTX:
                   c_get_libctx = OSSL_FUNC_core_get_libctx(in);
                   break;
               default:
                   break;
               }
           }

           if (c_get_libctx == NULL)
               return 0;

    /* Create provider context */
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    /* Get library context - this is owned by the core, we just store a reference */
    ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);
    /* libctx can be NULL for default context, that's OK */

           /* Register ASN1 method */
           /* Note: This must be done before any certificate parsing */
           /* Try to register - if it fails, it might already be registered */
           if (ml_dsa_sm2_register_ameth() == 0
               && EVP_PKEY_asn1_find(NULL, NID_ML_DSA_44_SM2) == NULL) {
               OPENSSL_free(ctx);
               return 0;
           }
           if (ml_kem512_sm2_register_ameth() == 0
               && EVP_PKEY_asn1_find(NULL, NID_ML_KEM_512_SM2) == NULL) {
               OPENSSL_free(ctx);
               return 0;
           }
           ERR_clear_error();

           *provctx = ctx;
           *out = ml_dsa_sm2_prov_dispatch_table;

           return 1;
       }
