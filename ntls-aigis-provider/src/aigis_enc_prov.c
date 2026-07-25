/*
 * OpenSSL 3 provider: Aigis-Enc-2 KEM（PQMagic）
 * - 随机密钥对：pqmagic_aigis_enc_2_std_keypair
 * - 封装/解封装：pqmagic_aigis_enc_2_std_enc / _dec
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

#include <pqmagic_api.h>

#define AIGIS_ALG_NAME "Aigis-Enc-2"
#define AIGIS_OID_TEXT "PQMagic-Aigis-Enc-2"

#define AIGIS_PK_LEN AIGIS_ENC_2_PUBLICKEYBYTES
#define AIGIS_SK_LEN AIGIS_ENC_2_SECRETKEYBYTES
#define AIGIS_CT_LEN AIGIS_ENC_2_CIPHERTEXTBYTES
#define AIGIS_SS_LEN AIGIS_ENC_2_SSBYTES

struct aigis_key {
    unsigned char pk[AIGIS_PK_LEN];
    size_t pk_len;
    unsigned char sk[AIGIS_SK_LEN];
    size_t sk_len;
};

struct aigis_gen_ctx {
    void *provctx;
};

struct aigis_kem_ctx {
    struct aigis_key *key;
};

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

    if (reference_sz != sizeof(void *))
        return NULL;
    key = *(struct aigis_key **)reference;
    *(struct aigis_key **)reference = NULL;
    return key;
}

static const OSSL_PARAM aigis_import_pub[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM aigis_import_priv[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
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

static const OSSL_PARAM aigis_export_pub[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM aigis_export_priv[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *aigis_km_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return aigis_export_pub;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return aigis_export_priv;
    return NULL;
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
        return (k->pk_len == AIGIS_PK_LEN);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return (k->sk_len == AIGIS_SK_LEN);
    return 1;
}

static int aigis_km_import(void *keydata, int selection, const OSSL_PARAM params[])
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
        if (plen != AIGIS_PK_LEN)
            return 0;
        k->pk_len = plen;
        got = 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        void *vp = k->sk;
        size_t plen = 0;

        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(k->sk), &plen))
            return 0;
        if (plen != AIGIS_SK_LEN)
            return 0;
        k->sk_len = plen;
        got = 1;
    }
    return got;
}

static int aigis_km_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                           void *cbarg)
{
    struct aigis_key *k = keydata;
    OSSL_PARAM params[3];
    int n = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && k->pk_len != 0) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, k->pk, k->pk_len);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && k->sk_len != 0) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, k->sk, k->sk_len);
    }
    if (n == 0)
        return 0;
    params[n] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM aigis_km_gettable[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *aigis_km_gettable_params(void *provctx)
{
    (void)provctx;
    return aigis_km_gettable;
}

static int aigis_km_get_params(void *keydata, OSSL_PARAM params[])
{
    struct aigis_key *k = keydata;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, AIGIS_OID_TEXT))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL && k->pk_len > 0
        && !OSSL_PARAM_set_octet_string(p, k->pk, k->pk_len))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL && k->sk_len > 0
        && !OSSL_PARAM_set_octet_string(p, k->sk, k->sk_len))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, (int)(k->pk_len * 8)))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;
    return 1;
}

static const char *aigis_km_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_KEM)
        return AIGIS_ALG_NAME;
    return NULL;
}

static void *aigis_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    struct aigis_gen_ctx *gctx;

    (void)params;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;
    gctx->provctx = provctx;
    return gctx;
}

static int aigis_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    (void)genctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *aigis_gen_settable_params(void *genctx, void *provctx)
{
    (void)genctx;
    (void)provctx;
    return NULL;
}

static void *aigis_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    struct aigis_gen_ctx *gctx = genctx;
    struct aigis_key *key;

    (void)cb;
    (void)cbarg;
    if (gctx == NULL)
        return NULL;
    key = aigis_km_new(gctx->provctx);
    if (key == NULL)
        return NULL;
    if (pqmagic_aigis_enc_2_std_keypair(key->pk, key->sk) != 0) {
        aigis_km_free(key);
        return NULL;
    }
    key->pk_len = AIGIS_PK_LEN;
    key->sk_len = AIGIS_SK_LEN;
    return key;
}

static void aigis_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static const OSSL_DISPATCH aigis_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))aigis_km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))aigis_km_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))aigis_km_load },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))aigis_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))aigis_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))aigis_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))aigis_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))aigis_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))aigis_km_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))aigis_km_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))aigis_km_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))aigis_km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))aigis_km_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))aigis_km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))aigis_km_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))aigis_km_query_operation_name },
    { 0, NULL }
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

static void *aigis_kem_dupctx(void *vctx)
{
    struct aigis_kem_ctx *src = vctx;
    struct aigis_kem_ctx *dst;

    if (src == NULL)
        return NULL;
    dst = OPENSSL_malloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;
    *dst = *src;
    return dst;
}

static int aigis_kem_encapsulate_init(void *vctx, void *provkey,
                                     const OSSL_PARAM *params)
{
    struct aigis_kem_ctx *ctx = vctx;
    struct aigis_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL || k->pk_len != AIGIS_PK_LEN)
        return 0;
    ctx->key = k;
    return 1;
}

static int aigis_kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                                 unsigned char *secret, size_t *secretlen)
{
    struct aigis_kem_ctx *ctx = vctx;
    struct aigis_key *k;

    if (ctx == NULL)
        return 0;
    k = ctx->key;
    if (k == NULL || k->pk_len != AIGIS_PK_LEN)
        return 0;
    if (out == NULL && secret == NULL) {
        if (outlen != NULL)
            *outlen = AIGIS_CT_LEN;
        if (secretlen != NULL)
            *secretlen = AIGIS_SS_LEN;
        return 1;
    }
    if (out == NULL || secret == NULL)
        return 0;
    if (pqmagic_aigis_enc_2_std_enc(out, secret, k->pk) != 0)
        return 0;
    if (outlen != NULL)
        *outlen = AIGIS_CT_LEN;
    if (secretlen != NULL)
        *secretlen = AIGIS_SS_LEN;
    return 1;
}

static int aigis_kem_decapsulate_init(void *vctx, void *provkey,
                                    const OSSL_PARAM *params)
{
    struct aigis_kem_ctx *ctx = vctx;
    struct aigis_key *k = provkey;

    (void)params;
    if (ctx == NULL || k == NULL || k->sk_len != AIGIS_SK_LEN)
        return 0;
    ctx->key = k;
    return 1;
}

static int aigis_kem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                                 const unsigned char *in, size_t inlen)
{
    struct aigis_kem_ctx *ctx = vctx;
    struct aigis_key *k;

    if (ctx == NULL)
        return 0;
    k = ctx->key;
    if (k == NULL || k->sk_len != AIGIS_SK_LEN)
        return 0;
    if (out == NULL) {
        if (outlen != NULL)
            *outlen = AIGIS_SS_LEN;
        return 1;
    }
    if (inlen != AIGIS_CT_LEN)
        return 0;
    if (pqmagic_aigis_enc_2_std_dec(out, in, k->sk) != 0)
        return 0;
    if (outlen != NULL)
        *outlen = AIGIS_SS_LEN;
    return 1;
}

static const OSSL_DISPATCH aigis_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))aigis_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))aigis_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))aigis_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))aigis_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))aigis_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))aigis_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))aigis_kem_dupctx },
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
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "aigis_enc"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM aigis_keymgmt_algs[] = {
    { AIGIS_ALG_NAME, "provider=aigis_enc", aigis_keymgmt_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM aigis_kem_algs[] = {
    { AIGIS_ALG_NAME, "provider=aigis_enc", aigis_kem_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *provider_query(void *provctx, int operation_id,
                                            int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return aigis_keymgmt_algs;
    case OSSL_OP_KEM:
        return aigis_kem_algs;
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

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);

    if (libctx == NULL)
        return 0;
    *provctx = libctx;
    *out = provider_functions;
    return 1;
}
