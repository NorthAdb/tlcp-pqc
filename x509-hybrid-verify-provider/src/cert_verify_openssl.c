/*
 * 供 openssl verify 使用：在标准 X509 验签成功后，对混合证追加 ML-DSA(4.1.8) 校验。
 * 通过 LD_PRELOAD 同名 cert_verify.so 拦截 X509_STORE_set_verify_cb 实现，不改动 verify_certs_1。
 */

#define _GNU_SOURCE
#include "cert_verify.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/provider.h>

static int (*g_user_verify_cb)(int ok, X509_STORE_CTX *ctx) = NULL;
static void (*real_X509_STORE_set_verify_cb)(X509_STORE *store,
                                              int (*cb)(int, X509_STORE_CTX *)) = NULL;
static int g_cv_providers_ready = 0;
static int g_interpose_enabled = -1;

static int cv_interpose_enabled(void)
{
    const char *e;

    if (g_interpose_enabled >= 0)
        return g_interpose_enabled;
    e = getenv("CERT_VERIFY_OPENSSL_INTERPOSE");
    if (e != NULL && (strcmp(e, "0") == 0 || strcmp(e, "false") == 0)) {
        g_interpose_enabled = 0;
        return 0;
    }
    g_interpose_enabled = 1;
    return 1;
}

static int cv_ensure_providers(void)
{
    if (g_cv_providers_ready)
        return 1;
    if (!cert_verify_providers_load(NULL))
        return 0;
    g_cv_providers_ready = 1;
    return 1;
}

static X509 *cv_issuer_at_depth(X509_STORE_CTX *ctx, int depth)
{
    STACK_OF(X509) *chain;
    int n;

    chain = X509_STORE_CTX_get0_chain(ctx);
    if (chain == NULL)
        return NULL;
    n = sk_X509_num(chain);
    if (depth < 0 || depth + 1 >= n)
        return NULL;
    return sk_X509_value(chain, depth + 1);
}

static int cert_verify_hybrid_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    X509 *cert;
    X509 *issuer;
    int depth;

    if (g_user_verify_cb != NULL)
        ok = g_user_verify_cb(ok, ctx);
    if (!ok || ctx == NULL)
        return ok;

    cert = X509_STORE_CTX_get_current_cert(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    issuer = cv_issuer_at_depth(ctx, depth);
    if (cert == NULL || issuer == NULL)
        return ok;

    if (!cv_ensure_providers())
        return 0;

    if (!cert_verify_mldsa_hybrid(cert, issuer, NULL)) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_SIGNATURE_FAILURE);
        return 0;
    }
    return ok;
}

int cert_verify_install_openssl_verify_cb(X509_STORE *store,
                                          int (*user_cb)(int, X509_STORE_CTX *))
{
    if (store == NULL)
        return 0;
    g_user_verify_cb = user_cb;
    if (real_X509_STORE_set_verify_cb == NULL) {
        real_X509_STORE_set_verify_cb =
            (void (*)(X509_STORE *, int (*)(int, X509_STORE_CTX *)))
            dlsym(RTLD_NEXT, "X509_STORE_set_verify_cb");
    }
    if (real_X509_STORE_set_verify_cb == NULL)
        return 0;
    real_X509_STORE_set_verify_cb(store, cert_verify_hybrid_verify_cb);
    return 1;
}

void X509_STORE_set_verify_cb(X509_STORE *store, int (*cb)(int, X509_STORE_CTX *))
{
    if (!cv_interpose_enabled()) {
        if (real_X509_STORE_set_verify_cb == NULL)
            real_X509_STORE_set_verify_cb =
                (void (*)(X509_STORE *, int (*)(int, X509_STORE_CTX *)))
                dlsym(RTLD_NEXT, "X509_STORE_set_verify_cb");
        if (real_X509_STORE_set_verify_cb != NULL)
            real_X509_STORE_set_verify_cb(store, cb);
        return;
    }
    (void)cert_verify_install_openssl_verify_cb(store, cb);
}

void cert_verify_openssl_interpose_init(void)
{
    (void)cv_interpose_enabled();
}
