/*
 * 验证证书（默认 certs/3 整条链）
 *
 * 用法:
 *   verify_certs_1 [目录]              # root/yunying/user_sig/user_enc
 *   verify_certs_1 <签发者.crt> <证书.crt>   # 仅验一张，如 root.crt yunying.crt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "cert_verify.h"

static const char *yesno(int v)
{
    return v ? "OK" : "FAIL";
}

#define V1_TRACE(fmt, ...) \
    do { \
        if (cert_verify_trace_enabled()) \
            printf("[verify_certs_1] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

static X509 *load_pem_cert(const char *path)
{
    BIO *bio = BIO_new_file(path, "r");
    X509 *x = NULL;

    if (bio == NULL)
        return NULL;
    x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return x;
}

static void print_verify_rules(void)
{
    printf("=== 验签规则 ===\n");
    printf("  [1] ML-DSA-44-with-SM3 (OID %s)\n",
           CERT_VERIFY_OID_MLDSA44_SIGALG);
    printf("      混合证: SM3(完整TBS去掉4.1.7/4.1.8，含4.1.6)，ML-DSA 签名在扩展4.1.8\n");
    printf("  [2] SM2-with-SM3: SM3(完整TBS，含4.1.6/7/8)，签名为证书外层\n\n");
}

static void print_one_result(const CERT_VERIFY_RESULT *res)
{
    printf("--- %s ---\n", res->subject);
    printf("  签发者: %s\n", res->issuer);
    printf("  ML-DSA(TBS去4.1.7/8):   %s\n", yesno(res->mldsa_tbs_pqc));
    printf("  SM2(完整TBS 外层):      %s\n", yesno(res->sm2_full_tbs));
    if (res->mldsa_full_tbs)
        printf("  ML-DSA(完整TBS 纯PQC): %s\n", yesno(res->mldsa_full_tbs));
    printf("  结果:                   %s\n", yesno(res->ok));
    if (res->err[0] != '\0')
        printf("  说明: %s\n", res->err);
    printf("\n");
}

static int init_openssl_providers(void)
{
    const char *prov_path;
    char prov_dir[1024];

#ifdef _WIN32
    prov_path = getenv("CERT_VERIFY_PROVIDER_PATH");
    if (prov_path == NULL)
        prov_path = "D:\\20240429certificate-verification\\tlcp-pqc\\providers";
#else
    prov_path = getenv("CERT_VERIFY_PROVIDER_PATH");
    if (prov_path == NULL)
        prov_path = "/home/wang/Desktop/pqmagic-algorithms-provider/build";
#endif
    if (getenv("OPENSSL_MODULES") == NULL) {
        snprintf(prov_dir, sizeof(prov_dir), "%s", prov_path);
#ifdef _WIN32
        _putenv_s("OPENSSL_MODULES", prov_dir);
#else
        setenv("OPENSSL_MODULES", prov_dir, 0);
#endif
    }
    V1_TRACE("OPENSSL_MODULES=%s", getenv("OPENSSL_MODULES"));
    V1_TRACE("调用 cert_verify_providers_load() -> OSSL_PROVIDER_load(default)+load(pqmagic)");
    if (!cert_verify_providers_load(NULL)) {
        fprintf(stderr, "无法加载 default/pqmagic（OPENSSL_MODULES=%s）\n",
                getenv("OPENSSL_MODULES") != NULL ? getenv("OPENSSL_MODULES")
                                                  : prov_path);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (getenv("CERT_VERIFY_TRACE") == NULL)
        cert_verify_set_trace(1);
    return 1;
}

static int verify_pair(const char *issuer_path, const char *cert_path)
{
    X509 *issuer = NULL;
    X509 *cert = NULL;
    CERT_VERIFY_PARSED parsed;
    CERT_VERIFY_RESULT res;
    int ok;

    printf("签发者: %s\n", issuer_path);
    printf("证书:   %s\n", cert_path);
    if (cert_verify_trace_enabled())
        printf("(已开启 CERT_VERIFY_TRACE)\n");
    printf("\n");

    issuer = load_pem_cert(issuer_path);
    cert = load_pem_cert(cert_path);
    if (issuer == NULL || cert == NULL) {
        fprintf(stderr, "读取 PEM 失败\n");
        ERR_print_errors_fp(stderr);
        X509_free(issuer);
        X509_free(cert);
        return 0;
    }

    printf("=== 证书解析 ===\n");
    cert_verify_parse_cert(issuer, &parsed);
    cert_verify_print_parsed("签发者", &parsed);
    cert_verify_parse_cert(cert, &parsed);
    cert_verify_print_parsed("待验证书", &parsed);

    V1_TRACE("cert_verify_one(cert=%s, issuer=%s)", cert_path, issuer_path);
    print_verify_rules();
    ok = cert_verify_one(cert, issuer, &res, NULL);
    print_one_result(&res);

    X509_free(issuer);
    X509_free(cert);
    printf(ok ? "验签: OK\n" : "验签: FAIL\n");
    return ok;
}

static int verify_chain_dir(const char *dir)
{
    CERT_VERIFY_RESULT results[8];
    int n = 0;
    int chain_ok;
    static const char *names[] = {
        "root.crt", "yunying.crt", "user_sig.crt", "user_enc.crt"
    };

    printf("证书目录: %s\n", dir);
    if (cert_verify_trace_enabled())
        printf("(已开启 CERT_VERIFY_TRACE：每步调用的函数见 [cert_verify] 行)\n");
    printf("\n");
    printf("=== 证书解析 ===\n");
    for (int i = 0; i < 4; i++) {
        char path[1024];
        X509 *x;
        CERT_VERIFY_PARSED parsed;

        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        V1_TRACE("解析阶段 [%d] BIO_new_file + PEM_read_bio_X509(%s)", i, path);
        x = load_pem_cert(path);
        if (x == NULL) {
            printf("[%s] 读取失败\n\n", names[i]);
            continue;
        }
        V1_TRACE("  -> cert_verify_parse_cert() + cert_verify_print_parsed()");
        cert_verify_parse_cert(x, &parsed);
        cert_verify_print_parsed(names[i], &parsed);
        X509_free(x);
    }

    V1_TRACE("验签阶段 cert_verify_chain_dir(%s) -> 4 次 cert_verify_one", dir);
    chain_ok = cert_verify_chain_dir(dir, results, &n, NULL);

    print_verify_rules();
    for (int i = 0; i < n; i++)
        print_one_result(&results[i]);

    printf(chain_ok ? "整条链验证: OK\n" : "整条链验证: FAIL\n");
    return chain_ok;
}

int main(int argc, char **argv)
{
    const char *dir = "/home/wang/Desktop/certs/3";
    int ok;
    int single = 0;
    const char *issuer_path = NULL;
    const char *cert_path = NULL;

    if (argc == 3) {
        single = 1;
        issuer_path = argv[1];
        cert_path = argv[2];
        V1_TRACE("main() 单证模式 issuer=%s cert=%s", issuer_path, cert_path);
    } else {
        if (argc > 1)
            dir = argv[1];
        V1_TRACE("main() 链模式, 证书目录=%s", dir);
    }

    V1_TRACE("OPENSSL_init_crypto(LOAD_CRYPTO_STRINGS|LOAD_CONFIG)");
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
                            | OPENSSL_INIT_LOAD_CONFIG,
                        NULL);

    if (!init_openssl_providers())
        return 1;

    if (single)
        ok = verify_pair(issuer_path, cert_path);
    else
        ok = verify_chain_dir(dir);

    V1_TRACE("cert_verify_providers_unload()");
    cert_verify_providers_unload(NULL);
    V1_TRACE("main() 结束 exit=%d", ok ? 0 : 2);
    return ok ? 0 : 2;
}
