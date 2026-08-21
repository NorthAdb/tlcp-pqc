/*
 * CLI: 解析 / 提取公钥 / 验签 Aigis 三类证书
 *
 * 用法:
 *   aigis_cert_tool extract <cert.pem>
 *   aigis_cert_tool verify <cert.pem> <issuer.pem>
 *   aigis_cert_tool verify-dir <certs/aigis/aigis|aigissm2|sm2extaigis>
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "aigis_cert.h"

static const char *mode_name(AIGIS_CERT_MODE m)
{
    switch (m) {
    case AIGIS_CERT_MODE_PURE:
        return "pure (裸抗量子)";
    case AIGIS_CERT_MODE_CONCAT:
        return "concat (混合串联)";
    case AIGIS_CERT_MODE_EXT:
        return "ext (混合扩展)";
    default:
        return "unknown";
    }
}

static void print_hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("%s (%zu bytes):\n", label, n);
    for (i = 0; i < n; i++) {
        if ((i % 16) == 0)
            printf("  ");
        printf("%02x%s", p[i], ((i + 1) % 16 == 0 || i + 1 == n) ? "\n" : ":");
    }
}

static X509 *load_cert(const char *path)
{
    BIO *b = BIO_new_file(path, "r");
    X509 *x;

    if (b == NULL)
        return NULL;
    x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    return x;
}

static int cmd_extract(const char *path)
{
    X509 *cert = load_cert(path);
    AIGIS_PUBKEY pk;

    if (cert == NULL) {
        fprintf(stderr, "无法读取证书: %s\n", path);
        return 1;
    }
    if (!aigis_cert_extract_subject_pubkey(cert, &pk)) {
        fprintf(stderr, "公钥提取失败（模式=%s）\n",
                mode_name(aigis_cert_detect_mode(cert)));
        X509_free(cert);
        return 1;
    }
    printf("mode: %s\n", mode_name(pk.mode));
    printf("spki_oid: %s\n", pk.spki_oid);
    printf("type: %s\n", pk.is_sig ? "Aigis-SIG1" : "Aigis-Enc-1");
    print_hex("aigis_pubkey", pk.aigis_pk, pk.aigis_pk_len);
    if (pk.sm2_pk_len)
        print_hex("sm2_pubkey", pk.sm2_pk, pk.sm2_pk_len);
    X509_free(cert);
    return 0;
}

static int cmd_verify(const char *cert_path, const char *issuer_path)
{
    X509 *cert = load_cert(cert_path);
    X509 *issuer = load_cert(issuer_path);
    AIGIS_VERIFY_RESULT res;

    if (cert == NULL || issuer == NULL) {
        fprintf(stderr, "无法读取证书\n");
        X509_free(cert);
        X509_free(issuer);
        return 1;
    }
    if (!aigis_cert_verify_one(cert, issuer, &res, NULL)) {
        printf("FAIL mode=%s aigis=%d sm2=%d\n  %s\n  subject=%s\n",
               mode_name(res.mode), res.aigis_ok, res.sm2_ok, res.err,
               res.subject);
        X509_free(cert);
        X509_free(issuer);
        return 1;
    }
    printf("OK mode=%s aigis=%d sm2=%d\n  subject=%s\n", mode_name(res.mode),
           res.aigis_ok, res.sm2_ok, res.subject);
    X509_free(cert);
    X509_free(issuer);
    return 0;
}

static int cmd_verify_dir(const char *dir)
{
    AIGIS_VERIFY_RESULT results[8];
    int n = 0, i, fail = 0;

    if (!aigis_cert_verify_dir(dir, results, &n, NULL) || n <= 0) {
        fprintf(stderr, "目录验签失败: %s（需要 root/yunying/user_sig.crt）\n",
                dir);
        return 1;
    }
    for (i = 0; i < n; i++) {
        printf("[%d] %s mode=%s aigis=%d sm2=%d %s\n", i,
               results[i].ok ? "OK" : "FAIL", mode_name(results[i].mode),
               results[i].aigis_ok, results[i].sm2_ok, results[i].subject);
        if (!results[i].ok) {
            printf("     %s\n", results[i].err);
            fail = 1;
        }
    }
    return fail;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def;

    aigis_cert_register_oids();
    def = OSSL_PROVIDER_load(NULL, "default");
    if (argc < 3) {
        fprintf(stderr,
                "Usage:\n"
                "  %s extract <cert.pem>\n"
                "  %s verify <cert.pem> <issuer.pem>\n"
                "  %s verify-dir <dir>\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "extract") == 0)
        return cmd_extract(argv[2]);
    if (strcmp(argv[1], "verify") == 0 && argc >= 4)
        return cmd_verify(argv[2], argv[3]);
    if (strcmp(argv[1], "verify-dir") == 0)
        return cmd_verify_dir(argv[2]);
    fprintf(stderr, "未知命令\n");
    (void)def;
    return 1;
}
