/*
 * Sign or verify a 32-byte SM3 digest with raw ML-DSA-44 key material (PQMagic).
 *
 * Usage:
 *   mldsa_sign_sm3 sign  <sk.bin> <digest32.bin> > signature.bin
 *   mldsa_sign_sm3 verify <pk.bin> <digest32.bin> <signature.bin>
 *
 * sk.bin: 2560 bytes (ML_DSA_44_SECRETKEYBYTES)
 * pk.bin: 1312 bytes (ML_DSA_44_PUBLICKEYBYTES)
 * digest32.bin: 32 bytes (SM3 hash of CSR CertificationRequestInfo)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pqmagic_api.h>

static int read_file(const char *path, unsigned char *buf, size_t expect)
{
    FILE *fp = fopen(path, "rb");
    size_t n;

    if (fp == NULL) {
        perror(path);
        return -1;
    }
    n = fread(buf, 1, expect, fp);
    fclose(fp);
    if (n != expect) {
        fprintf(stderr, "%s: expected %zu bytes, got %zu\n", path, expect, n);
        return -1;
    }
    return 0;
}

static int cmd_sign(const char *sk_path, const char *digest_path, const char *sig_path)
{
    unsigned char sk[ML_DSA_44_SECRETKEYBYTES];
    unsigned char digest[32];
    unsigned char sig[ML_DSA_44_SIGBYTES];
    size_t siglen = ML_DSA_44_SIGBYTES;
    FILE *out;
    int rc;

    if (read_file(sk_path, sk, sizeof(sk)) != 0)
        return 1;
    if (read_file(digest_path, digest, sizeof(digest)) != 0)
        return 1;

    rc = pqmagic_ml_dsa_44_std_signature(sig, &siglen, digest, sizeof(digest),
                                       NULL, 0, sk);
    if (rc != 0) {
        fprintf(stderr, "pqmagic_ml_dsa_44_std_signature failed: %d\n", rc);
        return 1;
    }
    if (siglen == 0 || siglen > sizeof(sig)) {
        fprintf(stderr, "invalid signature length: %zu\n", siglen);
        return 1;
    }

    out = fopen(sig_path, "wb");
    if (out == NULL) {
        perror(sig_path);
        return 1;
    }
    if (fwrite(sig, 1, siglen, out) != siglen) {
        fprintf(stderr, "write signature failed\n");
        fclose(out);
        return 1;
    }
    fclose(out);
    fprintf(stderr, "signed %zu bytes\n", siglen);
    return 0;
}

static int cmd_verify(const char *pk_path, const char *digest_path,
                      const char *sig_path)
{
    unsigned char pk[ML_DSA_44_PUBLICKEYBYTES];
    unsigned char digest[32];
    unsigned char sig[ML_DSA_44_SIGBYTES];
    size_t siglen;
    FILE *fp;
    int rc;

    if (read_file(pk_path, pk, sizeof(pk)) != 0)
        return 1;
    if (read_file(digest_path, digest, sizeof(digest)) != 0)
        return 1;

    fp = fopen(sig_path, "rb");
    if (fp == NULL) {
        perror(sig_path);
        return 1;
    }
    siglen = fread(sig, 1, sizeof(sig), fp);
    fclose(fp);
    if (siglen == 0) {
        fprintf(stderr, "%s: empty signature\n", sig_path);
        return 1;
    }

    rc = pqmagic_ml_dsa_44_std_verify(sig, siglen, digest, sizeof(digest),
                                     NULL, 0, pk);
    if (rc != 0) {
        fprintf(stderr, "verify failed: %d\n", rc);
        return 1;
    }
    fputs("OK\n", stdout);
    return 0;
}

static int cmd_selftest(void)
{
    unsigned char pk[ML_DSA_44_PUBLICKEYBYTES];
    unsigned char sk[ML_DSA_44_SECRETKEYBYTES];
    unsigned char sig[ML_DSA_44_SIGBYTES];
    unsigned char msg[32];
    size_t siglen = ML_DSA_44_SIGBYTES;
    int rc;

    memset(msg, 0x42, sizeof(msg));
    if (pqmagic_ml_dsa_44_std_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    rc = pqmagic_ml_dsa_44_std_signature(sig, &siglen, msg, sizeof(msg), NULL, 0, sk);
    if (rc != 0) {
        fprintf(stderr, "sign failed: %d\n", rc);
        return 1;
    }
    rc = pqmagic_ml_dsa_44_std_verify(sig, siglen, msg, sizeof(msg), NULL, 0, pk);
    if (rc != 0) {
        fprintf(stderr, "verify failed: %d (siglen=%zu)\n", rc, siglen);
        return 1;
    }
    fputs("selftest OK\n", stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage:\n"
                "  %s selftest\n"
                "  %s sign  <sk.bin> <digest32.bin> <signature.bin>\n"
                "  %s verify <pk.bin> <digest32.bin> <signature.bin>\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "selftest") == 0)
        return cmd_selftest();
    if (strcmp(argv[1], "sign") == 0) {
        if (argc != 5) {
            fprintf(stderr, "usage: %s sign <sk.bin> <digest32.bin> <signature.bin>\n", argv[0]);
            return 1;
        }
        return cmd_sign(argv[2], argv[3], argv[4]);
    }
    if (strcmp(argv[1], "verify") == 0) {
        if (argc != 5) {
            fprintf(stderr, "usage: %s verify <pk.bin> <digest32.bin> <signature.bin>\n",
                    argv[0]);
            return 1;
        }
        return cmd_verify(argv[2], argv[3], argv[4]);
    }
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}
