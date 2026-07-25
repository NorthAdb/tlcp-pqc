#ifndef CERT_VERIFY_H
#define CERT_VERIFY_H

#include <openssl/types.h>
#include <openssl/x509.h>

#define CERT_VERIFY_MLDSA44_SIG_LEN  2420
#define CERT_VERIFY_MLDSA44_PK_LEN   1312
#define CERT_VERIFY_MLKEM512_PK_LEN  800
#define CERT_VERIFY_EXT_PQC_PUB_OCTET_MAX  2048
#define CERT_VERIFY_EXT_PQC_SIGALG_OCTET_MAX 128

/* 国密混合证书自定义扩展（certs/3） */
#define CERT_VERIFY_OID_EXT_PQC_PUB   "1.2.156.10260.4.1.6"
#define CERT_VERIFY_OID_EXT_PQC_SIGALG "1.2.156.10260.4.1.7"
#define CERT_VERIFY_OID_EXT_PQC_SIG   "1.2.156.10260.4.1.8"
#define CERT_VERIFY_OID_SM2_SPKI      "1.2.156.10197.1.301"
#define CERT_VERIFY_OID_MLDSA44_SPKI  "1.2.156.10197.1.304.1"
#define CERT_VERIFY_OID_MLKEM512_SPKI "1.2.156.10197.1.303.1"
#define CERT_VERIFY_OID_MLDSA44_SIGALG "1.2.156.10197.1.505.1"
#define CERT_VERIFY_SIGALG_MLDSA44_SM3  "ML-DSA-44-with-SM3"

/* certs/3 国密混合证：含扩展 1.2.156.10260.4.1.6（SM2 主体 + PQC 扩展） */
int cert_verify_is_hybrid_sm2_pqc(X509 *cert);

/* certs/2 复合 SPKI：ML-DSA-44-SM2 + ML-DSA-44-SM2-with-SM3 外层签名 */
#define CERT_VERIFY_MLDSA44_SM2_PK_RAW_LEN  (CERT_VERIFY_MLDSA44_PK_LEN + 65)
#define CERT_VERIFY_SM2_SIG_LEN_MAX         128

int cert_verify_is_mldsa44_sm2(X509 *cert);

/* 加载 default + pqmagic + ml_dsa_sm2（certs/2 解析复合 SPKI 需后者） */
int cert_verify_providers_load(OSSL_LIB_CTX *libctx);
void cert_verify_providers_unload(OSSL_LIB_CTX *libctx);

/* OID → 可读名称（未知则回传 oid 本身） */
const char *cert_verify_oid_name(const char *oid);

/* 1=打印每步调用的函数；也可用环境变量 CERT_VERIFY_TRACE=1 */
void cert_verify_set_trace(int enable);
int cert_verify_trace_enabled(void);

typedef struct cert_verify_parsed_st {
    int is_hybrid_sm2_pqc;
    long version;
    char serial_hex[128];
    char sig_alg_tbs[128];
    char issuer[512];
    char subject[512];
    char not_before[64];
    char not_after[64];
    char subject_sm2_oid[64];
    size_t subject_sm2_pk_len;
  unsigned char subject_sm2_pk[128];
    char ext_pqc_pub_oid[64];
    size_t ext_pqc_pub_len;
    unsigned char ext_pqc_pub[CERT_VERIFY_MLDSA44_PK_LEN];
    size_t ext_pqc_pub_octet_len;
    unsigned char ext_pqc_pub_octet[CERT_VERIFY_EXT_PQC_PUB_OCTET_MAX];
    char ext_pqc_sigalg_oid[64];
    char ext_pqc_sigalg_name[128];
    size_t ext_pqc_sigalg_octet_len;
    unsigned char ext_pqc_sigalg_octet[CERT_VERIFY_EXT_PQC_SIGALG_OCTET_MAX];
    size_t ext_pqc_sig_len;
    unsigned char ext_pqc_sig[CERT_VERIFY_MLDSA44_SIG_LEN];
    char outer_sig_alg[128];
    size_t outer_sig_len;
} CERT_VERIFY_PARSED;

typedef struct cert_verify_result_st {
    int ok;
    int mldsa_tbs_pqc;   /* ML-DSA：SM3(完整TBS去4.1.7/8，含4.1.6)，签名为扩展 4.1.8 */
    int sm2_full_tbs;    /* SM2：SM3(完整 TBS)，签名为证书外层 */
    int mldsa_full_tbs;  /* 仅 certs/1 纯 PQC 模式 */
    char subject[256];
    char issuer[256];
    char err[512];
} CERT_VERIFY_RESULT;

/* 解析证书字段（含混合扩展） */
int cert_verify_parse_cert(X509 *cert, CERT_VERIFY_PARSED *info);

/* 将解析结果打印到 stdout */
void cert_verify_print_parsed(const char *label, const CERT_VERIFY_PARSED *info);

unsigned char *cert_verify_strip_extensions(const unsigned char *tbs, int tbs_len,
                                            int *orig_len);

/* ML-DSA 待验 TBS：完整 TBS 去掉扩展 4.1.7、4.1.8（保留 4.1.6） */
unsigned char *cert_verify_build_orig_tbs_hybrid(X509 *cert, int *orig_len);

int cert_verify_get_ext_pqc_pubkey(X509 *cert, unsigned char *pk, size_t pk_max,
                                   size_t *pk_len, char *alg_oid, size_t alg_sz);

int cert_verify_get_ext_pqc_signature(X509 *cert, unsigned char *sig,
                                      size_t sig_max, size_t *sig_len);

int cert_verify_get_issuer_pqc_pubkey(X509 *issuer, unsigned char *pk,
                                      size_t pk_max, size_t *pk_len);

/* 混合证书：ML-DSA 验扩展 4.1.8 */
int cert_verify_mldsa_hybrid(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx);

/* 混合证书：SM2 验外层签名 */
int cert_verify_sm2_outer(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx);

/* certs/2：ML-DSA-44-SM2-with-SM3 = ML-DSA(2420) + SM2(余下) 对完整 TBS */
int cert_verify_mldsa44_sm2_composite(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx);

/* certs/2 CSR：复合自签 PKCS#10，公钥取自 CRI 内 SPKI */
int cert_verify_is_mldsa44_sm2_req(X509_REQ *req);
int cert_verify_req_mldsa44_sm2_composite(X509_REQ *req, OSSL_LIB_CTX *libctx);

/* 纯 PQC SPKI 证书（certs/1） */
int cert_verify_get_subject_pqc_pubkey(X509 *cert,
                                     unsigned char *pk_out, size_t pk_out_len,
                                     size_t *pk_len, char *oid_text, size_t oid_sz);
int cert_verify_mldsa_tbs_plus_pqc(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx);
int cert_verify_mldsa_full_tbs_standard(X509 *cert, X509 *issuer,
                                        OSSL_LIB_CTX *libctx);
int cert_verify_sm2_full_tbs(X509 *cert, X509 *issuer, OSSL_LIB_CTX *libctx);

int cert_verify_one(X509 *cert, X509 *issuer, CERT_VERIFY_RESULT *res,
                    OSSL_LIB_CTX *libctx);

int cert_verify_chain_dir(const char *dir, CERT_VERIFY_RESULT *results,
                          int *nresults, OSSL_LIB_CTX *libctx);

/* openssl verify：包装 verify_cb，在标准验签通过后追加 ML-DSA 混合验签 */
void cert_verify_openssl_interpose_init(void);
int cert_verify_install_openssl_verify_cb(X509_STORE *store,
                                          int (*user_cb)(int, X509_STORE_CTX *));

#endif /* CERT_VERIFY_H */
