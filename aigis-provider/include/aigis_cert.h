/*
 * Aigis 证书：解析 / 公钥提取 / 验签（纯抗量子、混合串联、混合扩展）
 * 对应 certs/aigis/{aigis,aigissm2,sm2extaigis}（SIG1 / ENC1）
 */
#ifndef AIGIS_CERT_H
#define AIGIS_CERT_H

#include <stddef.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#ifdef _WIN32
# if defined(AIGIS_CERT_STATIC)
#  define AIGIS_CERT_API
# elif defined(AIGIS_CERT_EXPORTS) || defined(aigis_EXPORTS)
#  define AIGIS_CERT_API __declspec(dllexport)
# else
#  define AIGIS_CERT_API __declspec(dllimport)
# endif
#else
# define AIGIS_CERT_API
#endif

/* SPKI / 签名算法 OID（与样证 DER 一致） */
#define AIGIS_OID_ENC1_SPKI       "1.2.156.10197.1.305.1"
#define AIGIS_OID_SIG1_SPKI       "1.2.156.10197.1.306.1"
#define AIGIS_OID_SIG1_WITH_SM3   "1.2.156.10197.1.509.1"
#define AIGIS_OID_SIG1_SM2_WITH_SM3 "1.2.156.10197.1.510.1"
#define AIGIS_OID_ENC1_SM2_SPKI   "1.2.156.10197.1.511.1"
#define AIGIS_OID_SIG1_SM2_SPKI   "1.2.156.10197.1.512.1"

/* 混合扩展（与 ML 混合证相同） */
#define AIGIS_OID_EXT_PQC_PUB     "1.2.156.10260.4.1.6"
#define AIGIS_OID_EXT_PQC_SIGALG  "1.2.156.10260.4.1.7"
#define AIGIS_OID_EXT_PQC_SIG     "1.2.156.10260.4.1.8"
#define AIGIS_OID_SM2_SPKI        "1.2.156.10197.1.301"
#define AIGIS_OID_SM2_WITH_SM3    "1.2.156.10197.1.501"

/* PQMagic Aigis-SIG1 / ENC1 尺寸 */
#define AIGIS_SIG1_PK_LEN   1056
#define AIGIS_SIG1_SK_LEN   2448
#define AIGIS_SIG1_SIG_LEN  1852
#define AIGIS_ENC1_PK_LEN   672
#define AIGIS_ENC1_SK_LEN   1568
#define AIGIS_ENC1_CT_LEN   736
#define AIGIS_ENC1_SS_LEN   32
#define AIGIS_SM2_PK_LEN    65

typedef enum {
    AIGIS_CERT_MODE_UNKNOWN = 0,
    AIGIS_CERT_MODE_PURE,       /* aigis/：裸 SIG1/ENC1 SPKI */
    AIGIS_CERT_MODE_CONCAT,     /* aigissm2/：PQC‖SM2 串联 */
    AIGIS_CERT_MODE_EXT         /* sm2extaigis/：SM2 主体 + 4.1.6/7/8 */
} AIGIS_CERT_MODE;

typedef struct aigis_pubkey_st {
    AIGIS_CERT_MODE mode;
    char spki_oid[64];
    /* Aigis 裸公钥（SIG1 或 ENC1） */
    unsigned char aigis_pk[AIGIS_SIG1_PK_LEN];
    size_t aigis_pk_len;
    int is_sig; /* 1=SIG1, 0=ENC1 */
    /* 串联或扩展主体中的 SM2 未压缩公钥（可无） */
    unsigned char sm2_pk[AIGIS_SM2_PK_LEN];
    size_t sm2_pk_len;
} AIGIS_PUBKEY;

typedef struct aigis_verify_result_st {
    int ok;
    AIGIS_CERT_MODE mode;
    int aigis_ok;   /* Aigis 签名步 */
    int sm2_ok;     /* SM2 步（串联/扩展） */
    char subject[256];
    char issuer[256];
    char err[512];
} AIGIS_VERIFY_RESULT;

AIGIS_CERT_API void aigis_cert_register_oids(void);

AIGIS_CERT_API AIGIS_CERT_MODE aigis_cert_detect_mode(X509 *cert);

/* 从证书提取主体侧公钥材料（三种模式） */
AIGIS_CERT_API int aigis_cert_extract_subject_pubkey(X509 *cert, AIGIS_PUBKEY *out);

/* 单步：用 issuer 验 cert（自动识别模式） */
AIGIS_CERT_API int aigis_cert_verify_one(X509 *cert, X509 *issuer, AIGIS_VERIFY_RESULT *res,
                          OSSL_LIB_CTX *libctx);

/* 目录联调：root.crt -> yunying.crt -> user_sig.crt（及可选 user_enc） */
AIGIS_CERT_API int aigis_cert_verify_dir(const char *dir, AIGIS_VERIFY_RESULT *results,
                          int *nresults, OSSL_LIB_CTX *libctx);

/* Tongsuo openssl verify 钩子用：内部走 aigis_cert_verify_one */
AIGIS_CERT_API int aigis_x509_verify_pair(X509 *cert, X509 *issuer,
                                          OSSL_LIB_CTX *libctx);

/*
 * 同 aigis_x509_verify_pair，并回填模式与分步结果，供进度日志打印。
 * mode: 1=pure, 2=concat, 3=ext；aigis_ok/sm2_ok 为 0/1。
 */
AIGIS_CERT_API int aigis_x509_verify_pair_detail(X509 *cert, X509 *issuer,
                                                 OSSL_LIB_CTX *libctx,
                                                 int *mode, int *aigis_ok,
                                                 int *sm2_ok);

AIGIS_CERT_API void aigis_cert_set_trace(int enable);

#endif /* AIGIS_CERT_H */
