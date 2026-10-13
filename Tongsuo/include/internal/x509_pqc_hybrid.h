/*
 * 扩展验签：certs/3 国密混合证、certs/2 ML-DSA-44-SM2 复合证、certs/1 裸 PQC SPKI、
 * Aigis SIG1 纯/串联/扩展样证。
 */
#ifndef OSSL_X509_PQC_HYBRID_H
# define OSSL_X509_PQC_HYBRID_H

# include <openssl/types.h>
# include <openssl/x509.h>
# include <openssl/obj_mac.h>

# define OSSL_PQC_MLDSA44_SIG_LEN  2420
# define OSSL_PQC_MLDSA44_PK_LEN   1312
# define OSSL_PQC_MLDSA44_SK_LEN   2560
# define OSSL_PQC_MLKEM512_PK_LEN  800
# define OSSL_PQC_MLKEM512_SK_LEN  1632
# define OSSL_PQC_SM2_HYBRID_PK_LEN 65
# define OSSL_PQC_AIGIS_SIG1_SIG_LEN 1852
# define OSSL_PQC_AIGIS_SIG1_PK_LEN  1056

# define OSSL_AIGIS_OID_SIG1_SM2_WITH_SM3 "1.2.156.10197.1.510.1"
# define OSSL_AIGIS_OID_SIG1_WITH_SM3    "1.2.156.10197.1.509.1"
# define OSSL_AIGIS_OID_SIG1_SM2_SPKI    "1.2.156.10197.1.512.1"

/* certs/2：签名算法 ML-DSA-44-SM2-with-SM3 */
static ossl_inline int ossl_x509_is_mldsa44_sm2_cert(const X509 *cert)
{
    return cert != NULL
        && X509_get_signature_nid(cert) == NID_ML_DSA_44_SM2_with_SM3;
}

/*
 * Aigis 串联复合证（aigissm2）：签名 OID 1.2.156.10197.1.510.1。
 * NID 由 aigis provider 动态 OBJ_create，故用 OID 文本比较。
 */
int ossl_x509_is_aigis_sig1_sm2_cert(const X509 *cert);

/*
 * 在解析/验签前加载 pqmagic-algorithms-provider（certs/1 裸 SPKI、certs/2 验签）
 * 与 x509-hybrid-spki-provider（certs/2 复合 SPKI），不依赖 OPENSSL_CONF。
 * 环境变量：PQMAGIC_PROVIDER、ML_DSA_SM2_PROVIDER（或 X509_HYBRID_SPKI_PROVIDER）、
 * CERT_VERIFY_SO / X509_HYBRID_VERIFY_SO、AIGIS_PROVIDER。
 */
int ossl_x509_ensure_pqc_providers(OSSL_LIB_CTX *libctx);

/*
 * certs/2：跳过标准 X509_verify_ctx，由 cert_verify.so 做 ML-DSA+SM2 复合验签。
 */
int ossl_x509_verify_mldsa44_sm2_composite(const X509 *cert, const X509 *issuer,
                                            OSSL_LIB_CTX *libctx);

/*
 * Aigis 串联/扩展：加载 aigis.dll，调用 aigis_x509_verify_pair。
 */
int ossl_x509_verify_aigis(const X509 *cert, const X509 *issuer,
                           OSSL_LIB_CTX *libctx);

/*
 * 串联 CRL 双重验签（ML-DSA-44-SM2-with-SM3 或 Aigis-SIG1-SM2-with-SM3）。
 * 返回 1 验过，0 验失败，-1 不是这两种签名（调用方走原来的 X509_CRL_verify）。
 */
int ossl_x509_crl_verify_composite(X509_CRL *crl, X509 *issuer,
                                   OSSL_LIB_CTX *libctx);

/*
 * 验链进度按实际执行顺序打印，不预排段数。
 * sig_ok: 1 签名已验且通过，0 已验且失败，-1 尚未验签名。
 * revoked: 1 已吊销，0 已查且未吊销，-1 吊销检查未完成或不适用。
 */
void ossl_x509_vfy_report_reset(int with_crl);
void ossl_x509_vfy_report_cert_begin(void);
void ossl_x509_vfy_report_single_cert(const X509 *cert, int ok);
void ossl_x509_vfy_report_single_crl(const X509_CRL *crl, int ok);
void ossl_x509_vfy_report_done(int sig_ok, int revoked);

/* 混合扩展证内层是否为 Aigis-SIG1（扩展 4.1.7） */
int ossl_x509_hybrid_ext_is_aigis(const X509 *cert);

static ossl_inline int ossl_x509_is_mldsa44_sm2_req(const X509_REQ *req)
{
    return req != NULL
        && X509_REQ_get_signature_nid(req) == NID_ML_DSA_44_SM2_with_SM3;
}

/* Aigis 串联 CSR：签名 OID 510.1。NID 由 provider 动态注册，用 OID 文本比较。 */
int ossl_x509_is_aigis_sig1_sm2_req(const X509_REQ *req);

/*
 * certs/2 CSR：跳过标准 X509_REQ_verify，由 cert_verify 做 ML-DSA+SM2 复合自签验签。
 */
int ossl_x509_verify_req_mldsa44_sm2_composite(const X509_REQ *req,
                                               OSSL_LIB_CTX *libctx);

/*
 * certs/2 CSR 生成：-key ML-DSA-44-SPKI + -sm2key SM2，写入复合 SPKI（508.1）。
 */
int ossl_x509_req_set_mldsa44_sm2_pubkey_from_keys(X509_REQ *req,
                                                   EVP_PKEY *mldsa_pkey,
                                                   EVP_PKEY *sm2_pkey);

/*
 * certs/2 CSR 生成：对已有 CRI 做 ML-DSA+SM2 双签（506.1）。
 */
int ossl_x509_req_sign_mldsa44_sm2_composite(X509_REQ *req,
                                             EVP_PKEY *mldsa_pkey,
                                             EVP_PKEY *sm2_pkey,
                                             OSSL_LIB_CTX *libctx);

/*
 * Aigis 串联 CSR：-key id-Aigis-SIG1-SPKI + -sm2key SM2。
 * 公钥 OID 512.1（1056‖65），签名 OID 510.1（1852‖SM2）。
 */
int ossl_x509_req_set_aigis_sig1_sm2_pubkey_from_keys(X509_REQ *req,
                                                      EVP_PKEY *aigis_pkey,
                                                      EVP_PKEY *sm2_pkey);
int ossl_x509_req_sign_aigis_sig1_sm2_composite(X509_REQ *req,
                                                EVP_PKEY *aigis_pkey,
                                                EVP_PKEY *sm2_pkey,
                                                OSSL_LIB_CTX *libctx);
int ossl_x509_verify_req_aigis_sig1_sm2_composite(const X509_REQ *req,
                                                  OSSL_LIB_CTX *libctx);

/*
 * certs/3：标准 SM2 外层通过后追加 ML-DSA（扩展 4.1.8）；非混合证返回 1。
 */
int ossl_x509_verify_pqc_hybrid(const X509 *cert, const X509 *issuer,
                                OSSL_LIB_CTX *libctx);

/* certs/3：SubjectPublicKeyInfo 为 SM2，PQC 公钥在扩展 1.2.156.10260.4.1.6 */
int ossl_x509_is_hybrid_sm2_pqc_cert(const X509 *cert);

# ifndef OPENSSL_NO_NTLS
#  include <openssl/pem.h>

static ossl_inline int ossl_x509_hybrid_is_mldsa44_sm2(int nid)
{
    return nid == NID_ML_DSA_44_SM2;
}

static ossl_inline int ossl_x509_hybrid_is_mlkem512_sm2(int nid)
{
    return nid == NID_ML_KEM_512_SM2;
}

static ossl_inline int ossl_x509_hybrid_is_composite_pkey(const EVP_PKEY *pkey)
{
    return pkey != NULL
        && (EVP_PKEY_is_a(pkey, SN_ML_DSA_44_SM2)
            || EVP_PKEY_is_a(pkey, SN_ML_KEM_512_SM2));
}

/*
 * 复合 SPKI（ML-DSA-44-SM2 / ML-KEM-512-SM2）的 security bits；裸 PQC 返回 -1。
 */
int ossl_x509_hybrid_security_bits(const EVP_PKEY *pkey);

int ossl_x509_hybrid_security_sigbits(const X509 *x);

/*
 * 从复合证 SubjectPublicKeyInfo 拆出裸 PQC 与 SM2 公钥（调用方 EVP_PKEY_free）。
 * pqc_out / sm2_out 可为 NULL 表示不需要该半段。
 */
int ossl_x509_hybrid_split_from_x509(OSSL_LIB_CTX *libctx, const char *propq,
                                     const X509 *x,
                                     EVP_PKEY **pqc_out, EVP_PKEY **sm2_out);

/* NTLS KYBER_DILITHIUM：取加密证/签名证中的裸 PQC 公钥（新 EVP_PKEY，需 free） */
EVP_PKEY *ossl_x509_hybrid_ntls_pqc_pubkey(OSSL_LIB_CTX *libctx,
                                           const char *propq,
                                           const X509 *x);

/*
 * ECC-KYBER：加密证是否携带静态 ML-KEM-512（certs/2 复合 SPKI 或 certs/3 扩展 4.1.6）。
 */
int ossl_x509_hybrid_ntls_enc_static_mlkem(const X509 *enc);

/* 取加密证 SM2 公钥（复合/扩展证拆出 SM2 半段；纯 SM2 SPKI 直接引用） */
EVP_PKEY *ossl_x509_hybrid_ntls_sm2_pubkey(OSSL_LIB_CTX *libctx,
                                           const char *propq,
                                           const X509 *x);

int ossl_x509_hybrid_mlkem512_raw_pk(const EVP_PKEY *pkey,
                                     unsigned char *pk, size_t pklen);
int ossl_x509_hybrid_mlkem512_raw_sk(const EVP_PKEY *pkey,
                                     unsigned char *sk, size_t sklen);

EVP_PKEY *ossl_x509_hybrid_mlkem512_from_raw(OSSL_LIB_CTX *libctx,
                                             const char *propq,
                                             const unsigned char *pub,
                                             size_t publen,
                                             const unsigned char *priv,
                                             size_t privlen);

int ossl_x509_hybrid_mlkem512_keypair(OSSL_LIB_CTX *libctx, const char *propq,
                                      unsigned char *pk, size_t pklen,
                                      unsigned char *sk, size_t sklen);

/*
 * user_sig.key -> user_sig_sm2.key；成功写 out 并返回 1。
 */
int ossl_x509_hybrid_companion_sm2_key_path(const char *keyfile,
                                            char *out, size_t outlen);

/*
 * 加载 PQ 私钥：标准 PKCS#8 或 certs/1|certs/2 自定义裸 sk PEM。
 */
EVP_PKEY *ossl_x509_hybrid_load_pq_private_key(OSSL_LIB_CTX *libctx,
                                               const char *propq,
                                               const char *file,
                                               pem_password_cb *cb,
                                               void *cbarg);

EVP_PKEY *ossl_x509_hybrid_load_sm2_private_key_file(const char *file,
                                                     pem_password_cb *cb,
                                                     void *cbarg);
# endif /* OPENSSL_NO_NTLS */

#endif
